//go:build windows

package relayclient

import (
	"errors"
	"fmt"
	"io/fs"
	"unsafe"

	"golang.org/x/sys/windows"
)

// HardenState, for the relay state folder.
//
// The state folder holds the client's private key. On Windows a folder made
// with os.MkdirAll(0700) and a file written 0600 get no access list of their
// own: they inherit their parent's, and a state_dir outside the user's
// profile (D:\tools\…) inherits "Authenticated Users: Modify", so any local
// user could read or replace the key. hardenState gives the folder a
// protected access list for the current user, SYSTEM and Administrators,
// inherited by what is made in it, and the same to each of the client's
// files there.
//
// Every entry is opened as itself (FILE_FLAG_OPEN_REPARSE_POINT, and
// BACKUP_SEMANTICS for a folder), checked to be no link, junction or mount
// point on that handle, and its owner and access list read and set through
// that same handle — never by name, which would follow a reparse point to
// wherever it leads.

// creatorOwner is CREATOR OWNER (S-1-3-0): an inherit-only placeholder for
// whoever makes an entry, who must already be allowed in.
const creatorOwner = "S-1-3-0"

// hardenState makes the state folder and the client's files in it private
// to the current user (with SYSTEM and Administrators). The folder must
// exist; absent files are skipped. A link, junction or mount point is
// refused, as is an entry owned by someone else that cannot be taken back
// (ErrNotPrivate).
func hardenState(p Paths) error {
	user, err := stateUserSID()
	if err != nil {
		return err
	}
	if err := hardenEntry(p.Dir, user, true, true); err != nil {
		return err
	}
	for _, f := range p.privateFiles() {
		if err := hardenEntry(f, user, false, false); err != nil {
			return err
		}
	}
	return nil
}

// stateUserSID is whose the state folder is: SetStateOwner's SID, else
// this process's user.
func stateUserSID() (*windows.SID, error) {
	if stateOwner != "" {
		sid, err := windows.StringToSid(stateOwner)
		if err != nil {
			return nil, fmt.Errorf("the state folder's owner %q: %w", stateOwner, err)
		}
		return sid, nil
	}
	return currentUserSID()
}

// currentUserSID is the SID of the user this process runs as.
func currentUserSID() (*windows.SID, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("find the current user: %w", err)
	}
	return u.User.Sid.Copy()
}

// hardenEntry makes one entry private (required: it must be there).
func hardenEntry(path string, user *windows.SID, dir, required bool) error {
	h, err := openHandle(path)
	if errors.Is(err, fs.ErrNotExist) && !required {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open %s as itself: %w", path, err)
	}
	defer h.Close()
	return makePrivate(h, path, user, dir)
}

// makePrivate is hardenEntry on an open entry: no reparse point, the kind
// expected, an owner of the three, then the private access list.
func makePrivate(h *handleEntry, path string, user *windows.SID, dir bool) error {
	tag, err := h.reparse()
	if err != nil {
		return err
	}
	switch {
	case tag != 0:
		return fmt.Errorf("%s: %w: a link, junction or mount point where the client keeps its own %s", path, ErrNotPrivate,
			map[bool]string{true: "folder", false: "file"}[dir])
	case dir && !h.isDir():
		return fmt.Errorf("%s: %w: not a folder", path, ErrNotPrivate)
	case !dir && h.isDir():
		return fmt.Errorf("%s: %w: a folder where the client keeps a file", path, ErrNotPrivate)
	}
	owner, err := h.owner()
	if err != nil {
		return err
	}
	if !allowedSID(owner, user, false) {
		// Someone else's: taken back for the user where the rights allow
		// (WRITE_OWNER), else refused.
		if err := h.setOwner(user); err != nil {
			return fmt.Errorf("%s: %w: it is owned by %s, and giving it back to %s needs the restore privilege (an administrator's), which this process does not have (%v): take ownership of it once as an administrator, or choose another state_dir",
				path, ErrNotPrivate, accountName(owner), accountName(user), err)
		}
	}
	dacl, protected, err := h.dacl()
	if err != nil {
		return err
	}
	if ok, err := privateACL(dacl, protected, user); err != nil {
		return err
	} else if ok {
		return nil
	}
	want, err := privateDACL(user, dir)
	if err != nil {
		return err
	}
	if err := h.setDACL(want); err != nil {
		return fmt.Errorf("make %s private: %w", path, err)
	}
	dacl, protected, err = h.dacl()
	if err != nil {
		return err
	}
	if ok, err := privateACL(dacl, protected, user); err != nil || !ok {
		if err == nil {
			err = errors.New("others may still open it")
		}
		return fmt.Errorf("make %s private: %w", path, err)
	}
	return nil
}

// accountName is a SID as a person reads it: DOMAIN\name, or the SID.
func accountName(s *windows.SID) string {
	if s == nil {
		return "nobody"
	}
	if name, domain, _, err := s.LookupAccount(""); err == nil && name != "" {
		if domain != "" {
			return domain + `\` + name
		}
		return name
	}
	return s.String()
}

// privateDACL is the protected access list: full control for the user,
// SYSTEM and Administrators — for a folder, inherited by what is made in it.
func privateDACL(user *windows.SID, dir bool) (*windows.ACL, error) {
	inherit := ""
	if dir {
		inherit = "OICI"
	}
	sd, err := windows.SecurityDescriptorFromString(fmt.Sprintf("D:P(A;%[1]s;FA;;;SY)(A;%[1]s;FA;;;BA)(A;%[1]s;FA;;;%[2]s)", inherit, user.String()))
	if err != nil {
		return nil, err
	}
	dacl, _, err := sd.DACL()
	return dacl, err
}

// allowedSID says whether sid is the user, SYSTEM or Administrators (and,
// in an access list, CREATOR OWNER).
func allowedSID(sid, user *windows.SID, creator bool) bool {
	if sid == nil {
		return false
	}
	if sid.Equals(user) || sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return true
	}
	if creator {
		co, _ := windows.StringToSid(creatorOwner)
		return co != nil && sid.Equals(co)
	}
	return false
}

// privateACL reports whether only the user, SYSTEM and Administrators are
// allowed anything by dacl, and (protected) nothing is inherited.
func privateACL(dacl *windows.ACL, protected bool, user *windows.SID) (bool, error) {
	if dacl == nil || !protected {
		return false, nil // no access list is everyone's
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return false, err
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			return false, nil // an object or callback entry: not ours
		}
		if !allowedSID((*windows.SID)(unsafe.Pointer(&ace.SidStart)), user, true) {
			return false, nil
		}
	}
	return true, nil
}

// isPrivate reports whether path (opened as itself) is private as
// hardenState leaves an entry: no reparse point, and a protected access list
// allowing only the current user, SYSTEM and Administrators.
func isPrivate(path string) (bool, error) {
	user, err := currentUserSID()
	if err != nil {
		return false, err
	}
	h, err := openHandle(path)
	if err != nil {
		return false, err
	}
	defer h.Close()
	if tag, err := h.reparse(); err != nil || tag != 0 {
		return false, err
	}
	dacl, protected, err := h.dacl()
	if err != nil {
		return false, err
	}
	return privateACL(dacl, protected, user)
}

// handleEntry is an entry opened as itself.
type handleEntry struct {
	h windows.Handle
}

// openHandle opens path as itself; BACKUP_SEMANTICS opens a folder and a
// file alike.
func openHandle(path string) (*handleEntry, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT | windows.FILE_FLAG_BACKUP_SEMANTICS)
	share := uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE)
	// WRITE_OWNER only where it is granted: without it the owner can still
	// be read, and a foreign one is refused.
	for _, access := range []uint32{windows.READ_CONTROL | windows.WRITE_DAC | windows.WRITE_OWNER, windows.READ_CONTROL | windows.WRITE_DAC} {
		h, err := windows.CreateFile(p, access|windows.FILE_READ_ATTRIBUTES, share, nil, windows.OPEN_EXISTING, flags, 0)
		if err == nil {
			return &handleEntry{h: h}, nil
		}
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
		}
		if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return nil, &fs.PathError{Op: "open", Path: path, Err: err}
		}
	}
	return nil, &fs.PathError{Op: "open", Path: path, Err: windows.ERROR_ACCESS_DENIED}
}

type attributeTagInfo struct {
	FileAttributes uint32
	ReparseTag     uint32
}

func (e *handleEntry) info() (attributeTagInfo, error) {
	var i attributeTagInfo
	err := windows.GetFileInformationByHandleEx(e.h, windows.FileAttributeTagInfo, (*byte)(unsafe.Pointer(&i)), uint32(unsafe.Sizeof(i)))
	return i, err
}

// reparse is the entry's reparse tag, 0 for none.
func (e *handleEntry) reparse() (uint32, error) {
	i, err := e.info()
	if err != nil {
		return 0, err
	}
	if i.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 {
		return 0, nil
	}
	if i.ReparseTag == 0 {
		return 1, nil // a reparse point all the same
	}
	return i.ReparseTag, nil
}

func (e *handleEntry) isDir() bool {
	i, err := e.info()
	return err == nil && i.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
}

func (e *handleEntry) owner() (*windows.SID, error) {
	sd, err := windows.GetSecurityInfo(e.h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}
	o, _, err := sd.Owner()
	if err != nil || o == nil {
		return nil, err
	}
	return o.Copy()
}

func (e *handleEntry) setOwner(s *windows.SID) error {
	return windows.SetSecurityInfo(e.h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, s, nil, nil, nil)
}

// dacl is the entry's access list, and whether it is protected.
func (e *handleEntry) dacl() (*windows.ACL, bool, error) {
	sd, err := windows.GetSecurityInfo(e.h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, false, err
	}
	control, _, err := sd.Control()
	if err != nil {
		return nil, false, err
	}
	// The access list points into sd (Go memory), which it keeps alive.
	dacl, _, err := sd.DACL()
	if err != nil {
		return nil, false, err
	}
	return dacl, control&windows.SE_DACL_PROTECTED != 0, nil
}

func (e *handleEntry) setDACL(dacl *windows.ACL) error {
	return windows.SetSecurityInfo(e.h, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func (e *handleEntry) Close() error { return windows.CloseHandle(e.h) }
