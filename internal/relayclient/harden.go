package relayclient

import "errors"

// ErrNotPrivate is a state folder entry that cannot be made the user's
// alone: a link, junction or mount point where the client's own folder or
// file is expected, or one owned by someone else that cannot be taken back
// (Windows).
var ErrNotPrivate = errors.New("cannot be made private")

// privateFiles are the client's own files in the state folder, the only
// ones hardenState touches besides the folder itself.
func (p Paths) privateFiles() []string {
	return []string{
		p.Key(), p.Key() + nextSuffix, p.Key() + prevSuffix,
		p.Cert(), p.Cert() + nextSuffix, p.Cert() + prevSuffix,
		p.CA(), p.State(), p.Update(),
		p.Presence(),
	}
}

// stateOwner is the SID (Windows) of the user the state folder is kept
// private to when it is not this process's user: the background service
// runs as LocalSystem but keeps the folder its installer's.
var stateOwner string

// SetStateOwner makes the state folder private to sid instead of this
// process's user (Windows; ignored elsewhere). The service's --owner.
func SetStateOwner(sid string) { stateOwner = sid }
