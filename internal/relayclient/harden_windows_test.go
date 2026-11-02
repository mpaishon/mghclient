//go:build windows

package relayclient

// SR-12 (R4): the state folder and the key get a protected access list for
// the user, SYSTEM and Administrators — at enrolment, at renewal and at
// every load — and a link or junction in their place is refused.

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/mpaishon/mghclient/internal/relayclient/relaytest"
)

// openToEveryone gives path an inherited-style (unprotected) access list
// letting Everyone change it: what a state_dir under D:\ inherits.
func openToEveryone(t *testing.T, path string, dir bool) {
	t.Helper()
	sddl := "D:(A;;FA;;;WD)(A;;FA;;;OW)"
	if dir {
		sddl = "D:(A;OICI;FA;;;WD)(A;OICI;FA;;;OW)"
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

func mustBePrivate(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		ok, err := isPrivate(p)
		if err != nil || !ok {
			t.Errorf("%s is not private (%v)", p, err)
		}
	}
}

func TestHardenStateMakesTheFolderAndKeyPrivate(t *testing.T) {
	p := Paths{Dir: filepath.Join(t.TempDir(), "relay")}
	if err := os.MkdirAll(p.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	openToEveryone(t, p.Dir, true)
	if err := os.WriteFile(p.Key(), []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	openToEveryone(t, p.Key(), false)
	if ok, _ := isPrivate(p.Key()); ok {
		t.Fatal("precondition: the key is already private")
	}
	if err := hardenState(p); err != nil {
		t.Fatal(err)
	}
	mustBePrivate(t, p.Dir, p.Key())
	// A file made in the folder afterwards inherits the private list: its
	// entries (inherited, so not protected) name only the three.
	if err := os.WriteFile(p.State(), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	h, err := openHandle(p.State())
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	dacl, _, err := h.dacl()
	if err != nil {
		t.Fatal(err)
	}
	user, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := privateACL(dacl, true, user); err != nil || !ok {
		t.Errorf("a file made in the hardened folder lets others in (%v)", err)
	}
}

func TestHardenStateRefusesAJunction(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "elsewhere")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "relay")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Skipf("cannot make a junction here: %v %s", err, out)
	}
	if err := hardenState(Paths{Dir: link}); !errors.Is(err, ErrNotPrivate) {
		t.Fatalf("a junction as the state folder: %v, want ErrNotPrivate", err)
	}
}

func TestEnrolmentRenewalAndLoadKeepTheStatePrivate(t *testing.T) {
	s := relaytest.New(t, fakeData())
	dir, _ := enroll(t, s)
	p := Paths{Dir: dir}
	mustBePrivate(t, p.Dir, p.Key(), p.Cert(), p.CA(), p.State())

	// Opened up behind the client's back: the next load closes it again.
	openToEveryone(t, p.Dir, true)
	openToEveryone(t, p.Key(), false)
	c := newClient(t, dir)
	mustBePrivate(t, p.Dir, p.Key())

	openToEveryone(t, p.Dir, true)
	if renewed, err := c.RenewIfDue(context.Background(), true, time.Time{}); err != nil || !renewed {
		t.Fatalf("renewal: %v %v", renewed, err)
	}
	mustBePrivate(t, p.Dir, p.Key(), p.Cert(), p.Key()+prevSuffix)
}
