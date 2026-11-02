package relayclient

import (
	"errors"
	"os"
	"runtime"
	"testing"
)

// TestRenameWaitsOutAScanner: a sharing violation on Windows is retried until
// the file is free; elsewhere, and for any other error, the first answer
// stands.
func TestRenameWaitsOutAScanner(t *testing.T) {
	calls := 0
	renameFile = func(string, string) error {
		calls++
		if calls < 3 {
			return &os.LinkError{Op: "rename", Err: errorSharingViolation}
		}
		return nil
	}
	t.Cleanup(func() { renameFile = os.Rename })

	err := rename("a", "b")
	if runtime.GOOS == "windows" {
		if err != nil || calls != 3 {
			t.Fatalf("err = %v after %d calls, want success on the third", err, calls)
		}
	} else if err == nil || calls != 1 {
		t.Fatalf("err = %v after %d calls, want the first error back", err, calls)
	}

	calls = 0
	renameFile = func(string, string) error { calls++; return os.ErrNotExist }
	if err := rename("a", "b"); !errors.Is(err, os.ErrNotExist) || calls != 1 {
		t.Fatalf("err = %v after %d calls, want ErrNotExist at once", err, calls)
	}
}
