package relayclient

import (
	"errors"
	"os"
	"runtime"
	"syscall"
	"time"
)

// Windows refuses to replace a file another process has open without
// FILE_SHARE_DELETE, and antivirus and indexers open a newly written
// certificate or key for a moment to scan it. rename waits that out: on
// Windows it retries a sharing or access refusal for about a second before
// giving up. Elsewhere it is os.Rename.

const (
	renameTries = 10
	renameStep  = 25 * time.Millisecond
)

// The Windows errors a scanner holding the file causes.
const (
	errorAccessDenied     = syscall.Errno(5)
	errorSharingViolation = syscall.Errno(32)
	errorLockViolation    = syscall.Errno(33)
)

var renameFile = os.Rename // tests replace it

func rename(src, dst string) error {
	err := renameFile(src, dst)
	for i := 1; i < renameTries && err != nil && transientRename(err); i++ {
		time.Sleep(time.Duration(i) * renameStep)
		err = renameFile(src, dst)
	}
	return err
}

func transientRename(err error) bool {
	if runtime.GOOS != "windows" {
		return false
	}
	return errors.Is(err, errorSharingViolation) || errors.Is(err, errorLockViolation) || errors.Is(err, errorAccessDenied)
}
