//go:build !windows

package relayclient

// hardenState is Windows's (SR-12): on Linux and macOS the folder is made
// 0700 and the key written 0600, and those modes hold.
func hardenState(Paths) error { return nil }
