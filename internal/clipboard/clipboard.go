// Package clipboard wraps the macOS pbcopy / pbpaste utilities so that the
// CLI and menu-bar app share a single implementation.
package clipboard

import (
	"os/exec"
	"strings"
)

// Copy writes s to the macOS pasteboard via pbcopy.
func Copy(s string) error {
	cmd := exec.Command("pbcopy")
	cmd.Stdin = strings.NewReader(s)
	return cmd.Run()
}

// Paste returns the current macOS pasteboard contents via pbpaste.
func Paste() (string, error) {
	out, err := exec.Command("pbpaste").Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}
