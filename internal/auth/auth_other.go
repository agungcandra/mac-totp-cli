//go:build !darwin

package auth

import "errors"

var (
	ErrCancelled   = errors.New("authentication cancelled")
	ErrFailed      = errors.New("authentication failed")
	ErrUnavailable = errors.New("authentication unavailable on this device")
)

// Authenticate is only supported on macOS.
func Authenticate(reason string) error {
	return errors.New("totp-cli authentication is only supported on macOS (darwin)")
}
