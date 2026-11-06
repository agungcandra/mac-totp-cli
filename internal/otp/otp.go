// Package otp centralises the "generate a TOTP code for a stored account"
// flow so that `totp get` and the menu-bar app share identical auth, grace,
// and code-generation behaviour.
package otp

import (
	"errors"
	"fmt"
	"time"

	"github.com/agungcandra/totp-cli/internal/auth"
	"github.com/agungcandra/totp-cli/internal/store"
)

// Authenticator is the subset of internal/auth that Generate needs. It is a
// seam for tests; production code passes auth.Authenticate directly.
type Authenticator func(reason string) error

// Result is the output of a successful Generate call.
type Result struct {
	Code             string
	SecondsRemaining int
}

// Generate returns the current TOTP code for name, prompting for Touch ID /
// account password via authFn when the global 30s grace window is closed.
// When the grace window is open, no prompt is shown. After a successful
// prompt the window is refreshed (refresh failure is logged via warnFn but
// non-fatal, matching CLI behaviour).
//
// name:    account name
// now:     clock to use (production: time.Now())
// authFn:  nil falls back to auth.Authenticate
// warnFn:  nil swallows non-fatal warnings
func Generate(name string, now time.Time, authFn Authenticator, warnFn func(string)) (*Result, error) {
	if authFn == nil {
		authFn = auth.Authenticate
	}
	if !store.IsSessionValid(now) {
		if err := authFn("access TOTP secret for " + name); err != nil {
			return nil, err
		}
		if err := store.RefreshSession(now); err != nil && warnFn != nil {
			warnFn(fmt.Sprintf("warn: could not refresh auth session: %v", err))
		}
	}
	s, err := store.Get(name)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("no secret named %q", name)
		}
		return nil, err
	}
	code, err := s.Generate()
	if err != nil {
		return nil, err
	}
	return &Result{
		Code:             code,
		SecondsRemaining: s.SecondsRemaining(now),
	}, nil
}
