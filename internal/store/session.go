package store

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	keychain "github.com/keybase/go-keychain"
)

// SessionService is a DISTINCT keychain Service from Service so that `totp
// list` (which queries Service) never surfaces the session item, and so that
// the item appears in Keychain Access as its own row.
const SessionService = "com.agungcandra.totp-cli.session"

// SessionAccount is the fixed account name for the single global session item.
const SessionAccount = "session"

// SessionGrace is the window during which `totp get` skips the Touch ID
// prompt after a successful authentication. `totp rm` ignores this window
// and always authenticates.
//
// Trade-off: during the window any process running as this user can obtain a
// TOTP code by invoking this binary without a biometric prompt. Only this
// signed binary can modify (upsert) the session item silently — macOS gates
// keychain writes to generic-password items by the calling application's
// code signature, so a different process cannot extend or forge the window
// without first triggering its own "allow" dialog.
const SessionGrace = 30 * time.Second

// sessionValid is a pure predicate so it can be unit-tested without touching
// the keychain. It returns true only when:
//   - now is strictly before expiry (the window has not closed yet), AND
//   - expiry is at most grace into the future (a forged far-future value, or
//     a clock that was moved backwards, both read as invalid).
func sessionValid(expiry, now time.Time, grace time.Duration) bool {
	if !now.Before(expiry) {
		return false
	}
	return !expiry.After(now.Add(grace))
}

func readSessionExpiry() (time.Time, error) {
	q := keychain.NewItem()
	q.SetSecClass(keychain.SecClassGenericPassword)
	q.SetService(SessionService)
	q.SetAccount(SessionAccount)
	q.SetMatchLimit(keychain.MatchLimitOne)
	q.SetReturnData(true)
	results, err := keychain.QueryItem(q)
	if err != nil {
		return time.Time{}, err
	}
	if len(results) == 0 {
		return time.Time{}, ErrNotFound
	}
	secs, err := strconv.ParseInt(string(results[0].Data), 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse session expiry: %w", err)
	}
	return time.Unix(secs, 0), nil
}

// IsSessionValid reports whether a prior successful authentication is still
// within the grace window. Any keychain read or parse error is treated as
// invalid (the caller will prompt the user again).
func IsSessionValid(now time.Time) bool {
	expiry, err := readSessionExpiry()
	if err != nil {
		return false
	}
	return sessionValid(expiry, now, SessionGrace)
}

// RefreshSession upserts the session keychain item so its expiry is
// now + SessionGrace. Call ONLY after auth.Authenticate has succeeded.
func RefreshSession(now time.Time) error {
	expiry := now.Add(SessionGrace)
	data := []byte(strconv.FormatInt(expiry.Unix(), 10))

	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	item.SetService(SessionService)
	item.SetAccount(SessionAccount)
	item.SetLabel("TOTP auth session")
	item.SetSynchronizable(keychain.SynchronizableNo)
	item.SetAccessible(keychain.AccessibleWhenUnlockedThisDeviceOnly)
	item.SetData(data)

	err := keychain.AddItem(item)
	if err == nil {
		return nil
	}
	if !errors.Is(err, keychain.ErrorDuplicateItem) {
		return fmt.Errorf("session add: %w", err)
	}
	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassGenericPassword)
	query.SetService(SessionService)
	query.SetAccount(SessionAccount)
	update := keychain.NewItem()
	update.SetData(data)
	if err := keychain.UpdateItem(query, update); err != nil {
		return fmt.Errorf("session update: %w", err)
	}
	return nil
}
