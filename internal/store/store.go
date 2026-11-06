// Package store persists TOTP secrets as generic-password items in the macOS
// login keychain.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	keychain "github.com/keybase/go-keychain"

	"github.com/agungcandra/totp-cli/internal/totp"
)

// Service is the keychain Service attribute shared by every item this CLI owns.
const Service = "com.agungcandra.totp-cli"

// ErrNotFound indicates no keychain item matches the given name.
var ErrNotFound = errors.New("secret not found")

// ErrExists indicates a secret with the same name already exists.
var ErrExists = errors.New("secret already exists")

func baseItem(name string) keychain.Item {
	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	item.SetService(Service)
	item.SetAccount(name)
	item.SetLabel("TOTP: " + name)
	item.SetSynchronizable(keychain.SynchronizableNo)
	item.SetAccessible(keychain.AccessibleWhenUnlockedThisDeviceOnly)
	return item
}

// Add stores the secret. If force is true, an existing item is replaced.
func Add(s *totp.Secret, force bool) error {
	if s.Name == "" {
		return errors.New("secret name is required")
	}
	data, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("marshal secret: %w", err)
	}
	item := baseItem(s.Name)
	item.SetData(data)

	err = keychain.AddItem(item)
	if err == nil {
		return nil
	}
	if !errors.Is(err, keychain.ErrorDuplicateItem) {
		return fmt.Errorf("keychain add: %w", err)
	}
	if !force {
		return ErrExists
	}
	// Replace existing in-place so an interrupted operation never leaves the
	// account with no secret (previously: Delete then Add, which could lose
	// the secret if the process was killed between the two calls).
	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassGenericPassword)
	query.SetService(Service)
	query.SetAccount(s.Name)
	update := keychain.NewItem()
	update.SetData(data)
	update.SetLabel("TOTP: " + s.Name)
	if err := keychain.UpdateItem(query, update); err != nil {
		return fmt.Errorf("keychain update: %w", err)
	}
	return nil
}

// Get fetches and decodes a stored secret. On macOS this will prompt for
// keychain access unless the user has previously clicked "Always Allow".
func Get(name string) (*totp.Secret, error) {
	q := keychain.NewItem()
	q.SetSecClass(keychain.SecClassGenericPassword)
	q.SetService(Service)
	q.SetAccount(name)
	q.SetMatchLimit(keychain.MatchLimitOne)
	q.SetReturnData(true)

	results, err := keychain.QueryItem(q)
	if err != nil {
		return nil, fmt.Errorf("keychain query: %w", err)
	}
	if len(results) == 0 {
		return nil, ErrNotFound
	}
	var s totp.Secret
	if err := json.Unmarshal(results[0].Data, &s); err != nil {
		return nil, fmt.Errorf("decode stored secret: %w", err)
	}
	s.Name = name
	if err := s.Normalize(); err != nil {
		return nil, err
	}
	return &s, nil
}

// List returns stored secret names (no secret data is read).
func List() ([]string, error) {
	q := keychain.NewItem()
	q.SetSecClass(keychain.SecClassGenericPassword)
	q.SetService(Service)
	q.SetMatchLimit(keychain.MatchLimitAll)
	q.SetReturnAttributes(true)

	results, err := keychain.QueryItem(q)
	if err != nil {
		return nil, fmt.Errorf("keychain query: %w", err)
	}
	names := make([]string, 0, len(results))
	for _, r := range results {
		names = append(names, r.Account)
	}
	sort.Strings(names)
	return names, nil
}

// Delete removes the keychain item for name.
func Delete(name string) error {
	q := keychain.NewItem()
	q.SetSecClass(keychain.SecClassGenericPassword)
	q.SetService(Service)
	q.SetAccount(name)
	err := keychain.DeleteItem(q)
	if err == nil {
		return nil
	}
	if errors.Is(err, keychain.ErrorItemNotFound) {
		return ErrNotFound
	}
	return fmt.Errorf("keychain delete: %w", err)
}
