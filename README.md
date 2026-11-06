# totp-cli

A minimal macOS CLI for generating [TOTP](https://datatracker.ietf.org/doc/html/rfc6238) codes. Secrets are stored in the macOS **login Keychain** as generic-password items, and sensitive operations (`get`, `rm`) are gated behind **Touch ID / account password** via `LocalAuthentication`.

## Install

Requires Go 1.25+ and macOS.

```sh
go install github.com/agungcandra/totp-cli/cmd/totp@latest
```

This installs a binary called `totp` into `$GOBIN` (default `$HOME/go/bin`).

## Usage

```sh
# Add a secret from an otpauth:// URI — the URI is read from a hidden prompt,
# never from argv, so it will not appear in shell history or `ps`.
totp add github --uri

# Add a secret interactively — the base32 secret is read from a hidden prompt
totp add work

# Generate a code (Touch ID prompt). Code goes to stdout; "expires in Ns" to stderr.
totp get github
totp get github --copy        # also pipes the code to pbcopy

# List stored secret names (no auth required, no secret data read)
totp list

# Delete a secret (Touch ID prompt — grace window is ignored here)
totp rm github
```

Flags for `add`:

- `--uri` — read an `otpauth://totp/...` URI from the hidden prompt (fields override individual flags).
- `--digits` — `6` (default) or `8`.
- `--period` — seconds per step (default `30`).
- `--algo` — `SHA1` (default), `SHA256`, or `SHA512`.
- `--force` — overwrite an existing secret of the same name.

### 30-second auth grace window

After a successful Touch ID / password prompt from `totp get`, the next 30
seconds of `totp get` calls (for **any** account) skip the prompt. This is a
single global window, backed by a keychain item that you can inspect in
**Keychain Access** under the service `com.agungcandra.totp-cli.session` (it
is intentionally a separate service from the secrets, so `totp list` never
shows it).

- `totp rm` **always** prompts, regardless of the window.
- Trade-off: during the window, any process running as your user can invoke
  `totp get` and obtain a code without a biometric prompt. Only this signed
  binary can silently upsert the session item (macOS gates keychain writes
  by the calling application's code signature), so another process cannot
  extend or forge the window without first triggering its own "allow"
  dialog.
- The window is clamped: a session item whose expiry is more than 30 seconds
  in the future (e.g. from a clock that moved backwards, or tampering) is
  treated as invalid and `totp get` will prompt again.

## Security model

- Secrets are JSON-encoded and stored as generic-password items in the login Keychain with:
  - `Service = com.agungcandra.totp-cli`
  - `Account = <name>`
  - `Label  = "TOTP: <name>"`
  - `Accessible = AccessibleWhenUnlockedThisDeviceOnly`
  - `Synchronizable = No` (never synced to iCloud)
- Before reading or deleting a secret, `totp` calls `LAContext.evaluatePolicy(DeviceOwnerAuthentication)`, which prompts for Touch ID or your macOS account password.
- `list` reads only attribute data (not the secret), so it does not trigger auth.

### Known trade-off — SHORTCUT

The Touch ID gate is enforced by **this binary**, not by the Keychain item's ACL. A more defensible design would use `kSecAccessControlUserPresence` on the Keychain item so that *any* process asking for the secret must pass biometric auth. That path requires the binary to be signed with a Developer ID and a provisioning profile, otherwise macOS returns `errSecMissingEntitlement (-34018)` to unsigned CLIs. The code is marked with a `SHORTCUT` comment where this applies.

Practically, this means any process you give access to your Keychain to could read a secret. macOS gates Keychain reads by *application*: the first time you (or a rebuilt copy of `totp`) reads a secret you will see the native "allow / always allow" dialog. **Rebuilding the binary changes its code signature**, so after `go install` you will be asked to "Always Allow" again — that is expected.

## Menu bar app

`totp menubar` runs a macOS menu-bar extra: a monochrome template icon in
the system menu bar with one item per stored account (names only — codes
are never shown in the menu). Click an account to copy its current TOTP
code to the clipboard.

```sh
# Run the menu bar app in the foreground (Ctrl+C or the Quit menu item exits).
totp menubar

# Install a LaunchAgent so it starts at login.
totp menubar --install

# Remove the LaunchAgent.
totp menubar --uninstall
```

Behaviour:

- **Shared auth with `totp get`.** Clicking an account runs the same code
  path as the CLI `get`: within the 30-second grace window no prompt
  appears; outside it, Touch ID / your account password is required. The
  grace window is shared between the CLI and the menu bar.
- **Names-only menu.** The menu lists account names. Codes never appear in
  the menu — they only land on the clipboard after you click.
- **Clipboard auto-clear.** 30 seconds after a successful copy the
  clipboard is cleared, but only if it still contains the code `totp` put
  there. If you have copied something else in the meantime, that is left
  alone.
- **macOS notification.** Each copy / error pops a short "Copied code for
  &lt;name&gt;" / error notification via `osascript`. If copying to the
  clipboard fails, the notification shows the code itself as a fallback so
  you can still type it (and it remains in Notification Center history).
- **Auto-refresh.** The menu re-reads the keychain account list every
  ~45s, and immediately via **Refresh accounts**, so newly added secrets
  appear without restarting.
- **No Dock icon.** The process sets `NSApplicationActivationPolicyAccessory`
  on startup, so no Dock icon or app-switcher entry appears.

### LaunchAgent (`--install` / `--uninstall`)

`--install` writes `~/Library/LaunchAgents/com.agungcandra.totp-cli.menubar.plist`
pointing at the current binary (`os.Executable()` + `filepath.EvalSymlinks`)
with `menubar` as its only argument, then runs:

```
launchctl bootout   gui/<uid>/com.agungcandra.totp-cli.menubar   # best-effort
launchctl bootstrap gui/<uid> <plist>
```

`--uninstall` reverses both.

> **Install from a stable path.** The plist stores the absolute path to the
> binary. If you run `totp menubar --install` from a scratch build (e.g.
> `./totp`), the LaunchAgent will reference that file; move or delete it and
> the agent stops working. Install only after `go install`, so the path is
> `$GOBIN/totp`.
>
> **Rebuilding re-prompts for Keychain access.** Each `go install` produces a
> new code signature, which macOS treats as a different application for
> Keychain ACL purposes — you will see the native "Allow / Always Allow"
> dialog the first time the rebuilt binary reads a secret. That is expected.

### Tests

```sh
go test ./internal/totp/... ./internal/store/... ./internal/menubar/...
```

Unit tests cover the RFC 6238 Appendix B vectors for SHA1 / SHA256 / SHA512, base32 normalization, and `otpauth://` URI parsing. Tests never touch the Keychain or LocalAuthentication.
