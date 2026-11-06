// Command totp is a macOS CLI for generating TOTP codes backed by the login
// Keychain, with Touch ID / account password gating on sensitive operations.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/agungcandra/totp-cli/internal/auth"
	"github.com/agungcandra/totp-cli/internal/clipboard"
	"github.com/agungcandra/totp-cli/internal/menubar"
	"github.com/agungcandra/totp-cli/internal/otp"
	"github.com/agungcandra/totp-cli/internal/store"
	"github.com/agungcandra/totp-cli/internal/totp"
)

const usage = `totp - macOS CLI TOTP manager (Keychain + Touch ID)

Usage:
  totp add <name> [--uri] [--digits 6] [--period 30] [--algo SHA1] [--force]
  totp get <name> [--copy]
  totp list
  totp rm  <name>
  totp menubar [--install | --uninstall]
  totp help

Default: the base32 secret is read from a hidden prompt. With --uri an
otpauth:// URI is read from the hidden prompt instead (so it never appears
in argv / shell history / 'ps').

'totp get' skips the Touch ID prompt for 30 seconds after a successful
authentication (across all accounts). 'totp rm' always prompts.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]
	var err error
	switch cmd {
	case "add":
		err = runAdd(args)
	case "get":
		err = runGet(args)
	case "list", "ls":
		err = runList(args)
	case "rm", "remove", "delete":
		err = runRm(args)
	case "menubar":
		err = runMenubar(args)
	case "help", "-h", "--help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func runAdd(args []string) error {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	uri := fs.Bool("uri", false, "read an otpauth:// URI from the hidden prompt instead of a base32 secret")
	digits := fs.Int("digits", 6, "code digits (6 or 8)")
	period := fs.Int("period", 30, "period seconds")
	algo := fs.String("algo", "SHA1", "algorithm (SHA1, SHA256, SHA512)")
	force := fs.Bool("force", false, "overwrite existing secret")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return errors.New("add: <name> required")
	}
	name := fs.Arg(0)

	var s *totp.Secret
	if *uri {
		raw, err := readHidden("Enter otpauth:// URI: ")
		if err != nil {
			return err
		}
		parsed, err := totp.ParseURI(raw)
		if err != nil {
			return err
		}
		s = parsed
		s.Name = name
	} else {
		raw, err := readHidden("Enter base32 TOTP secret: ")
		if err != nil {
			return err
		}
		s = &totp.Secret{
			Name:      name,
			Secret:    raw,
			Algorithm: totp.Algorithm(strings.ToUpper(*algo)),
			Digits:    *digits,
			Period:    *period,
		}
		if err := s.Normalize(); err != nil {
			return err
		}
	}
	// Validate by generating one code.
	if _, err := s.Generate(); err != nil {
		return fmt.Errorf("secret validation: %w", err)
	}
	if err := store.Add(s, *force); err != nil {
		if errors.Is(err, store.ErrExists) {
			return fmt.Errorf("secret %q already exists (use --force to overwrite)", name)
		}
		return err
	}
	fmt.Fprintf(os.Stderr, "added %q\n", name)
	return nil
}

// readHidden reads one line from a tty with echo disabled, or the whole of
// stdin when stdin is a pipe. Either way the secret never appears in argv.
func readHidden(prompt string) (string, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		fmt.Fprint(os.Stderr, prompt)
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("read input: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", fmt.Errorf("read input: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

func runGet(args []string) error {
	fs := flag.NewFlagSet("get", flag.ContinueOnError)
	copyFlag := fs.Bool("copy", false, "copy code to clipboard via pbcopy")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return errors.New("get: <name> required")
	}
	name := fs.Arg(0)
	// Trade-off: within the 30s grace window any process running as this
	// user can shell out to `totp get` and obtain a code without a Touch ID
	// prompt. Only this signed binary can silently upsert the session item
	// (macOS gates keychain writes by application identity), so a different
	// process cannot extend or forge the window without triggering its own
	// "allow" dialog. `totp rm` always authenticates regardless.
	res, err := otp.Generate(name, nowFn(), auth.Authenticate, func(w string) {
		fmt.Fprintln(os.Stderr, w)
	})
	if err != nil {
		return authError(err)
	}
	fmt.Fprintln(os.Stdout, res.Code)
	fmt.Fprintf(os.Stderr, "(expires in %ds)\n", res.SecondsRemaining)
	if *copyFlag {
		if err := clipboard.Copy(res.Code); err != nil {
			return fmt.Errorf("pbcopy: %w", err)
		}
		fmt.Fprintln(os.Stderr, "code copied to clipboard")
	}
	return nil
}

func runMenubar(args []string) error {
	fs := flag.NewFlagSet("menubar", flag.ContinueOnError)
	install := fs.Bool("install", false, "install LaunchAgent so the menu bar starts at login")
	uninstall := fs.Bool("uninstall", false, "remove the LaunchAgent")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *install && *uninstall {
		return errors.New("menubar: --install and --uninstall are mutually exclusive")
	}
	if *install {
		if err := menubar.Install(); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "installed LaunchAgent "+menubar.LaunchAgentLabel)
		return nil
	}
	if *uninstall {
		if err := menubar.Uninstall(); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "uninstalled LaunchAgent "+menubar.LaunchAgentLabel)
		return nil
	}
	menubar.Run() // blocks on main; must be the only call from main.
	return nil
}

func runList(_ []string) error {
	names, err := store.List()
	if err != nil {
		return err
	}
	for _, n := range names {
		fmt.Println(n)
	}
	return nil
}

func runRm(args []string) error {
	fs := flag.NewFlagSet("rm", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return errors.New("rm: <name> required")
	}
	name := fs.Arg(0)
	if err := auth.Authenticate("delete TOTP secret for " + name); err != nil {
		return authError(err)
	}
	if err := store.Delete(name); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("no secret named %q", name)
		}
		return err
	}
	fmt.Fprintf(os.Stderr, "removed %q\n", name)
	return nil
}

func authError(err error) error {
	switch {
	case errors.Is(err, auth.ErrCancelled):
		return errors.New("authentication cancelled")
	case errors.Is(err, auth.ErrFailed):
		return errors.New("authentication failed")
	case errors.Is(err, auth.ErrUnavailable):
		return errors.New("Touch ID / account password unavailable on this device")
	default:
		return err
	}
}

var nowFn = time.Now
