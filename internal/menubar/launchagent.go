// Package menubar implements the macOS menu-bar extra and its launchd
// LaunchAgent installer.
package menubar

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

// LaunchAgentLabel is the launchd Label and the plist's filename stem.
const LaunchAgentLabel = "com.agungcandra.totp-cli.menubar"

// PlistConfig is the input to RenderPlist.
type PlistConfig struct {
	Label      string
	Executable string // absolute, symlink-resolved path to the binary
	Args       []string
}

// RenderPlist returns a LaunchAgent plist for the menu-bar app.
//
// RunAtLoad=true (start at login), KeepAlive=false (do not respawn if the
// user quits), ProcessType=Interactive (so launchd does not deprioritise
// it — it lives in the user's UI session).
//
// String values are XML-escaped so a path containing e.g. an ampersand or
// an angle bracket does not produce malformed XML. The escaping is covered
// by a unit test.
func RenderPlist(cfg PlistConfig) ([]byte, error) {
	if cfg.Label == "" {
		return nil, errors.New("plist: label required")
	}
	if cfg.Executable == "" {
		return nil, errors.New("plist: executable required")
	}
	args := append([]string{cfg.Executable}, cfg.Args...)

	var buf bytes.Buffer
	buf.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	buf.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	buf.WriteString(`<plist version="1.0">` + "\n")
	buf.WriteString("<dict>\n")
	writeKey(&buf, "Label")
	writeString(&buf, cfg.Label)
	writeKey(&buf, "ProgramArguments")
	buf.WriteString("  <array>\n")
	for _, a := range args {
		buf.WriteString("    ")
		writeString(&buf, a)
	}
	buf.WriteString("  </array>\n")
	writeKey(&buf, "RunAtLoad")
	buf.WriteString("  <true/>\n")
	writeKey(&buf, "KeepAlive")
	buf.WriteString("  <false/>\n")
	writeKey(&buf, "ProcessType")
	writeString(&buf, "Interactive")
	buf.WriteString("</dict>\n</plist>\n")
	return buf.Bytes(), nil
}

func writeKey(buf *bytes.Buffer, k string) {
	buf.WriteString("  <key>")
	_ = xml.EscapeText(buf, []byte(k))
	buf.WriteString("</key>\n")
}

func writeString(buf *bytes.Buffer, s string) {
	buf.WriteString("<string>")
	_ = xml.EscapeText(buf, []byte(s))
	buf.WriteString("</string>\n")
}

// PlistPath returns ~/Library/LaunchAgents/<label>.plist.
func PlistPath(homeDir string) string {
	return filepath.Join(homeDir, "Library", "LaunchAgents", LaunchAgentLabel+".plist")
}

// resolveExecutable returns the absolute, symlink-resolved path to the
// current binary. This is what goes into the plist so launchd invokes the
// binary the user actually installed, not whatever is on $PATH at boot.
func resolveExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("executable path: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return "", fmt.Errorf("resolve symlinks: %w", err)
	}
	return resolved, nil
}

// Install writes the plist to ~/Library/LaunchAgents/ and bootstraps it
// into the user's GUI domain. If the agent is already loaded it is booted
// out first so the new plist takes effect.
func Install() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	exe, err := resolveExecutable()
	if err != nil {
		return err
	}
	data, err := RenderPlist(PlistConfig{
		Label:      LaunchAgentLabel,
		Executable: exe,
		Args:       []string{"menubar"},
	})
	if err != nil {
		return err
	}
	dir := filepath.Join(home, "Library", "LaunchAgents")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	path := PlistPath(home)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	uid := strconv.Itoa(os.Getuid())
	target := "gui/" + uid
	// Best-effort bootout first; ignore "not loaded" exit codes.
	_ = exec.Command("launchctl", "bootout", target+"/"+LaunchAgentLabel).Run()
	if out, err := exec.Command("launchctl", "bootstrap", target, path).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl bootstrap: %w: %s", err, bytes.TrimSpace(out))
	}
	return nil
}

// Uninstall boots out the LaunchAgent and removes the plist. A missing
// agent / plist is not an error.
func Uninstall() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	uid := strconv.Itoa(os.Getuid())
	// SHORTCUT: ignore launchctl bootout exit code; upgrade when we need to
	// distinguish "not loaded" from genuine failures (requires parsing
	// stderr — launchctl's exit codes are poorly documented).
	_ = exec.Command("launchctl", "bootout", "gui/"+uid+"/"+LaunchAgentLabel).Run()
	path := PlistPath(home)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", path, err)
	}
	return nil
}
