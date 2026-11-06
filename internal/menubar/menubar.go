package menubar

import (
	_ "embed"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"fyne.io/systray"

	"github.com/agungcandra/totp-cli/internal/clipboard"
	"github.com/agungcandra/totp-cli/internal/otp"
	"github.com/agungcandra/totp-cli/internal/store"
)

//go:embed icon.png
var iconPNG []byte

// refreshInterval is how often the menu re-queries store.List so newly
// added / removed accounts appear without the user clicking Refresh.
// Attribute reads don't prompt for Touch ID, so this is cheap.
const refreshInterval = 45 * time.Second

// clipboardClearDelay is how long after a copy we clear the pasteboard,
// as long as it still contains the code we put there.
const clipboardClearDelay = 30 * time.Second

// Run blocks the main goroutine driving the macOS menu-bar extra. It must
// be called from main() (systray requires the main thread on macOS).
func Run() {
	// Hide the Dock icon before systray.Run attaches to NSApplication.
	setAccessoryPolicy()
	systray.Run(onReady, func() {})
}

// state is the mutable menu state guarded by mu.
type state struct {
	mu   sync.Mutex
	stop chan struct{} // closed on refresh to unblock the previous menu's goroutines
	// authMu serialises account-click handlers so only one Touch ID prompt
	// is on screen at a time.
	authMu sync.Mutex
}

var app state

func onReady() {
	systray.SetTemplateIcon(iconPNG, iconPNG)
	systray.SetTooltip("totp")

	// Static items first (separator + Refresh + Quit live at the bottom of
	// the menu). Account items are inserted above them; systray adds items
	// in call order, so we build dynamic items on each refresh and reuse
	// these static ones.
	// Build an initial batch of account slots. systray.MenuItem has no
	// "insert before" API, so we take a different approach: we rebuild the
	// full menu via ResetMenu on every refresh.
	refresh()

	// Background auto-refresh.
	go func() {
		t := time.NewTicker(refreshInterval)
		defer t.Stop()
		for range t.C {
			refresh()
		}
	}()
}

// refresh rebuilds the menu from store.List. store.List only reads
// attributes, so it does not prompt for Touch ID.
func refresh() {
	names, err := store.List()
	if err != nil {
		// Can't surface via notification without the user clicking; show
		// an empty menu with a disabled error row.
		names = nil
	}
	sort.Strings(names)

	app.mu.Lock()
	defer app.mu.Unlock()

	// Signal goroutines from the previous menu generation to exit. systray
	// does not close old ClickedCh channels when ResetMenu is called, so
	// without this signal we'd leak a goroutine per account per refresh.
	if app.stop != nil {
		close(app.stop)
	}
	stop := make(chan struct{})
	app.stop = stop

	systray.ResetMenu()

	if err != nil {
		errItem := systray.AddMenuItem("error: "+err.Error(), "")
		errItem.Disable()
	} else if len(names) == 0 {
		empty := systray.AddMenuItem("(no accounts — use `totp add`)", "")
		empty.Disable()
	} else {
		for _, name := range names {
			item := systray.AddMenuItem(name, "copy code for "+name)
			go handleClicks(name, item, stop)
		}
	}
	systray.AddSeparator()
	refreshBtn := systray.AddMenuItem("Refresh accounts", "re-read accounts from keychain")
	quitBtn := systray.AddMenuItem("Quit", "")
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-refreshBtn.ClickedCh:
				go refresh()
			case <-quitBtn.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()
}

// handleClicks consumes clicks for one account item until the menu is
// rebuilt (stop is closed) or systray closes the channel.
func handleClicks(name string, item *systray.MenuItem, stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		case _, ok := <-item.ClickedCh:
			if !ok {
				return
			}
			go copyCodeFor(name)
		}
	}
}

func copyCodeFor(name string) {
	// One prompt at a time. If another click is mid-auth we queue behind
	// it; when we acquire the lock the earlier auth may have refreshed the
	// grace window, in which case otp.Generate will not prompt again.
	app.authMu.Lock()
	defer app.authMu.Unlock()

	res, err := otp.Generate(name, time.Now(), nil, nil)
	if err != nil {
		notify(fmt.Sprintf("totp: %s — %s", name, shortErr(err)))
		return
	}
	if err := clipboard.Copy(res.Code); err != nil {
		notify(fmt.Sprintf("totp: %s — clipboard error", name))
		return
	}
	notify("Copied code for " + name)
	// Auto-clear clipboard after the code expires-ish, but only if the
	// clipboard still contains the code we put there.
	go clearClipboardLater(res.Code, clipboardClearDelay)
}

func clearClipboardLater(code string, after time.Duration) {
	time.Sleep(after)
	cur, err := clipboard.Paste()
	if err != nil {
		return
	}
	if cur != code {
		return
	}
	_ = clipboard.Copy("")
}

func shortErr(err error) string {
	s := err.Error()
	// SHORTCUT: trim long errors to one line; upgrade when we want
	// per-error-type strings (cancelled vs failed vs unavailable).
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 80 {
		s = s[:80] + "…"
	}
	return s
}

// notify shows a macOS notification. The message is passed via argv to
// osascript (`on run argv`), not interpolated into the script, so a name
// containing quotes or backslashes cannot break out and execute AppleScript.
func notify(message string) {
	const script = `on run argv
	display notification (item 1 of argv) with title "totp"
end run`
	cmd := exec.Command("osascript", "-e", script, "--", message)
	// SHORTCUT: swallow notification errors; upgrade when we want a log.
	_ = cmd.Run()
}
