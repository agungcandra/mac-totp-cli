//go:build darwin

package menubar

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Cocoa
#import <Cocoa/Cocoa.h>

// Hide the Dock icon so this process is a true menu-bar accessory.
// Calling this before systray.Run() is harmless if the shared NSApplication
// has not yet been created — [NSApplication sharedApplication] creates it.
static void totp_set_accessory_policy(void) {
    [[NSApplication sharedApplication] setActivationPolicy:NSApplicationActivationPolicyAccessory];
}
*/
import "C"

// setAccessoryPolicy flips NSApplicationActivationPolicy to Accessory so the
// menu-bar process does not show a Dock icon. systray does not do this
// itself (as of fyne.io/systray v1.12.2), so we do it explicitly on main
// before systray.Run takes over the thread.
func setAccessoryPolicy() {
	C.totp_set_accessory_policy()
}
