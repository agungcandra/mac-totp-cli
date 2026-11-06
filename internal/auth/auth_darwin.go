//go:build darwin

// Package auth gates sensitive operations behind macOS LocalAuthentication
// (Touch ID or account password).
//
// SHORTCUT: gate enforced by binary, not keychain ACL; upgrade to
// kSecAccessControlUserPresence when signed with Developer ID + provisioning profile.
package auth

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework LocalAuthentication -framework Foundation

#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>

// authResult: 0 = success, 1 = user cancelled, 2 = auth failed,
// 3 = policy unavailable (no Touch ID / passcode), 4 = other.
static int totp_authenticate(const char *reason) {
    @autoreleasepool {
        LAContext *ctx = [[LAContext alloc] init];
        NSError *evalErr = nil;
        if (![ctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&evalErr]) {
            return 3;
        }
        NSString *nsReason = [NSString stringWithUTF8String:reason];
        __block int result = 4;
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        [ctx evaluatePolicy:LAPolicyDeviceOwnerAuthentication
            localizedReason:nsReason
                      reply:^(BOOL success, NSError *error) {
            if (success) {
                result = 0;
            } else if (error) {
                switch (error.code) {
                    case LAErrorUserCancel:
                    case LAErrorAppCancel:
                    case LAErrorSystemCancel:
                        result = 1;
                        break;
                    case LAErrorAuthenticationFailed:
                        result = 2;
                        break;
                    case LAErrorPasscodeNotSet:
                        result = 3;
                        break;
                    default:
                        result = 4;
                        break;
                }
            }
            dispatch_semaphore_signal(sem);
        }];
        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
        return result;
    }
}
*/
import "C"

import (
	"errors"
	"unsafe"
)

// ErrCancelled means the user dismissed the auth prompt.
var ErrCancelled = errors.New("authentication cancelled")

// ErrFailed means the user tried to authenticate but failed.
var ErrFailed = errors.New("authentication failed")

// ErrUnavailable means the device has no Touch ID / passcode configured.
var ErrUnavailable = errors.New("authentication unavailable on this device")

// Authenticate prompts the user via LocalAuthentication. The reason string
// appears in the system dialog.
func Authenticate(reason string) error {
	cReason := C.CString(reason)
	defer C.free(unsafe.Pointer(cReason))
	switch int(C.totp_authenticate(cReason)) {
	case 0:
		return nil
	case 1:
		return ErrCancelled
	case 2:
		return ErrFailed
	case 3:
		return ErrUnavailable
	default:
		return errors.New("authentication error")
	}
}
