//go:build windows

package sandboxes

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsLocalPipePathMatchesPerUserContract(t *testing.T) {
	address := filepath.Join(`C:\Users\runner`, `.sandboxes`, `sandboxesd.sock`)
	got, err := localPipePath(address)
	if err != nil {
		t.Fatal(err)
	}
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	identity := user.User.Sid.String() + "\x00" + strings.ToLower(filepath.Clean(address))
	sum := sha256.Sum256([]byte(identity))
	want := localPipePrefix + hex.EncodeToString(sum[:16])
	if got != want {
		t.Fatalf("pipe path mismatch: got %q, want %q", got, want)
	}
}

func TestWindowsLocalPipePathPreservesExplicitPipe(t *testing.T) {
	const explicit = `\\.\pipe\quoiner-custom-daemon`
	got, err := localPipePath(explicit)
	if err != nil {
		t.Fatal(err)
	}
	if got != explicit {
		t.Fatalf("explicit endpoint changed: got %q, want %q", got, explicit)
	}
}
