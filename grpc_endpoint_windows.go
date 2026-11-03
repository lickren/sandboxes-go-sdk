//go:build windows

package sandboxes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"path/filepath"
	"strings"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

const localPipePrefix = `\\.\pipe\lickren-sandboxesd-`

func localGRPCEndpoint(address string, dialer func(context.Context, string) (net.Conn, error)) (string, func(context.Context, string) (net.Conn, error), error) {
	if dialer != nil {
		return "passthrough:///local-daemon", dialer, nil
	}
	pipe, err := localPipePath(address)
	if err != nil {
		return "", nil, err
	}
	return "passthrough:///local-daemon", func(ctx context.Context, _ string) (net.Conn, error) {
		return winio.DialPipeContext(ctx, pipe)
	}, nil
}

func localPipePath(address string) (string, error) {
	if strings.HasPrefix(strings.ToLower(address), strings.ToLower(`\\.\pipe\`)) {
		return address, nil
	}
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("read current user SID: %w", err)
	}
	identity := user.User.Sid.String() + "\x00" + strings.ToLower(filepath.Clean(address))
	sum := sha256.Sum256([]byte(identity))
	return localPipePrefix + hex.EncodeToString(sum[:16]), nil
}
