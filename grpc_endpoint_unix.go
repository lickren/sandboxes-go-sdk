//go:build !windows

package sandboxes

import (
	"context"
	"net"
)

func localGRPCEndpoint(address string, dialer func(context.Context, string) (net.Conn, error)) (string, func(context.Context, string) (net.Conn, error), error) {
	return "unix:" + address, dialer, nil
}
