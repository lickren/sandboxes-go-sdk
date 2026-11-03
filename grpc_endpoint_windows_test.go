//go:build windows

package sandboxes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
	localv1 "github.com/lickren/sandboxes-api/gen/go/sandboxes/local/v1"
	"golang.org/x/sys/windows"
	"google.golang.org/grpc"
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
	const explicit = `\\.\pipe\lickren-custom-daemon`
	got, err := localPipePath(explicit)
	if err != nil {
		t.Fatal(err)
	}
	if got != explicit {
		t.Fatalf("explicit endpoint changed: got %q, want %q", got, explicit)
	}
}

type windowsPipeSandboxServer struct {
	localv1.UnimplementedSandboxServiceServer
}

func (windowsPipeSandboxServer) List(context.Context, *localv1.ListRequest) (*localv1.ListResponse, error) {
	return &localv1.ListResponse{Items: []*localv1.Sandbox{{Id: "sb-windows-ci"}}}, nil
}

func TestWindowsSDKConnectsToDaemonPipe(t *testing.T) {
	address := filepath.Join(t.TempDir(), "sandboxesd.sock")
	pipe, err := localPipePath(address)
	if err != nil {
		t.Fatal(err)
	}
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := winio.ListenPipe(pipe, &winio.PipeConfig{
		SecurityDescriptor: "D:P(A;;GA;;;" + user.User.Sid.String() + ")(A;;GA;;;SY)",
	})
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	localv1.RegisterSandboxServiceServer(server, windowsPipeSandboxServer{})
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		select {
		case <-serveDone:
		case <-time.After(5 * time.Second):
			t.Error("gRPC server did not stop")
		}
	})

	client, err := New(Config{Address: address, CallTimeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	page, err := client.Sandboxes().List(ctx, ListOptions{})
	if err != nil {
		t.Fatalf("list sandboxes over the SDK named-pipe dialer: %v", err)
	}
	if len(page.Items) != 1 || page.Items[0].ID != "sb-windows-ci" {
		t.Fatalf("unexpected SDK response: %+v", page.Items)
	}
}
