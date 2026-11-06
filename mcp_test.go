package sandboxes

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type mcpTestServer struct {
	localv1.UnimplementedSandboxServiceServer
	apiVersion string
	callCount  int
	request    *localv1.MCPCallRequest
	callErr    error
}

func (s *mcpTestServer) GetVersion(context.Context, *localv1.GetVersionRequest) (*localv1.GetVersionResponse, error) {
	return &localv1.GetVersionResponse{Version: "test", ApiVersion: s.apiVersion}, nil
}

func (s *mcpTestServer) MCPCall(_ context.Context, request *localv1.MCPCallRequest) (*localv1.MCPCallResponse, error) {
	s.callCount++
	s.request = request
	if s.callErr != nil {
		return nil, s.callErr
	}
	return &localv1.MCPCallResponse{ResultJson: `{"content":[]}`}, nil
}

func newMCPTestClient(t *testing.T, apiVersion string) (Client, *mcpTestServer, func()) {
	t.Helper()
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	implementation := &mcpTestServer{apiVersion: apiVersion}
	localv1.RegisterSandboxServiceServer(server, implementation)
	go func() { _ = server.Serve(listener) }()
	client, err := New(Config{
		Address: "mcp-bufnet",
		Dialer: func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		},
	})
	if err != nil {
		server.Stop()
		t.Fatal(err)
	}
	return client, implementation, func() {
		_ = client.Close()
		server.Stop()
	}
}

func TestMCPCallSendsValidatedArgumentsAndReturnsJSON(t *testing.T) {
	client, server, cleanup := newMCPTestClient(t, "0.0.18")
	defer cleanup()
	arguments := json.RawMessage(`{"query":"synthetic"}`)
	result, err := MCP(client).Call(context.Background(), "sb-owned", "search", "find", arguments)
	if err != nil {
		t.Fatal(err)
	}
	if string(result) != `{"content":[]}` || server.callCount != 1 {
		t.Fatalf("result=%s calls=%d", result, server.callCount)
	}
	if server.request.GetSandboxId() != "sb-owned" || server.request.GetServerName() != "search" || server.request.GetToolName() != "find" || server.request.GetArgumentsJson() != string(arguments) {
		t.Fatalf("request=%+v", server.request)
	}
}

func TestMCPCallDefaultsEmptyArgumentsToObject(t *testing.T) {
	client, server, cleanup := newMCPTestClient(t, "0.0.18")
	defer cleanup()
	if _, err := MCP(client).Call(context.Background(), "sb-owned", "search", "find", nil); err != nil {
		t.Fatal(err)
	}
	if server.request.GetArgumentsJson() != "{}" {
		t.Fatalf("arguments = %q, want empty object", server.request.GetArgumentsJson())
	}
}

func TestMCPCallRejectsInvalidArgumentsAndOldDaemon(t *testing.T) {
	client, server, cleanup := newMCPTestClient(t, "0.0.18")
	_, err := MCP(client).Call(context.Background(), "sb-owned", "search", "find", json.RawMessage(`[]`))
	if err == nil || server.callCount != 0 {
		t.Fatalf("invalid arguments err=%v calls=%d", err, server.callCount)
	}
	cleanup()

	client, server, cleanup = newMCPTestClient(t, "0.0.17")
	defer cleanup()
	_, err = MCP(client).Call(context.Background(), "sb-owned", "search", "find", nil)
	var typed *Error
	if !errors.As(err, &typed) || typed.Code != errorCodeUnsupported || server.callCount != 0 {
		t.Fatalf("old daemon err=%v calls=%d", err, server.callCount)
	}
}

func TestMCPCallMapsDaemonErrors(t *testing.T) {
	client, server, cleanup := newMCPTestClient(t, "0.0.18")
	defer cleanup()
	server.callErr = status.Error(codes.PermissionDenied, "approval denied")
	_, err := MCP(client).Call(context.Background(), "sb-1", "search", "find", nil)
	var typed *Error
	if !errors.As(err, &typed) || typed.Code != "permission_denied" {
		t.Fatalf("error = %v", err)
	}
}
