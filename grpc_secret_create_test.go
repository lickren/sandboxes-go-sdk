package sandboxes

import (
	"context"
	"errors"
	"net"
	"testing"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type captureSecretCreateServer struct {
	localv1.UnimplementedSecretServiceServer
	request *localv1.SecretServiceCreateRequest
	err     error
}

func (s *captureSecretCreateServer) Create(_ context.Context, req *localv1.SecretServiceCreateRequest) (*localv1.SecretServiceCreateResponse, error) {
	s.request = req
	if s.err != nil {
		return nil, s.err
	}
	return &localv1.SecretServiceCreateResponse{Secret: &localv1.SecretSummary{
		Service: req.GetService(), Scope: req.GetScope(), SandboxName: req.GetSandboxName(),
	}}, nil
}

func TestSecretCreationUsesAtomicCreateRPC(t *testing.T) {
	tests := []struct {
		name      string
		serverErr error
		wantCode  string
	}{
		{name: "created"},
		{name: "already exists", serverErr: status.Error(codes.AlreadyExists, "service secret already exists"), wantCode: "already_exists"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listener := bufconn.Listen(1024 * 1024)
			server := grpc.NewServer()
			capture := &captureSecretCreateServer{err: tt.serverErr}
			localv1.RegisterSecretServiceServer(server, capture)
			go func() { _ = server.Serve(listener) }()
			t.Cleanup(server.Stop)

			client, err := New(Config{Address: "bufnet", Dialer: func(ctx context.Context, _ string) (net.Conn, error) {
				return listener.DialContext(ctx)
			}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })

			creator, ok := SecretCreation(client)
			if !ok {
				t.Fatal("client does not expose create-only capability")
			}
			secret, err := creator.Create(context.Background(), "github", SecretScopeSandbox, "dev", []byte("synthetic-token"))
			if tt.wantCode != "" {
				var sdkErr *Error
				if !errors.As(err, &sdkErr) || sdkErr.Code != tt.wantCode {
					t.Fatalf("error=%v, want SDK error code %q", err, tt.wantCode)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if capture.request == nil || capture.request.GetService() != "github" || capture.request.GetScope() != string(SecretScopeSandbox) ||
				capture.request.GetSandboxName() != "dev" || string(capture.request.GetValue()) != "synthetic-token" {
				t.Fatalf("unexpected atomic create request: %+v", capture.request)
			}
			if tt.wantCode == "" && (secret.Service != "github" || secret.Scope != SecretScopeSandbox || secret.SandboxName != "dev") {
				t.Fatalf("unexpected response mapping: %+v", secret)
			}
		})
	}
}
