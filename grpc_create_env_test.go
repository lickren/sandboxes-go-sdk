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

type captureCreateServer struct {
	localv1.UnimplementedSandboxServiceServer
	request    chan *localv1.CreateRequest
	apiVersion string
	versionErr error
}

func (s captureCreateServer) Create(_ context.Context, req *localv1.CreateRequest) (*localv1.CreateResponse, error) {
	s.request <- req
	return &localv1.CreateResponse{Operation: &localv1.Operation{Id: "op-1", SandboxId: "sb-1"}}, nil
}

func (s captureCreateServer) GetVersion(context.Context, *localv1.GetVersionRequest) (*localv1.GetVersionResponse, error) {
	if s.versionErr != nil {
		return nil, s.versionErr
	}
	return &localv1.GetVersionResponse{Version: "test", ApiVersion: s.apiVersion}, nil
}

func TestCreatePassesEnv(t *testing.T) {
	lis := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	capture := captureCreateServer{request: make(chan *localv1.CreateRequest, 1), apiVersion: "0.0.15"}
	localv1.RegisterSandboxServiceServer(server, capture)
	go func() { _ = server.Serve(lis) }()
	t.Cleanup(server.Stop)
	client, err := New(Config{Address: "bufnet", Dialer: func(ctx context.Context, _ string) (net.Conn, error) {
		return lis.DialContext(ctx)
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if _, err := client.Sandboxes().Create(context.Background(), CreateRequest{
		Name: "dev", Env: map[string]string{"A": "1"}, PolicyProfile: "balanced",
		OAuthCredentials: []OAuthCredential{{
			Service: "claude", TokenEndpoint: OAuthTokenEndpoint{Host: "auth.example.test", Path: "/oauth/token"},
			ResourceHosts: []string{"api.example.test"}, Sentinels: OAuthSentinels{AccessToken: "access-sentinel", RefreshToken: "refresh-sentinel"},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	req := <-capture.request
	if req.GetEnv()["A"] != "1" || req.GetPolicyProfile() != "balanced" {
		t.Fatalf("env=%v", req.GetEnv())
	}
	credentials := req.GetOauthCredentials()
	if len(credentials) != 1 || credentials[0].GetTokenEndpoint().GetHost() != "auth.example.test" || len(credentials[0].GetResourceHosts()) != 1 ||
		credentials[0].GetSentinels().GetAccessToken() != "access-sentinel" {
		t.Fatalf("OAuth credentials did not roundtrip through Create: %+v", credentials)
	}
}

func TestCreateFailsClosedWhenDaemonOAuthMetadataSupportIsUnverified(t *testing.T) {
	tests := []struct {
		name       string
		apiVersion string
		versionErr error
		wantCode   string
	}{
		{name: "older daemon version", apiVersion: "0.0.14", wantCode: errorCodeUnsupported},
		{name: "unknown daemon version", apiVersion: "not-a-version", wantCode: errorCodeUnsupported},
		{name: "version check unavailable", versionErr: status.Error(codes.Unimplemented, "version check unavailable"), wantCode: errorCodeInternal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listener := bufconn.Listen(1024 * 1024)
			server := grpc.NewServer()
			capture := captureCreateServer{
				request: make(chan *localv1.CreateRequest, 1), apiVersion: tt.apiVersion, versionErr: tt.versionErr,
			}
			localv1.RegisterSandboxServiceServer(server, capture)
			go func() { _ = server.Serve(listener) }()
			t.Cleanup(server.Stop)
			client, err := New(Config{Address: "bufnet", Dialer: func(ctx context.Context, _ string) (net.Conn, error) {
				return listener.DialContext(ctx)
			}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })

			_, err = client.Sandboxes().Create(context.Background(), CreateRequest{OAuthCredentials: []OAuthCredential{{Service: "claude"}}})
			var sdkErr *Error
			if !errors.As(err, &sdkErr) || sdkErr.Code != tt.wantCode {
				t.Fatalf("error=%v, want SDK error code %q", err, tt.wantCode)
			}
			select {
			case req := <-capture.request:
				t.Fatalf("daemon received OAuth Create request before version validation: %+v", req)
			default:
			}
		})
	}
}
