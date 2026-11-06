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

type capturePolicyServer struct {
	localv1.UnimplementedSandboxServiceServer
	refreshCalled int
	resetCalled   int
	err           error
}

func (s *capturePolicyServer) RefreshPolicies(_ context.Context, _ *localv1.RefreshPoliciesRequest) (*localv1.RefreshPoliciesResponse, error) {
	s.refreshCalled++
	if s.err != nil {
		return nil, s.err
	}
	return &localv1.RefreshPoliciesResponse{Applied: 2, Skipped: 1}, nil
}

func (s *capturePolicyServer) ResetGlobalPolicy(_ context.Context, _ *localv1.ResetGlobalPolicyRequest) (*localv1.ResetGlobalPolicyResponse, error) {
	s.resetCalled++
	if s.err != nil {
		return nil, s.err
	}
	return &localv1.ResetGlobalPolicyResponse{
		Allow:   []*localv1.NetworkRule{{Protocol: "tcp", Cidr: "192.0.2.0/24"}},
		Profile: "deny-all",
	}, nil
}

func policyTestClient(t *testing.T, capture *capturePolicyServer) Client {
	t.Helper()
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
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
	return client
}

func TestPolicyRefreshAndResetRoundTrip(t *testing.T) {
	capture := &capturePolicyServer{}
	client := policyTestClient(t, capture)
	policies := Policies(client)

	applied, err := policies.Refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if applied != 2 || capture.refreshCalled != 1 {
		t.Fatalf("applied=%d refreshCalled=%d", applied, capture.refreshCalled)
	}

	allow, deny, profile, err := policies.ResetGlobal(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(allow) != 1 || allow[0].CIDR != "192.0.2.0/24" || len(deny) != 0 || profile != "deny-all" {
		t.Fatalf("allow=%+v deny=%+v profile=%q", allow, deny, profile)
	}
	if capture.resetCalled != 1 {
		t.Fatalf("resetCalled=%d", capture.resetCalled)
	}
}

func TestPolicyRefreshMapsErrors(t *testing.T) {
	capture := &capturePolicyServer{err: status.Error(codes.FailedPrecondition, "gateway reload rejected")}
	client := policyTestClient(t, capture)
	if _, err := Policies(client).Refresh(context.Background()); err == nil {
		t.Fatal("expected error")
	} else {
		var sdkErr *Error
		if !errors.As(err, &sdkErr) {
			t.Fatalf("error is not an SDK error: %v", err)
		}
	}
}
