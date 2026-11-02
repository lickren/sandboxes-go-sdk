package sandboxes

import (
	"context"
	"net"
	"testing"

	localv1 "github.com/QUOINER/sandboxes-api/gen/go/sandboxes/local/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

type captureCreateServer struct {
	localv1.UnimplementedSandboxServiceServer
	request chan *localv1.CreateRequest
}

func (s captureCreateServer) Create(_ context.Context, req *localv1.CreateRequest) (*localv1.CreateResponse, error) {
	s.request <- req
	return &localv1.CreateResponse{Operation: &localv1.Operation{Id: "op-1", SandboxId: "sb-1"}}, nil
}

func TestCreatePassesEnv(t *testing.T) {
	lis := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	capture := captureCreateServer{request: make(chan *localv1.CreateRequest, 1)}
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
	if _, err := client.Sandboxes().Create(context.Background(), CreateRequest{Name: "dev", Env: map[string]string{"A": "1"}, PolicyProfile: "balanced"}); err != nil {
		t.Fatal(err)
	}
	req := <-capture.request
	if req.GetEnv()["A"] != "1" || req.GetPolicyProfile() != "balanced" {
		t.Fatalf("env=%v", req.GetEnv())
	}
}
