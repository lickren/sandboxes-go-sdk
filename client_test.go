package sandboxes

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestExecStreamsOutput(t *testing.T) {
	client, cleanup := newTestClient(t)
	defer cleanup()
	var stdout, stderr bytes.Buffer
	code, err := ExecService(client).Exec(context.Background(), ExecRequest{
		SandboxID: "sb-1", Argv: []string{"echo"}, Stdout: &stdout, Stderr: &stderr,
	})
	if err != nil || code != 0 || stdout.String() != "out" || stderr.String() != "err" {
		t.Fatalf("exec code=%d err=%v stdout=%q stderr=%q", code, err, stdout.String(), stderr.String())
	}
}

func TestError(t *testing.T) {
	err := &Error{Code: "conflict", Message: "revision mismatch"}
	if got := err.Error(); got != "conflict: revision mismatch" {
		t.Fatalf("unexpected message: %s", got)
	}
}

func TestClientGetAndList(t *testing.T) {
	client, cleanup := newTestClient(t)
	defer cleanup()

	sb, err := client.Sandboxes().Get(context.Background(), "sb-1")
	if err != nil {
		t.Fatal(err)
	}
	if sb.ID != "sb-1" || sb.State != "running" || sb.CPUs != 4 || sb.MemoryMiB != 2048 || sb.StoppedAt.Unix() != 200 ||
		len(sb.Workspaces) != 2 || !sb.Workspaces[1].ReadOnly || len(sb.Ports) != 1 || sb.Ports[0].Host != 8080 ||
		len(sb.Allow) != 1 || sb.Allow[0].Port != 80 || len(sb.Deny) != 1 || sb.Deny[0].Protocol != "udp" ||
		sb.Agent != "shell" || !sb.Detached || sb.PolicyProfile != "balanced" || sb.LastUsedAt.Unix() != 300 {
		t.Fatalf("unexpected sandbox: %+v", sb)
	}

	page, err := client.Sandboxes().List(context.Background(), ListOptions{PageSize: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.NextPageToken != "" {
		t.Fatalf("unexpected page: %+v", page)
	}
}

func TestClientMapsNotFound(t *testing.T) {
	client, cleanup := newTestClient(t)
	defer cleanup()

	_, err := client.Sandboxes().Get(context.Background(), "missing")
	if err == nil {
		t.Fatal("expected error")
	}
	var typed *Error
	if !errors.As(err, &typed) {
		t.Fatalf("expected typed error, got %T", err)
	}
	if typed.Code != "not_found" {
		t.Fatalf("code = %s", typed.Code)
	}
}

func TestClientWatch(t *testing.T) {
	client, cleanup := newTestClient(t)
	defer cleanup()

	stream, err := client.Sandboxes().Watch(context.Background(), WatchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stream.Close() }()
	event, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if event.Type != "sandbox" || event.Sandbox == nil || event.Sandbox.ID != "sb-1" {
		t.Fatalf("unexpected event: %+v", event)
	}
}

func TestWatchCloseCancelsServerAndPendingRecv(t *testing.T) {
	lis := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	stopped := make(chan struct{})
	localv1.RegisterSandboxServiceServer(server, blockingWatchServer{stopped: stopped})
	go func() { _ = server.Serve(lis) }()
	t.Cleanup(server.Stop)
	client, err := New(Config{Address: "bufnet", Dialer: func(ctx context.Context, _ string) (net.Conn, error) {
		return lis.DialContext(ctx)
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	stream, err := client.Sandboxes().Watch(context.Background(), WatchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("receive initial event: %v", err)
	}
	recvDone := make(chan error, 1)
	go func() { _, err := stream.Recv(); recvDone <- err }()
	if err := stream.Close(); err != nil {
		t.Fatalf("close watch: %v", err)
	}
	select {
	case err := <-recvDone:
		if err == nil {
			t.Fatal("pending receive succeeded after close")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("close did not unblock receive")
	}
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("close did not cancel server watch")
	}
}

type blockingWatchServer struct {
	localv1.UnimplementedSandboxServiceServer
	stopped chan struct{}
}

func (s blockingWatchServer) Watch(_ *localv1.WatchRequest, stream grpc.ServerStreamingServer[localv1.WatchResponse]) error {
	defer close(s.stopped)
	if err := stream.Send(&localv1.WatchResponse{Type: "sandbox"}); err != nil {
		return err
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}

func TestOperationsWait(t *testing.T) {
	client, cleanup := newTestClient(t)
	defer cleanup()

	op, err := client.Operations().Wait(context.Background(), "op-1")
	if err != nil {
		t.Fatal(err)
	}
	if op.State != "done" {
		t.Fatalf("state = %s", op.State)
	}
}

func TestStopGraceEncoding(t *testing.T) {
	client, cleanup := newTestClient(t)
	defer cleanup()
	for _, tc := range []struct {
		grace time.Duration
		want  string
	}{
		{0, "0"},
		{500 * time.Millisecond, "1"},
		{1500 * time.Millisecond, "2"},
		{time.Hour, "3600"},
	} {
		op, err := client.Sandboxes().Stop(context.Background(), "sb-1", StopOptions{Grace: tc.grace})
		if err != nil || op == nil || op.ID != tc.want {
			t.Fatalf("grace %s: operation=%+v err=%v", tc.grace, op, err)
		}
	}
	for _, grace := range []time.Duration{-time.Millisecond, time.Hour + time.Nanosecond} {
		_, err := client.Sandboxes().Stop(context.Background(), "sb-1", StopOptions{Grace: grace})
		var typed *Error
		if !errors.As(err, &typed) || typed.Code != errorCodeInvalidArgument {
			t.Fatalf("invalid grace %s: %v", grace, err)
		}
	}
}

func TestRegistryCredentialLogin(t *testing.T) {
	client, cleanup := newTestClient(t)
	defer cleanup()
	resp, err := client.RegistryCredentials().Login(context.Background(), RegistryLoginRequest{
		Registry: "ghcr.io", Username: "alice", Password: []byte("synthetic-token"), Scope: RegistryScopeSandbox, SandboxName: "sample",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Registry != "ghcr.io" || resp.Scope != RegistryScopeSandbox || resp.SandboxName != "sample" {
		t.Fatalf("unexpected response: %#v", resp)
	}
}

func TestRegistryCredentialLogout(t *testing.T) {
	client, cleanup := newTestClient(t)
	defer cleanup()
	resp, err := client.RegistryCredentials().Logout(context.Background(), RegistryLogoutRequest{
		Registry: "ghcr.io", Scope: RegistryScopeAllSandboxes,
	})
	if err != nil || !resp.Removed {
		t.Fatalf("logout returned %#v, %v", resp, err)
	}
}

func TestAccountLoginAndLogout(t *testing.T) {
	client, cleanup := newTestClient(t)
	defer cleanup()
	if err := Accounts(client).Login(context.Background(), "docker"); err != nil {
		t.Fatal(err)
	}
	removed, err := Accounts(client).Logout(context.Background(), "docker")
	if err != nil || !removed {
		t.Fatalf("account logout: removed=%t err=%v", removed, err)
	}
}

func TestAccountStatusReturnsCredentialPresenceOnly(t *testing.T) {
	client, cleanup := newTestClient(t)
	defer cleanup()
	present, err := AccountStatus(client).Status(context.Background(), "docker")
	if err != nil || !present {
		t.Fatalf("account status present=%t err=%v", present, err)
	}
}

func TestInteractiveAccountLoginDeviceHandoff(t *testing.T) {
	client, cleanup := newTestClient(t)
	defer cleanup()
	var info DeviceLoginInfo
	err := InteractiveAccounts(client).LoginInteractive(context.Background(), "docker", func(_ context.Context, got DeviceLoginInfo) error {
		info = got
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if info.UserCode != "ABCD-EFGH" || info.VerificationURI != "https://login.example/device" {
		t.Fatalf("device handoff details = %+v", info)
	}
}

func TestInteractiveAccountLoginCancellationStopsBeforeCompletion(t *testing.T) {
	client, cleanup := newTestClient(t)
	defer cleanup()
	canceled := errors.New("handoff canceled by user")
	err := InteractiveAccounts(client).LoginInteractive(context.Background(), "docker", func(_ context.Context, _ DeviceLoginInfo) error {
		return canceled
	})
	if !errors.Is(err, canceled) {
		t.Fatalf("expected local handoff cancellation, got %v", err)
	}
}

type nilAccountProvider struct{ Client }

func (nilAccountProvider) AccountService() AccountService { return nil }

func TestAccountsHandlesMissingProvider(t *testing.T) {
	for _, client := range []Client{nil, nilAccountProvider{}} {
		err := Accounts(client).Login(context.Background(), "docker")
		var typed *Error
		if !errors.As(err, &typed) || typed.Code != errorCodeUnsupported {
			t.Fatalf("missing account provider returned %v", err)
		}
		_, err = Accounts(client).Logout(context.Background(), "docker")
		if !errors.As(err, &typed) || typed.Code != errorCodeUnsupported {
			t.Fatalf("missing account provider logout returned %v", err)
		}
		_, err = AccountStatus(client).Status(context.Background(), "docker")
		if !errors.As(err, &typed) || typed.Code != errorCodeUnsupported {
			t.Fatalf("missing account status provider returned %v", err)
		}
	}
}

func TestVersionService(t *testing.T) {
	client, cleanup := newTestClient(t)
	defer cleanup()
	info, err := Version(client).Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.Version != "0.0.9" || info.APIVersion != "0.0.5" {
		t.Fatalf("version info = %+v", info)
	}
}

func TestVersionHandlesMissingProvider(t *testing.T) {
	for _, client := range []Client{nil, nilAccountProvider{}} {
		_, err := Version(client).Get(context.Background())
		var typed *Error
		if !errors.As(err, &typed) || typed.Code != errorCodeUnsupported {
			t.Fatalf("missing version provider returned %v", err)
		}
	}
}

func newTestClient(t *testing.T) (Client, func()) {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	localv1.RegisterSandboxServiceServer(server, fakeSandboxServer{})
	localv1.RegisterOperationServiceServer(server, fakeOperationServer{})
	localv1.RegisterRegistryCredentialServiceServer(server, fakeRegistryCredentialServer{})
	localv1.RegisterAccountServiceServer(server, fakeAccountServer{})
	go func() {
		_ = server.Serve(lis)
	}()
	client, err := New(Config{
		Address: "bufnet",
		Dialer: func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		},
	})
	if err != nil {
		server.Stop()
		t.Fatal(err)
	}
	return client, func() {
		_ = client.Close()
		server.Stop()
	}
}

type fakeAccountServer struct {
	localv1.UnimplementedAccountServiceServer
}

func (fakeAccountServer) Login(_ context.Context, req *localv1.AccountServiceLoginRequest) (*localv1.AccountServiceLoginResponse, error) {
	if req.GetProvider() != "docker" {
		return nil, status.Error(codes.InvalidArgument, "unexpected account provider")
	}
	return &localv1.AccountServiceLoginResponse{Provider: "docker", Authenticated: true}, nil
}

func (fakeAccountServer) LoginDevice(stream grpc.BidiStreamingServer[localv1.AccountServiceLoginDeviceRequest, localv1.AccountServiceLoginDeviceResponse]) error {
	initial, err := stream.Recv()
	if err != nil || initial.GetProvider() != "docker" {
		return status.Error(codes.InvalidArgument, "unexpected device login provider")
	}
	if err := stream.Send(&localv1.AccountServiceLoginDeviceResponse{UserCode: "ABCD-EFGH", VerificationUri: "https://login.example/device"}); err != nil {
		return err
	}
	ack, err := stream.Recv()
	if err != nil {
		return err
	}
	if !ack.GetContinueAfterHandoff() {
		return status.Error(codes.Canceled, "device login canceled")
	}
	return stream.Send(&localv1.AccountServiceLoginDeviceResponse{Authenticated: true})
}

func (fakeAccountServer) Logout(_ context.Context, req *localv1.AccountServiceLogoutRequest) (*localv1.AccountServiceLogoutResponse, error) {
	return &localv1.AccountServiceLogoutResponse{Removed: req.GetProvider() == "docker"}, nil
}

func (fakeAccountServer) Status(_ context.Context, req *localv1.AccountServiceStatusRequest) (*localv1.AccountServiceStatusResponse, error) {
	if req.GetProvider() != "docker" {
		return nil, status.Error(codes.InvalidArgument, "unexpected account status provider")
	}
	return &localv1.AccountServiceStatusResponse{Provider: "docker", CredentialPresent: true}, nil
}

type fakeRegistryCredentialServer struct {
	localv1.UnimplementedRegistryCredentialServiceServer
}

func (fakeRegistryCredentialServer) Logout(_ context.Context, req *localv1.RegistryCredentialServiceLogoutRequest) (*localv1.RegistryCredentialServiceLogoutResponse, error) {
	return &localv1.RegistryCredentialServiceLogoutResponse{Removed: req.GetRegistry() == "ghcr.io"}, nil
}

func (fakeRegistryCredentialServer) Login(_ context.Context, req *localv1.RegistryCredentialServiceLoginRequest) (*localv1.RegistryCredentialServiceLoginResponse, error) {
	if string(req.GetPassword()) != "synthetic-token" {
		return nil, status.Error(codes.InvalidArgument, "unexpected synthetic fixture")
	}
	return &localv1.RegistryCredentialServiceLoginResponse{
		Registry: req.GetRegistry(), Username: req.GetUsername(), Scope: req.GetScope(), SandboxName: req.GetSandboxName(),
	}, nil
}

type fakeSandboxServer struct {
	localv1.UnimplementedSandboxServiceServer
}

func (fakeSandboxServer) GetPolicyProfile(context.Context, *localv1.GetPolicyProfileRequest) (*localv1.GetPolicyProfileResponse, error) {
	return &localv1.GetPolicyProfileResponse{Profile: "balanced"}, nil
}

func (fakeSandboxServer) SetPolicyProfile(_ context.Context, req *localv1.SetPolicyProfileRequest) (*localv1.SetPolicyProfileResponse, error) {
	return &localv1.SetPolicyProfileResponse{Profile: req.GetProfile()}, nil
}

func (fakeSandboxServer) Exec(_ *localv1.ExecRequest, stream grpc.ServerStreamingServer[localv1.ExecResponse]) error {
	for _, frame := range []*localv1.ExecResponse{
		{Frame: &localv1.ExecResponse_Stdout{Stdout: []byte("out")}},
		{Frame: &localv1.ExecResponse_Stderr{Stderr: []byte("err")}},
		{Frame: &localv1.ExecResponse_ExitCode{ExitCode: 0}},
	} {
		if err := stream.Send(frame); err != nil {
			return err
		}
	}
	return nil
}

func (fakeSandboxServer) Stop(_ context.Context, req *localv1.StopRequest) (*localv1.StopResponse, error) {
	return &localv1.StopResponse{Operation: &localv1.Operation{Id: strconv.FormatInt(req.GetGraceSeconds(), 10)}}, nil
}

func (fakeSandboxServer) GetVersion(context.Context, *localv1.GetVersionRequest) (*localv1.GetVersionResponse, error) {
	return &localv1.GetVersionResponse{Version: "0.0.9", ApiVersion: "0.0.5"}, nil
}

func (fakeSandboxServer) Get(_ context.Context, req *localv1.GetRequest) (*localv1.GetResponse, error) {
	if req.GetId() == "missing" {
		return nil, status.Error(codes.NotFound, "sandbox not found")
	}
	return &localv1.GetResponse{Sandbox: &localv1.Sandbox{
		Id:            "sb-1",
		Name:          "dev",
		State:         localv1.SandboxState_SANDBOX_STATE_RUNNING,
		Generation:    2,
		CreatedAtUnix: 100,
		Cpus:          4,
		MemoryMib:     2048,
		StoppedAtUnix: 200,
		Workspaces: []*localv1.Workspace{
			{Path: "/work"}, {Path: "/docs", ReadOnly: true},
		},
		Ports: []*localv1.Port{{Host: 8080, Guest: 3000, Protocol: "tcp"}},
		Allow: []*localv1.NetworkRule{{Protocol: "tcp", Cidr: "0.0.0.0/0", Port: 80}},
		Deny:  []*localv1.NetworkRule{{Protocol: "udp", Cidr: "10.0.0.0/8", Port: 53}},
		Agent: "shell", Detached: true, PolicyProfile: "balanced", LastUsedAtUnix: 300,
	}}, nil
}

func (fakeSandboxServer) List(context.Context, *localv1.ListRequest) (*localv1.ListResponse, error) {
	return &localv1.ListResponse{Items: []*localv1.Sandbox{{Id: "sb-1"}}}, nil
}

func (fakeSandboxServer) Watch(_ *localv1.WatchRequest, stream grpc.ServerStreamingServer[localv1.WatchResponse]) error {
	return stream.Send(&localv1.WatchResponse{
		Type:     "sandbox",
		Sandbox:  &localv1.Sandbox{Id: "sb-1", State: localv1.SandboxState_SANDBOX_STATE_RUNNING},
		Revision: 2,
	})
}

type fakeOperationServer struct {
	localv1.UnimplementedOperationServiceServer
}

func (fakeOperationServer) Get(context.Context, *localv1.OperationServiceGetRequest) (*localv1.OperationServiceGetResponse, error) {
	return &localv1.OperationServiceGetResponse{Operation: &localv1.Operation{
		Id:        "op-1",
		SandboxId: "sb-1",
		Kind:      localv1.OperationKind_OPERATION_KIND_CREATE,
		State:     localv1.OperationState_OPERATION_STATE_DONE,
	}}, nil
}

func TestClientPolicyProfile(t *testing.T) {
	client, cleanup := newTestClient(t)
	defer cleanup()
	profile, err := Policies(client).GetPolicyProfile(context.Background())
	if err != nil || profile != "balanced" {
		t.Fatalf("profile=%q err=%v", profile, err)
	}
	profile, err = Policies(client).SetPolicyProfile(context.Background(), "allow-all")
	if err != nil || profile != "allow-all" {
		t.Fatalf("set profile=%q err=%v", profile, err)
	}
}
