package sandboxes

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"

	localv1 "github.com/lickren/sandboxes-api/gen/go/sandboxes/local/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

type sessionRecorder struct {
	open   *localv1.ExecSessionOpen
	stdin  []byte
	resize []*localv1.ExecSessionResize
	eof    bool
}

type sessionServer struct {
	localv1.UnimplementedSandboxServiceServer
	recorder *sessionRecorder
	closeNow bool
}

func (s *sessionServer) ExecSession(stream grpc.BidiStreamingServer[localv1.ExecSessionRequest, localv1.ExecSessionResponse]) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	s.recorder.open = first.GetOpen()
	if s.closeNow {
		return nil
	}
	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		switch frame := req.GetFrame().(type) {
		case *localv1.ExecSessionRequest_Stdin:
			s.recorder.stdin = append(s.recorder.stdin, frame.Stdin...)
		case *localv1.ExecSessionRequest_Resize:
			s.recorder.resize = append(s.recorder.resize, frame.Resize)
		case *localv1.ExecSessionRequest_StdinEof:
			s.recorder.eof = frame.StdinEof
		}
		if s.recorder.eof {
			break
		}
	}
	for _, frame := range []*localv1.ExecSessionResponse{
		{Frame: &localv1.ExecSessionResponse_Stdout{Stdout: []byte("out")}},
		{Frame: &localv1.ExecSessionResponse_Stderr{Stderr: []byte("err")}},
		{Frame: &localv1.ExecSessionResponse_ExitCode{ExitCode: 7}},
	} {
		if err := stream.Send(frame); err != nil {
			return err
		}
	}
	return nil
}

func newSessionClient(t *testing.T, server *sessionServer) (Client, func()) {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	localv1.RegisterSandboxServiceServer(grpcServer, server)
	go func() {
		_ = grpcServer.Serve(lis)
	}()
	client, err := New(Config{
		Address: "bufnet",
		Dialer: func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		},
	})
	if err != nil {
		grpcServer.Stop()
		t.Fatal(err)
	}
	return client, func() {
		_ = client.Close()
		grpcServer.Stop()
	}
}

func TestExecSessionSendsOpenStdinResizeAndEOF(t *testing.T) {
	recorder := &sessionRecorder{}
	client, cleanup := newSessionClient(t, &sessionServer{recorder: recorder})
	defer cleanup()

	session, err := Sessions(client).OpenSession(context.Background(), SessionRequest{
		SandboxID: "sb-1", Argv: []string{"/bin/sh"}, Workdir: "/workspace",
		Env: []string{"A=1"}, User: "1000:1001",
		TTY: true, Size: TerminalSize{Rows: 25, Cols: 90},
	})
	if err != nil {
		t.Fatal(err)
	}
	input := make([]byte, 70000)
	if err := session.SendInput(input); err != nil {
		t.Fatal(err)
	}
	if err := session.Resize(TerminalSize{Rows: 41, Cols: 101}); err != nil {
		t.Fatal(err)
	}
	if err := session.CloseInput(); err != nil {
		t.Fatal(err)
	}
	if err := session.SendInput([]byte("late")); err == nil {
		t.Fatal("input after EOF was accepted")
	}

	frames := make([]SessionFrame, 0, 3)
	for {
		frame, err := session.Receive()
		if err != nil {
			t.Fatalf("receive: %v", err)
		}
		frames = append(frames, frame)
		if frame.ExitCode != nil {
			break
		}
	}
	if string(frames[0].Stdout) != "out" || string(frames[1].Stderr) != "err" || *frames[2].ExitCode != 7 {
		t.Fatalf("unexpected frames: %#v", frames)
	}

	if recorder.open.GetSandboxId() != "sb-1" || recorder.open.GetTty() != true ||
		recorder.open.GetRows() != 25 || recorder.open.GetCols() != 90 ||
		len(recorder.open.GetArgv()) != 1 || recorder.open.GetWorkdir() != "/workspace" ||
		len(recorder.open.GetEnv()) != 1 || recorder.open.GetEnv()[0] != "A=1" || recorder.open.GetUser() != "1000:1001" {
		t.Fatalf("unexpected open frame: %#v", recorder.open)
	}
	if len(recorder.stdin) != len(input) || !recorder.eof {
		t.Fatalf("stdin bytes=%d eof=%t", len(recorder.stdin), recorder.eof)
	}
	if len(recorder.resize) != 1 || recorder.resize[0].GetRows() != 41 || recorder.resize[0].GetCols() != 101 {
		t.Fatalf("unexpected resize: %#v", recorder.resize)
	}
}

func TestExecSessionReportsMissingExitStatus(t *testing.T) {
	recorder := &sessionRecorder{}
	client, cleanup := newSessionClient(t, &sessionServer{recorder: recorder, closeNow: true})
	defer cleanup()

	session, err := Sessions(client).OpenSession(context.Background(), SessionRequest{SandboxID: "sb-1", Argv: []string{"true"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.Receive(); err == nil {
		t.Fatal("session without exit status did not fail")
	}
}

func TestSessionsUnsupportedClient(t *testing.T) {
	for _, client := range []Client{nil, unsupportedSessionClient{}} {
		_, err := Sessions(client).OpenSession(context.Background(), SessionRequest{})
		var typed *Error
		if !errors.As(err, &typed) || typed.Code != errorCodeUnsupported {
			t.Fatalf("client %T returned %v", client, err)
		}
	}
}

type unsupportedSessionClient struct{ Client }

type recordingExecServer struct {
	localv1.UnimplementedSandboxServiceServer
	request *localv1.ExecRequest
}

func (s *recordingExecServer) Exec(req *localv1.ExecRequest, stream grpc.ServerStreamingServer[localv1.ExecResponse]) error {
	s.request = req
	return stream.Send(&localv1.ExecResponse{Frame: &localv1.ExecResponse_ExitCode{ExitCode: 0}})
}

func TestExecSendsEnvAndUser(t *testing.T) {
	server := &recordingExecServer{}
	lis := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	localv1.RegisterSandboxServiceServer(grpcServer, server)
	go func() { _ = grpcServer.Serve(lis) }()
	client, err := New(Config{Address: "bufnet", Dialer: func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }})
	if err != nil {
		grpcServer.Stop()
		t.Fatal(err)
	}
	defer grpcServer.Stop()
	defer func() { _ = client.Close() }()
	if code, err := ExecService(client).Exec(context.Background(), ExecRequest{
		SandboxID: "sb-1", Argv: []string{"env"}, Env: []string{"A=1"}, User: "0:0",
	}); err != nil || code != 0 {
		t.Fatalf("exec code=%d err=%v", code, err)
	}
	if server.request == nil || len(server.request.GetEnv()) != 1 || server.request.GetEnv()[0] != "A=1" || server.request.GetUser() != "0:0" {
		t.Fatalf("unexpected exec request: %#v", server.request)
	}
}
