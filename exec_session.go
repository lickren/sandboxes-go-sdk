package sandboxes

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	localv1 "github.com/quoiner/sandboxes-api/gen/go/sandboxes/local/v1"
	"google.golang.org/grpc"
)

// TerminalSize describes a terminal's dimensions in character cells.
type TerminalSize struct{ Rows, Cols uint32 }

// SessionRequest opens an interactive guest process.
type SessionRequest struct {
	SandboxID string
	Argv      []string
	Workdir   string
	// Env contains explicit KEY=VALUE overrides. Host environment variables are
	// never copied. User accepts numeric IDs or supported local guest names.
	Env  []string
	User string
	TTY  bool
	Size TerminalSize
}

// SessionFrame carries guest output or the final process exit status.
type SessionFrame struct {
	Stdout, Stderr []byte
	ExitCode       *int
}

// ExecSession allows one receiver and concurrent input/resize senders.
type ExecSession interface {
	SendInput([]byte) error
	CloseInput() error
	Resize(TerminalSize) error
	Receive() (SessionFrame, error)
}

// SessionExecutor is an optional client capability.
type SessionExecutor interface {
	OpenSession(context.Context, SessionRequest) (ExecSession, error)
}

// Sessions returns the interactive execution capability.
func Sessions(c Client) SessionExecutor {
	if p, ok := c.(interface{ SessionExecutor() SessionExecutor }); ok {
		return p.SessionExecutor()
	}
	return unsupportedSessions{}
}

type unsupportedSessions struct{}

func (unsupportedSessions) OpenSession(context.Context, SessionRequest) (ExecSession, error) {
	return nil, &Error{Code: errorCodeUnsupported, Message: "interactive exec is not supported by this client"}
}
func (c *client) SessionExecutor() SessionExecutor { return sessionClient{c: c} }

type sessionClient struct{ c *client }

func (e sessionClient) OpenSession(ctx context.Context, req SessionRequest) (ExecSession, error) {
	stream, err := e.c.sandboxes.ExecSession(ctx)
	if err != nil {
		return nil, mapError(err)
	}
	err = stream.Send(&localv1.ExecSessionRequest{Frame: &localv1.ExecSessionRequest_Open{Open: &localv1.ExecSessionOpen{SandboxId: req.SandboxID, Argv: req.Argv, Workdir: req.Workdir, Tty: req.TTY, Rows: req.Size.Rows, Cols: req.Size.Cols, Env: req.Env, User: req.User}}})
	if err != nil {
		return nil, mapError(err)
	}
	return &grpcExecSession{stream: stream}, nil
}

type grpcExecSession struct {
	stream grpc.BidiStreamingClient[localv1.ExecSessionRequest, localv1.ExecSessionResponse]
	mu     sync.Mutex
	closed bool
}

func (s *grpcExecSession) SendInput(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("stdin is closed")
	}
	for len(data) > 0 {
		n := min(len(data), 32*1024)
		if err := s.stream.Send(&localv1.ExecSessionRequest{Frame: &localv1.ExecSessionRequest_Stdin{Stdin: data[:n]}}); err != nil {
			return mapError(err)
		}
		data = data[n:]
	}
	return nil
}
func (s *grpcExecSession) CloseInput() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return mapError(s.stream.Send(&localv1.ExecSessionRequest{Frame: &localv1.ExecSessionRequest_StdinEof{StdinEof: true}}))
}
func (s *grpcExecSession) Resize(size TerminalSize) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return mapError(s.stream.Send(&localv1.ExecSessionRequest{Frame: &localv1.ExecSessionRequest_Resize{Resize: &localv1.ExecSessionResize{Rows: size.Rows, Cols: size.Cols}}}))
}
func (s *grpcExecSession) Receive() (SessionFrame, error) {
	frame, err := s.stream.Recv()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return SessionFrame{}, fmt.Errorf("session ended without exit status")
		}
		return SessionFrame{}, mapError(err)
	}
	switch v := frame.GetFrame().(type) {
	case *localv1.ExecSessionResponse_Stdout:
		return SessionFrame{Stdout: v.Stdout}, nil
	case *localv1.ExecSessionResponse_Stderr:
		return SessionFrame{Stderr: v.Stderr}, nil
	case *localv1.ExecSessionResponse_ExitCode:
		code := int(v.ExitCode)
		return SessionFrame{ExitCode: &code}, nil
	default:
		return SessionFrame{}, errors.New("invalid session frame")
	}
}
