package sandboxes

import (
	"context"
	"errors"
	"fmt"
	"io"

	localv1 "github.com/quoiner/sandboxes-api/gen/go/sandboxes/local/v1"
)

// ExecRequest specifies a non-interactive guest command.
type ExecRequest struct {
	SandboxID string
	Argv      []string
	Workdir   string
	// Env contains explicit KEY=VALUE overrides. Host environment variables are
	// never copied. User accepts numeric IDs or supported local guest names.
	Env    []string
	User   string
	Stdout io.Writer
	Stderr io.Writer
}

// Executor provides optional non-interactive guest execution.
type Executor interface {
	Exec(ctx context.Context, req ExecRequest) (int, error)
}

// ExecService returns the optional executor supported by the client.
func ExecService(c Client) Executor {
	if provider, ok := c.(interface{ Executor() Executor }); ok {
		if executor := provider.Executor(); executor != nil {
			return executor
		}
	}
	return unsupportedExecutor{}
}

type unsupportedExecutor struct{}

func (unsupportedExecutor) Exec(context.Context, ExecRequest) (int, error) {
	return 0, &Error{Code: errorCodeUnsupported, Message: "exec is not supported by this client"}
}

func (c *client) Executor() Executor { return execClient{c: c} }

type execClient struct{ c *client }

func (e execClient) Exec(ctx context.Context, req ExecRequest) (int, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := e.c.sandboxes.Exec(ctx, &localv1.ExecRequest{SandboxId: req.SandboxID, Argv: req.Argv, Workdir: req.Workdir, Env: req.Env, User: req.User})
	if err != nil {
		return 0, mapError(err)
	}
	for {
		frame, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return 0, fmt.Errorf("exec stream ended without exit status")
			}
			return 0, mapError(err)
		}
		switch value := frame.GetFrame().(type) {
		case *localv1.ExecResponse_Stdout:
			if err := writeExecOutput(req.Stdout, value.Stdout); err != nil {
				return 0, err
			}
		case *localv1.ExecResponse_Stderr:
			if err := writeExecOutput(req.Stderr, value.Stderr); err != nil {
				return 0, err
			}
		case *localv1.ExecResponse_ExitCode:
			return int(value.ExitCode), nil
		default:
			return 0, fmt.Errorf("invalid exec stream frame")
		}
	}
}

func writeExecOutput(w io.Writer, data []byte) error {
	if w == nil {
		return nil
	}
	n, err := w.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return nil
}
