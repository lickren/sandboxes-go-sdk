package sandboxes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"
)

const mcpCallMinimumAPIVersion = "0.0.18"

type mcpServiceClient struct{ c *client }

type unsupportedMCPService struct{}

func (c *client) MCPService() MCPService { return mcpServiceClient{c: c} }

func (unsupportedMCPService) Call(context.Context, string, string, string, json.RawMessage) (json.RawMessage, error) {
	return nil, &Error{Code: errorCodeUnsupported, Message: "MCP tool calls are not supported by this client"}
}

func (s mcpServiceClient) Call(ctx context.Context, sandboxID, serverName, toolName string, arguments json.RawMessage) (json.RawMessage, error) {
	if sandboxID == "" || serverName == "" || toolName == "" {
		return nil, errors.New("MCP sandbox, server, and tool names are required")
	}
	if len(arguments) == 0 {
		arguments = json.RawMessage(`{}`)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(arguments, &object); err != nil || object == nil {
		return nil, errors.New("MCP arguments must be a JSON object")
	}
	version, err := Version(s.c).Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("verify daemon MCP support: %w", err)
	}
	if !apiVersionAtLeast(version.APIVersion, mcpCallMinimumAPIVersion) {
		return nil, &Error{Code: errorCodeUnsupported, Message: "MCP tool calls require daemon API v0.0.18 or newer"}
	}
	ctx, cancel := s.c.context(ctx)
	defer cancel()
	resp, err := s.c.sandboxes.MCPCall(ctx, &localv1.MCPCallRequest{
		SandboxId: sandboxID, ServerName: serverName, ToolName: toolName,
		ArgumentsJson: string(arguments),
	})
	if err != nil {
		return nil, mapError(err)
	}
	result := json.RawMessage(resp.GetResultJson())
	if len(result) == 0 || !json.Valid(result) || !bytes.HasPrefix(bytes.TrimSpace(result), []byte("{")) {
		return nil, errors.New("daemon returned an invalid MCP tool result")
	}
	return result, nil
}
