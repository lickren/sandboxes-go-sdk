package sandboxes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"
)

const (
	mcpMinimumAPIVersion     = "0.0.18"
	maxMCPCallArgumentsBytes = 1 << 20
	maxMCPCallResultBytes    = 4 << 20
)

type mcpServiceClient struct{ c *client }

type unsupportedMCPService struct{}

func (c *client) MCPService() MCPService { return mcpServiceClient{c: c} }

func (unsupportedMCPService) List(context.Context, string) ([]MCPServer, error) {
	return nil, &Error{Code: errorCodeUnsupported, Message: "MCP server inventory is not supported by this client"}
}

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
	if len(arguments) > maxMCPCallArgumentsBytes {
		return nil, errors.New("MCP arguments exceed the 1 MiB limit")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(arguments, &object); err != nil || object == nil {
		return nil, errors.New("MCP arguments must be a JSON object")
	}
	version, err := Version(s.c).Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("verify daemon MCP support: %w", err)
	}
	if !apiVersionAtLeast(version.APIVersion, mcpMinimumAPIVersion) {
		return nil, &Error{Code: errorCodeUnsupported, Message: "MCP requires daemon API v0.0.18 or newer"}
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
	if len(result) > maxMCPCallResultBytes {
		return nil, errors.New("MCP tool result exceeds the 4 MiB limit")
	}
	if len(result) == 0 || !json.Valid(result) || !bytes.HasPrefix(bytes.TrimSpace(result), []byte("{")) {
		return nil, errors.New("daemon returned an invalid MCP tool result")
	}
	return result, nil
}

func (s mcpServiceClient) List(ctx context.Context, sandboxID string) ([]MCPServer, error) {
	version, err := Version(s.c).Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("verify daemon MCP support: %w", err)
	}
	if !apiVersionAtLeast(version.APIVersion, mcpMinimumAPIVersion) {
		return nil, &Error{Code: errorCodeUnsupported, Message: "MCP server inventory requires daemon API v0.0.18 or newer"}
	}
	ctx, cancel := s.c.context(ctx)
	defer cancel()
	resp, err := s.c.sandboxes.ListMCPServers(ctx, &localv1.ListMCPServersRequest{SandboxId: sandboxID})
	if err != nil {
		return nil, mapError(err)
	}
	servers := make([]MCPServer, 0, len(resp.GetServers()))
	for _, server := range resp.GetServers() {
		if server == nil || server.GetName() == "" {
			return nil, errors.New("daemon returned an invalid MCP server summary")
		}
		servers = append(servers, MCPServer{
			Name: server.GetName(), Gateway: server.GetGateway(), Transport: server.GetTransport(),
			Loaded: server.GetLoaded(), Usable: server.GetUsable(), AuthRequired: server.GetAuthRequired(),
			AuthConfigured: server.GetAuthConfigured(), HasCustomHeaders: server.GetHasCustomHeaders(),
			CustomHeadersSupported:        server.GetCustomHeadersSupported(),
			CustomHeaderSecretsConfigured: server.GetCustomHeaderSecretsConfigured(),
		})
	}
	return servers, nil
}
