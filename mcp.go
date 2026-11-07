package sandboxes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strings"

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

func (unsupportedMCPService) ApproveCall(context.Context, string) (json.RawMessage, error) {
	return nil, &Error{Code: errorCodeUnsupported, Message: "MCP approval is not supported by this client"}
}

func (unsupportedMCPService) Register(context.Context, MCPServerConfig) (*MCPRegistration, error) {
	return nil, &Error{Code: errorCodeUnsupported, Message: "MCP registration is not supported by this client"}
}

func (unsupportedMCPService) ApproveRegistration(context.Context, string) (*MCPServer, error) {
	return nil, &Error{Code: errorCodeUnsupported, Message: "MCP registration approval is not supported by this client"}
}

func (unsupportedMCPService) Remove(context.Context, string) (bool, error) {
	return false, &Error{Code: errorCodeUnsupported, Message: "MCP removal is not supported by this client"}
}

func (s mcpServiceClient) Call(ctx context.Context, sandboxID, serverName, toolName string, arguments json.RawMessage) (json.RawMessage, error) {
	if sandboxID == "" || serverName == "" || toolName == "" {
		return nil, errors.New("MCP sandbox, server, and tool names are required")
	}
	arguments, err := validateMCPArguments(arguments)
	if err != nil {
		return nil, err
	}
	if err := s.requireMCPVersion(ctx); err != nil {
		return nil, err
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
	if resp.GetApprovalRequired() {
		if resp.GetApprovalId() == "" {
			return nil, errors.New("daemon requested MCP approval without a challenge ID")
		}
		return nil, &MCPApprovalRequiredError{ApprovalID: resp.GetApprovalId(), Reason: resp.GetApprovalReason()}
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

func validateMCPArguments(arguments json.RawMessage) (json.RawMessage, error) {
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
	return arguments, nil
}

func (s mcpServiceClient) ApproveCall(ctx context.Context, approvalID string) (json.RawMessage, error) {
	if approvalID == "" {
		return nil, errors.New("MCP approval ID is required")
	}
	if err := s.requireMCPVersion(ctx); err != nil {
		return nil, err
	}
	ctx, cancel := s.c.context(ctx)
	defer cancel()
	resp, err := s.c.sandboxes.MCPApproveCall(ctx, &localv1.MCPApproveCallRequest{ApprovalId: approvalID})
	if err != nil {
		return nil, mapError(err)
	}
	return validateMCPResult(resp.GetResultJson())
}

func (s mcpServiceClient) Register(ctx context.Context, server MCPServerConfig) (*MCPRegistration, error) {
	if server.Name == "" {
		return nil, errors.New("MCP server name is required")
	}
	if server.URL != "" && server.Command != "" {
		return nil, errors.New("set either command or url, not both")
	}
	if server.URL == "" && (server.Command == "" || server.WorkingDirectory == "") {
		return nil, errors.New("MCP name, command, and absolute working directory are required")
	}
	if len(server.Arguments) > 64 || len(server.Headers) > 16 {
		return nil, errors.New("MCP registration exceeds argument or header limits")
	}
	total := len(server.Name) + len(server.Command) + len(server.WorkingDirectory) + len(server.URL)
	for _, arg := range server.Arguments {
		total += len(arg)
	}
	for key, value := range server.Headers {
		total += len(key) + len(value)
		if strings.ContainsAny(value, "\r\n\x00") {
			return nil, errors.New("MCP header values must not contain control characters")
		}
		if strings.EqualFold(strings.TrimSpace(key), "authorization") || strings.EqualFold(strings.TrimSpace(key), "proxy-authorization") {
			return nil, errors.New("secret MCP headers must come from the host credential broker, not registration")
		}
	}
	if total > 16<<10 {
		return nil, errors.New("MCP registration exceeds 16 KiB")
	}
	if err := s.requireMCPVersion(ctx); err != nil {
		return nil, err
	}
	ctx, cancel := s.c.context(ctx)
	defer cancel()
	resp, err := s.c.sandboxes.MCPRegisterServer(ctx, &localv1.MCPRegisterServerRequest{
		Name: server.Name, Command: server.Command, Arguments: append([]string(nil), server.Arguments...), WorkingDirectory: server.WorkingDirectory,
		Url: server.URL, Headers: maps.Clone(server.Headers),
	})
	if err != nil {
		return nil, mapError(err)
	}
	registration := &MCPRegistration{ApprovalID: resp.GetApprovalId(), ApprovalRequired: resp.GetApprovalRequired()}
	if resp.GetServer() != nil {
		converted := convertMCPServer(resp.GetServer())
		registration.Server = &converted
	}
	if registration.ApprovalRequired && registration.ApprovalID == "" {
		return nil, errors.New("daemon requested registration approval without a challenge ID")
	}
	return registration, nil
}

func (s mcpServiceClient) ApproveRegistration(ctx context.Context, approvalID string) (*MCPServer, error) {
	if approvalID == "" {
		return nil, errors.New("MCP approval ID is required")
	}
	if err := s.requireMCPVersion(ctx); err != nil {
		return nil, err
	}
	ctx, cancel := s.c.context(ctx)
	defer cancel()
	resp, err := s.c.sandboxes.MCPApproveRegistration(ctx, &localv1.MCPApproveRegistrationRequest{ApprovalId: approvalID})
	if err != nil {
		return nil, mapError(err)
	}
	if resp.GetServer() == nil {
		return nil, errors.New("daemon returned no MCP server summary")
	}
	server := convertMCPServer(resp.GetServer())
	return &server, nil
}

func (s mcpServiceClient) Remove(ctx context.Context, name string) (bool, error) {
	if name == "" {
		return false, errors.New("MCP server name is required")
	}
	if err := s.requireMCPVersion(ctx); err != nil {
		return false, err
	}
	ctx, cancel := s.c.context(ctx)
	defer cancel()
	resp, err := s.c.sandboxes.MCPRemoveServer(ctx, &localv1.MCPRemoveServerRequest{Name: name})
	if err != nil {
		return false, mapError(err)
	}
	return resp.GetRemoved(), nil
}

func (s mcpServiceClient) requireMCPVersion(ctx context.Context) error {
	version, err := Version(s.c).Get(ctx)
	if err != nil {
		return fmt.Errorf("verify daemon MCP support: %w", err)
	}
	if !apiVersionAtLeast(version.APIVersion, mcpMinimumAPIVersion) {
		return &Error{Code: errorCodeUnsupported, Message: "MCP requires daemon API v0.0.18 or newer"}
	}
	return nil
}

func validateMCPResult(raw string) (json.RawMessage, error) {
	result := json.RawMessage(raw)
	if len(result) > maxMCPCallResultBytes {
		return nil, errors.New("MCP tool result exceeds the 4 MiB limit")
	}
	if len(result) == 0 || !json.Valid(result) || !bytes.HasPrefix(bytes.TrimSpace(result), []byte("{")) {
		return nil, errors.New("daemon returned an invalid MCP tool result")
	}
	return result, nil
}

func convertMCPServer(server *localv1.MCPServerSummary) MCPServer {
	return MCPServer{Name: server.GetName(), Gateway: server.GetGateway(), Transport: server.GetTransport(),
		Loaded: server.GetLoaded(), Usable: server.GetUsable(), AuthRequired: server.GetAuthRequired(),
		AuthConfigured: server.GetAuthConfigured(), HasCustomHeaders: server.GetHasCustomHeaders(),
		CustomHeadersSupported: server.GetCustomHeadersSupported(), CustomHeaderSecretsConfigured: server.GetCustomHeaderSecretsConfigured()}
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
