package sandboxes

import (
	"context"
	"fmt"
	"time"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type client struct {
	conn        *grpc.ClientConn
	sandboxes   localv1.SandboxServiceClient
	operations  localv1.OperationServiceClient
	registry    localv1.RegistryCredentialServiceClient
	accounts    localv1.AccountServiceClient
	secrets     localv1.SecretServiceClient
	callTimeout time.Duration
}

// New creates a lazy local daemon client.
func New(cfg Config) (Client, error) {
	if cfg.Address == "" {
		return nil, fmt.Errorf("sandbox daemon address is required")
	}
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	target, dialer, err := localGRPCEndpoint(cfg.Address, cfg.Dialer)
	if err != nil {
		return nil, fmt.Errorf("resolve local daemon endpoint: %w", err)
	}
	if dialer != nil {
		opts = append(opts, grpc.WithContextDialer(dialer))
	}
	conn, err := grpc.NewClient(target, opts...)
	if err != nil {
		return nil, fmt.Errorf("create grpc client: %w", err)
	}
	return &client{
		conn:        conn,
		sandboxes:   localv1.NewSandboxServiceClient(conn),
		operations:  localv1.NewOperationServiceClient(conn),
		registry:    localv1.NewRegistryCredentialServiceClient(conn),
		accounts:    localv1.NewAccountServiceClient(conn),
		secrets:     localv1.NewSecretServiceClient(conn),
		callTimeout: cfg.CallTimeout,
	}, nil
}

func (c *client) Sandboxes() SandboxService { return sandboxClient{c: c} }

func (c *client) Operations() OperationService { return operationClient{c: c} }

func (c *client) RegistryCredentials() RegistryCredentialService {
	return registryCredentialClient{c: c}
}

func (c *client) AccountService() AccountService { return accountServiceClient{c: c} }

func (c *client) InteractiveAccountService() InteractiveAccountService {
	return accountServiceClient{c: c}
}

func (c *client) AccountStatusService() AccountStatusService { return accountServiceClient{c: c} }

func (c *client) VersionService() VersionService { return versionClient{c: c} }

func (c *client) DockerPATAccountService() DockerPATAccountService { return accountServiceClient{c: c} }

func (c *client) PolicyService() PolicyService { return c }

func (c *client) UpdatePolicy(ctx context.Context, id string, allow, deny []NetworkRule) (*Sandbox, error) {
	ctx, cancel := c.context(ctx)
	defer cancel()
	resp, err := c.sandboxes.UpdatePolicy(ctx, &localv1.UpdatePolicyRequest{
		Id: id, Allow: toProtoRules(allow), Deny: toProtoRules(deny),
	})
	if err != nil {
		return nil, mapError(err)
	}
	return fromProtoSandbox(resp.GetSandbox())
}

func (c *client) MutatePolicy(ctx context.Context, id, action string, rule NetworkRule) (*Sandbox, error) {
	ctx, cancel := c.context(ctx)
	defer cancel()
	resp, err := c.sandboxes.MutatePolicy(ctx, &localv1.MutatePolicyRequest{
		Id: id, Action: action, Rule: toProtoRules([]NetworkRule{rule})[0],
	})
	if err != nil {
		return nil, mapError(err)
	}
	return fromProtoSandbox(resp.GetSandbox())
}

func (c *client) GetPolicyProfile(ctx context.Context) (string, error) {
	ctx, cancel := c.context(ctx)
	defer cancel()
	resp, err := c.sandboxes.GetPolicyProfile(ctx, &localv1.GetPolicyProfileRequest{})
	if err != nil {
		return "", mapError(err)
	}
	return resp.GetProfile(), nil
}

func (c *client) GetGlobalPolicy(ctx context.Context) ([]NetworkRule, []NetworkRule, error) {
	ctx, cancel := c.context(ctx)
	defer cancel()
	resp, err := c.sandboxes.GetGlobalPolicy(ctx, &localv1.GetGlobalPolicyRequest{})
	if err != nil {
		return nil, nil, mapError(err)
	}
	return fromProtoRules(resp.GetAllow()), fromProtoRules(resp.GetDeny()), nil
}

func (c *client) MutateGlobalPolicy(ctx context.Context, action string, rule NetworkRule) ([]NetworkRule, []NetworkRule, error) {
	ctx, cancel := c.context(ctx)
	defer cancel()
	resp, err := c.sandboxes.MutateGlobalPolicy(ctx, &localv1.MutateGlobalPolicyRequest{
		Action: action, Rule: toProtoRules([]NetworkRule{rule})[0],
	})
	if err != nil {
		return nil, nil, mapError(err)
	}
	return fromProtoRules(resp.GetAllow()), fromProtoRules(resp.GetDeny()), nil
}

func (c *client) Check(ctx context.Context, id, protocol, address, domain string, port uint16) (PolicyDecision, error) {
	ctx, cancel := c.context(ctx)
	defer cancel()
	resp, err := c.sandboxes.CheckPolicy(ctx, &localv1.CheckPolicyRequest{
		SandboxId: id, Protocol: protocol, Address: address, Domain: domain, Port: uint32(port),
	})
	if err != nil {
		return PolicyDecision{}, mapError(err)
	}
	return PolicyDecision{Allowed: resp.GetAllowed(), RuleID: resp.GetRuleId(), Reason: resp.GetReason()}, nil
}

func (c *client) SetPolicyProfile(ctx context.Context, profile string) (string, error) {
	ctx, cancel := c.context(ctx)
	defer cancel()
	resp, err := c.sandboxes.SetPolicyProfile(ctx, &localv1.SetPolicyProfileRequest{Profile: profile})
	if err != nil {
		return "", mapError(err)
	}
	return resp.GetProfile(), nil
}

func (c *client) PortService() PortService { return c }

func (c *client) UpdatePorts(ctx context.Context, id string, ports []Port) (*Sandbox, error) {
	ctx, cancel := c.context(ctx)
	defer cancel()
	resp, err := c.sandboxes.UpdatePorts(ctx, &localv1.UpdatePortsRequest{Id: id, Ports: toProtoPorts(ports)})
	if err != nil {
		return nil, mapError(err)
	}
	return fromProtoSandbox(resp.GetSandbox())
}

func (c *client) ListRegistryCredentials(ctx context.Context) ([]RegistryCredentialSummary, error) {
	ctx, cancel := c.context(ctx)
	defer cancel()
	resp, err := c.registry.List(ctx, &localv1.RegistryCredentialServiceListRequest{})
	if err != nil {
		return nil, mapError(err)
	}
	out := make([]RegistryCredentialSummary, 0, len(resp.GetCredentials()))
	for _, item := range resp.GetCredentials() {
		out = append(out, RegistryCredentialSummary{
			Registry: item.GetRegistry(), Username: item.GetUsername(),
			Scope: item.GetScope(), SandboxName: item.GetSandboxName(),
		})
	}
	return out, nil
}

func (c *client) Close() error { return c.conn.Close() }

func (c *client) context(ctx context.Context) (context.Context, context.CancelFunc) {
	if c.callTimeout <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, c.callTimeout)
}

type sandboxClient struct{ c *client }

func (s sandboxClient) Create(ctx context.Context, req CreateRequest) (*Operation, error) {
	if len(req.OAuthCredentials) > 0 {
		version, err := Version(s.c).Get(ctx)
		if err != nil {
			return nil, fmt.Errorf("verify daemon OAuth metadata support: %w", err)
		}
		if !apiVersionAtLeast(version.APIVersion, oauthCredentialsMinimumAPIVersion) {
			return nil, &Error{Code: errorCodeUnsupported, Message: "daemon API does not support OAuth credential metadata"}
		}
	}
	ctx, cancel := s.c.context(ctx)
	defer cancel()
	resp, err := s.c.sandboxes.Create(ctx, &localv1.CreateRequest{
		Name:             req.Name,
		Image:            req.Image,
		Workspace:        req.Workspace,
		IdempotencyKey:   req.IdempotencyKey,
		Cpus:             req.CPUs,
		MemoryMib:        req.MemoryMiB,
		Workspaces:       toProtoWorkspaces(req.Workspaces),
		Ports:            toProtoPorts(req.Ports),
		Allow:            toProtoRules(req.Allow),
		Deny:             toProtoRules(req.Deny),
		Agent:            req.Agent,
		Detached:         req.Detached,
		PolicyProfile:    req.PolicyProfile,
		Privileged:       req.Privileged,
		Env:              req.Env,
		OauthCredentials: toProtoOAuthCredentials(req.OAuthCredentials),
	})
	if err != nil {
		return nil, mapError(err)
	}
	return fromProtoOperation(resp.GetOperation()), nil
}

func toProtoOAuthCredentials(credentials []OAuthCredential) []*localv1.OAuthCredential {
	if len(credentials) == 0 {
		return nil
	}
	out := make([]*localv1.OAuthCredential, 0, len(credentials))
	for i := range credentials {
		credential := &credentials[i]
		out = append(out, &localv1.OAuthCredential{
			Service:        credential.Service,
			TokenEndpoint:  &localv1.OAuthTokenEndpoint{Host: credential.TokenEndpoint.Host, Path: credential.TokenEndpoint.Path},
			ResourceHosts:  append([]string(nil), credential.ResourceHosts...),
			Sentinels:      &localv1.OAuthSentinels{AccessToken: credential.Sentinels.AccessToken, RefreshToken: credential.Sentinels.RefreshToken},
			CredentialFile: &localv1.OAuthCredentialFile{Path: credential.CredentialFile.Path, StructureJson: credential.CredentialFile.StructureJSON, Template: credential.CredentialFile.Template},
			ResponseFields: &localv1.OAuthResponseFields{AccessToken: credential.ResponseFields.AccessToken, RefreshToken: credential.ResponseFields.RefreshToken, ExpiresIn: credential.ResponseFields.ExpiresIn, Scope: credential.ResponseFields.Scope, IdToken: credential.ResponseFields.IDToken},
			Passthrough:    credential.Passthrough, SkipIfEnv: append([]string(nil), credential.SkipIfEnv...),
		})
	}
	return out
}

func (s sandboxClient) GetPolicyProfile(ctx context.Context) (string, error) {
	ctx, cancel := s.c.context(ctx)
	defer cancel()
	resp, err := s.c.sandboxes.GetPolicyProfile(ctx, &localv1.GetPolicyProfileRequest{})
	if err != nil {
		return "", mapError(err)
	}
	return resp.GetProfile(), nil
}

func (s sandboxClient) SetPolicyProfile(ctx context.Context, profile string) (string, error) {
	ctx, cancel := s.c.context(ctx)
	defer cancel()
	resp, err := s.c.sandboxes.SetPolicyProfile(ctx, &localv1.SetPolicyProfileRequest{Profile: profile})
	if err != nil {
		return "", mapError(err)
	}
	return resp.GetProfile(), nil
}

func (s sandboxClient) Get(ctx context.Context, id string) (*Sandbox, error) {
	ctx, cancel := s.c.context(ctx)
	defer cancel()
	resp, err := s.c.sandboxes.Get(ctx, &localv1.GetRequest{Id: id})
	if err != nil {
		return nil, mapError(err)
	}
	return fromProtoSandbox(resp.GetSandbox())
}

func (s sandboxClient) List(ctx context.Context, opts ListOptions) (*Page[Sandbox], error) {
	if opts.PageSize < 0 || opts.PageSize > 1<<31-1 {
		return nil, &Error{Code: errorCodeInvalidArgument, Message: "page size out of range"}
	}
	ctx, cancel := s.c.context(ctx)
	defer cancel()
	resp, err := s.c.sandboxes.List(ctx, &localv1.ListRequest{
		PageSize:  int32(opts.PageSize),
		PageToken: opts.PageToken,
	})
	if err != nil {
		return nil, mapError(err)
	}
	items := make([]Sandbox, 0, len(resp.GetItems()))
	for _, item := range resp.GetItems() {
		sb, err := fromProtoSandbox(item)
		if err != nil {
			return nil, err
		}
		if sb != nil {
			items = append(items, *sb)
		}
	}
	return &Page[Sandbox]{Items: items, NextPageToken: resp.GetNextPageToken()}, nil
}

func (s sandboxClient) Start(ctx context.Context, id string) (*Operation, error) {
	ctx, cancel := s.c.context(ctx)
	defer cancel()
	resp, err := s.c.sandboxes.Start(ctx, &localv1.StartRequest{Id: id})
	if err != nil {
		return nil, mapError(err)
	}
	return fromProtoOperation(resp.GetOperation()), nil
}

func (s sandboxClient) Stop(ctx context.Context, id string, opts StopOptions) (*Operation, error) {
	if opts.Grace < 0 || opts.Grace > time.Hour {
		return nil, &Error{Code: errorCodeInvalidArgument, Message: "stop grace must be between zero and one hour"}
	}
	seconds := int64(opts.Grace / time.Second)
	if opts.Grace%time.Second != 0 {
		seconds++
	}
	ctx, cancel := s.c.context(ctx)
	defer cancel()
	resp, err := s.c.sandboxes.Stop(ctx, &localv1.StopRequest{
		Id:           id,
		GraceSeconds: seconds,
	})
	if err != nil {
		return nil, mapError(err)
	}
	return fromProtoOperation(resp.GetOperation()), nil
}

func (s sandboxClient) Delete(ctx context.Context, id string, opts DeleteOptions) (*Operation, error) {
	ctx, cancel := s.c.context(ctx)
	defer cancel()
	resp, err := s.c.sandboxes.Delete(ctx, &localv1.DeleteRequest{Id: id, Force: opts.Force})
	if err != nil {
		return nil, mapError(err)
	}
	return fromProtoOperation(resp.GetOperation()), nil
}

func (s sandboxClient) Watch(ctx context.Context, opts WatchOptions) (EventStream, error) {
	streamCtx, cancel := context.WithCancel(ctx)
	stream, err := s.c.sandboxes.Watch(streamCtx, &localv1.WatchRequest{
		SandboxId:     opts.SandboxID,
		AfterRevision: opts.AfterRevision,
	})
	if err != nil {
		cancel()
		return nil, mapError(err)
	}
	return &eventStream{stream: stream, cancel: cancel}, nil
}

type eventStream struct {
	stream grpc.ServerStreamingClient[localv1.WatchResponse]
	cancel context.CancelFunc
}

func (e *eventStream) Recv() (*Event, error) {
	resp, err := e.stream.Recv()
	if err != nil {
		e.cancel()
		return nil, mapError(err)
	}
	event, err := fromProtoEvent(resp)
	if err != nil {
		e.cancel()
	}
	return event, err
}

func (e *eventStream) Close() error {
	e.cancel()
	return e.stream.CloseSend()
}

type operationClient struct{ c *client }

type versionClient struct{ c *client }

func (v versionClient) Get(ctx context.Context) (VersionInfo, error) {
	ctx, cancel := v.c.context(ctx)
	defer cancel()
	resp, err := v.c.sandboxes.GetVersion(ctx, &localv1.GetVersionRequest{})
	if err != nil {
		return VersionInfo{}, mapError(err)
	}
	return VersionInfo{Version: resp.GetVersion(), APIVersion: resp.GetApiVersion()}, nil
}

type registryCredentialClient struct{ c *client }

type accountServiceClient struct{ c *client }

type accountDeviceLoginStream = grpc.BidiStreamingClient[localv1.AccountServiceLoginDeviceRequest, localv1.AccountServiceLoginDeviceResponse]

func (a accountServiceClient) LoginInteractive(ctx context.Context, provider string, handoff func(context.Context, DeviceLoginInfo) error) error {
	if provider == "" || handoff == nil {
		return &Error{Code: errorCodeInvalidArgument, Message: "provider and device handoff are required"}
	}
	ctx, cancel := a.c.context(ctx)
	defer cancel()
	stream, err := a.c.accounts.LoginDevice(ctx)
	if err != nil {
		return mapError(err)
	}
	info, err := beginInteractiveDeviceLogin(stream, provider)
	if err != nil {
		return err
	}
	if err := handoff(ctx, info); err != nil {
		cancelInteractiveDeviceLogin(stream)
		return err
	}
	if err := confirmInteractiveDeviceLogin(stream); err != nil {
		return err
	}
	return finishInteractiveDeviceLogin(stream)
}

func beginInteractiveDeviceLogin(stream accountDeviceLoginStream, provider string) (DeviceLoginInfo, error) {
	if err := stream.Send(&localv1.AccountServiceLoginDeviceRequest{Provider: provider}); err != nil {
		return DeviceLoginInfo{}, mapError(err)
	}
	initial, err := stream.Recv()
	if err != nil {
		return DeviceLoginInfo{}, mapError(err)
	}
	info := DeviceLoginInfo{UserCode: initial.GetUserCode(), VerificationURI: initial.GetVerificationUri()}
	if info.UserCode == "" || info.VerificationURI == "" || initial.GetAuthenticated() {
		return DeviceLoginInfo{}, &Error{Code: "failed_precondition", Message: "daemon returned invalid device login details"}
	}
	return info, nil
}

func cancelInteractiveDeviceLogin(stream accountDeviceLoginStream) {
	_ = stream.Send(&localv1.AccountServiceLoginDeviceRequest{ContinueAfterHandoff: false})
	_ = stream.CloseSend()
}

func confirmInteractiveDeviceLogin(stream accountDeviceLoginStream) error {
	if err := stream.Send(&localv1.AccountServiceLoginDeviceRequest{ContinueAfterHandoff: true}); err != nil {
		return mapError(err)
	}
	if err := stream.CloseSend(); err != nil {
		return mapError(err)
	}
	return nil
}

func finishInteractiveDeviceLogin(stream accountDeviceLoginStream) error {
	result, err := stream.Recv()
	if err != nil {
		return mapError(err)
	}
	if !result.GetAuthenticated() || result.GetUserCode() != "" || result.GetVerificationUri() != "" {
		return &Error{Code: "unauthenticated", Message: "account provider did not confirm authentication"}
	}
	return nil
}

func (a accountServiceClient) Status(ctx context.Context, provider string) (bool, error) {
	ctx, cancel := a.c.context(ctx)
	defer cancel()
	resp, err := a.c.accounts.Status(ctx, &localv1.AccountServiceStatusRequest{Provider: provider})
	if err != nil {
		return false, mapError(err)
	}
	return resp.GetCredentialPresent(), nil
}

func (a accountServiceClient) Login(ctx context.Context, provider string) error {
	ctx, cancel := a.c.context(ctx)
	defer cancel()
	resp, err := a.c.accounts.Login(ctx, &localv1.AccountServiceLoginRequest{Provider: provider})
	if err != nil {
		return mapError(err)
	}
	if !resp.GetAuthenticated() {
		return &Error{Code: "failed_precondition", Message: "account provider did not confirm authentication"}
	}
	return nil
}

func (a accountServiceClient) LoginWithPAT(ctx context.Context, username string, password []byte) error {
	ctx, cancel := a.c.context(ctx)
	defer cancel()
	resp, err := a.c.accounts.LoginWithPAT(ctx, &localv1.AccountServiceLoginWithPATRequest{
		Username: username,
		Password: password,
	})
	if err != nil {
		return mapError(err)
	}
	if !resp.GetAuthenticated() {
		return &Error{Code: "unauthenticated", Message: "Docker Hub did not confirm authentication"}
	}
	return nil
}

func (a accountServiceClient) Logout(ctx context.Context, provider string) (bool, error) {
	ctx, cancel := a.c.context(ctx)
	defer cancel()
	resp, err := a.c.accounts.Logout(ctx, &localv1.AccountServiceLogoutRequest{Provider: provider})
	if err != nil {
		return false, mapError(err)
	}
	return resp.GetRemoved(), nil
}

func (r registryCredentialClient) Login(ctx context.Context, req RegistryLoginRequest) (*RegistryLoginResponse, error) {
	ctx, cancel := r.c.context(ctx)
	defer cancel()
	scope, err := registryScopeToProto(req.Scope)
	if err != nil {
		return nil, err
	}
	resp, err := r.c.registry.Login(ctx, &localv1.RegistryCredentialServiceLoginRequest{
		Registry: req.Registry, Username: req.Username, Password: req.Password,
		Scope: scope, SandboxName: req.SandboxName,
	})
	if err != nil {
		return nil, mapError(err)
	}
	return &RegistryLoginResponse{
		Registry: resp.GetRegistry(), Username: resp.GetUsername(),
		Scope: registryScopeFromProto(resp.GetScope()), SandboxName: resp.GetSandboxName(),
	}, nil
}

func (r registryCredentialClient) Logout(ctx context.Context, req RegistryLogoutRequest) (*RegistryLogoutResponse, error) {
	ctx, cancel := r.c.context(ctx)
	defer cancel()
	scope, err := registryScopeToProto(req.Scope)
	if err != nil {
		return nil, err
	}
	resp, err := r.c.registry.Logout(ctx, &localv1.RegistryCredentialServiceLogoutRequest{
		Registry: req.Registry, Scope: scope, SandboxName: req.SandboxName,
	})
	if err != nil {
		return nil, mapError(err)
	}
	return &RegistryLogoutResponse{Removed: resp.GetRemoved()}, nil
}

func registryScopeToProto(scope RegistryCredentialScope) (localv1.RegistryCredentialScope, error) {
	switch scope {
	case "", RegistryScopeHostOnly:
		return localv1.RegistryCredentialScope_REGISTRY_CREDENTIAL_SCOPE_HOST_ONLY, nil
	case RegistryScopeAllSandboxes:
		return localv1.RegistryCredentialScope_REGISTRY_CREDENTIAL_SCOPE_ALL_SANDBOXES, nil
	case RegistryScopeSandbox:
		return localv1.RegistryCredentialScope_REGISTRY_CREDENTIAL_SCOPE_SANDBOX, nil
	default:
		return localv1.RegistryCredentialScope_REGISTRY_CREDENTIAL_SCOPE_UNSPECIFIED, &Error{Code: errorCodeInvalidArgument, Message: "unsupported registry credential scope"}
	}
}

func registryScopeFromProto(scope localv1.RegistryCredentialScope) RegistryCredentialScope {
	switch scope {
	case localv1.RegistryCredentialScope_REGISTRY_CREDENTIAL_SCOPE_ALL_SANDBOXES:
		return RegistryScopeAllSandboxes
	case localv1.RegistryCredentialScope_REGISTRY_CREDENTIAL_SCOPE_SANDBOX:
		return RegistryScopeSandbox
	default:
		return RegistryScopeHostOnly
	}
}

func (o operationClient) Get(ctx context.Context, id string) (*Operation, error) {
	ctx, cancel := o.c.context(ctx)
	defer cancel()
	resp, err := o.c.operations.Get(ctx, &localv1.OperationServiceGetRequest{Id: id})
	if err != nil {
		return nil, mapError(err)
	}
	return fromProtoOperation(resp.GetOperation()), nil
}

func (o operationClient) Wait(ctx context.Context, id string) (*Operation, error) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		op, err := o.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		if op.State == StateDone || op.State == StateFailed {
			return op, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}
