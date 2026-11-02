package sandboxes

import (
	"context"

	localv1 "github.com/quoiner/sandboxes-api/gen/go/sandboxes/local/v1"
)

// SecretScope controls where a service secret may be used.
type SecretScope string

const (
	SecretScopeGlobal  SecretScope = "global"
	SecretScopeSandbox SecretScope = "sandbox"
)

// ServiceSecret is non-secret metadata.
type ServiceSecret struct {
	Service     string
	Scope       SecretScope
	SandboxName string
}

// SecretService manages host-keychain service secrets.
type SecretService interface {
	Set(ctx context.Context, service string, scope SecretScope, sandboxName string, value []byte) (ServiceSecret, error)
	List(ctx context.Context) ([]ServiceSecret, error)
	Remove(ctx context.Context, service string, scope SecretScope, sandboxName string) (bool, error)
}

// SecretServiceProvider is implemented by clients that expose service secrets.
type SecretServiceProvider interface {
	SecretService() SecretService
}

// Secrets returns the optional service-secret client.
func Secrets(c Client) SecretService {
	if provider, ok := c.(SecretServiceProvider); ok {
		if service := provider.SecretService(); service != nil {
			return service
		}
	}
	return unsupportedSecretService{}
}

const unsupportedSecretsMessage = "service secrets are not supported by this client"

type unsupportedSecretService struct{}

func (unsupportedSecretService) Set(context.Context, string, SecretScope, string, []byte) (ServiceSecret, error) {
	return ServiceSecret{}, &Error{Code: errorCodeUnsupported, Message: unsupportedSecretsMessage}
}

func (unsupportedSecretService) List(context.Context) ([]ServiceSecret, error) {
	return nil, &Error{Code: errorCodeUnsupported, Message: unsupportedSecretsMessage}
}

func (unsupportedSecretService) Remove(context.Context, string, SecretScope, string) (bool, error) {
	return false, &Error{Code: errorCodeUnsupported, Message: unsupportedSecretsMessage}
}

func (c *client) SecretService() SecretService { return secretClient{c: c} }

type secretClient struct{ c *client }

func (s secretClient) Set(ctx context.Context, service string, scope SecretScope, sandboxName string, value []byte) (ServiceSecret, error) {
	ctx, cancel := s.c.context(ctx)
	defer cancel()
	resp, err := s.c.secrets.Set(ctx, &localv1.SecretServiceSetRequest{
		Service: service, Scope: string(scope), SandboxName: sandboxName, Value: value,
	})
	if err != nil {
		return ServiceSecret{}, mapError(err)
	}
	return serviceSecretFromProto(resp.GetSecret()), nil
}

func (s secretClient) List(ctx context.Context) ([]ServiceSecret, error) {
	ctx, cancel := s.c.context(ctx)
	defer cancel()
	resp, err := s.c.secrets.List(ctx, &localv1.SecretServiceListRequest{})
	if err != nil {
		return nil, mapError(err)
	}
	out := make([]ServiceSecret, 0, len(resp.GetSecrets()))
	for _, item := range resp.GetSecrets() {
		if item != nil {
			out = append(out, serviceSecretFromProto(item))
		}
	}
	return out, nil
}

func (s secretClient) Remove(ctx context.Context, service string, scope SecretScope, sandboxName string) (bool, error) {
	ctx, cancel := s.c.context(ctx)
	defer cancel()
	resp, err := s.c.secrets.Remove(ctx, &localv1.SecretServiceRemoveRequest{
		Service: service, Scope: string(scope), SandboxName: sandboxName,
	})
	if err != nil {
		return false, mapError(err)
	}
	return resp.GetRemoved(), nil
}

func serviceSecretFromProto(item *localv1.SecretSummary) ServiceSecret {
	if item == nil {
		return ServiceSecret{}
	}
	return ServiceSecret{Service: item.GetService(), Scope: SecretScope(item.GetScope()), SandboxName: item.GetSandboxName()}
}
