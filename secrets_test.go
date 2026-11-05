package sandboxes

import (
	"context"
	"testing"
)

type legacySecretService struct{}

func (legacySecretService) Set(context.Context, string, SecretScope, string, []byte) (ServiceSecret, error) {
	return ServiceSecret{}, nil
}

func (legacySecretService) List(context.Context) ([]ServiceSecret, error) { return nil, nil }

func (legacySecretService) Remove(context.Context, string, SecretScope, string) (bool, error) {
	return false, nil
}

var _ SecretService = legacySecretService{}

type legacySecretsClient struct{ secrets SecretService }

func (legacySecretsClient) Sandboxes() SandboxService                      { return nil }
func (legacySecretsClient) Operations() OperationService                   { return nil }
func (legacySecretsClient) RegistryCredentials() RegistryCredentialService { return nil }
func (legacySecretsClient) Close() error                                   { return nil }
func (c legacySecretsClient) SecretService() SecretService                 { return c.secrets }

func TestSecretCreationIsOptionalForExistingSecretServiceImplementations(t *testing.T) {
	creator, ok := SecretCreation(legacySecretsClient{secrets: legacySecretService{}})
	if ok || creator != nil {
		t.Fatalf("legacy SecretService unexpectedly exposes create-only capability: creator=%T ok=%t", creator, ok)
	}
}
