# sandboxes-go-sdk

## Import path migration

The canonical Go module path is now `github.com/rheic/sandboxes-go-sdk` (previously `github.com/quoiner/sandboxes-go-sdk`). Update imports and `go.mod` requirements when moving to a release that includes this change. The old module path is not kept as a compatibility alias.

Status: pre-alpha.

Official Go client for the local sandboxes daemon. The SDK is a client library,
not a second business-logic layer.

## Boundaries

- public domain types are not protobuf types;
- retries, idempotency, operation wait/watch, stream reconnect, pagination, and
  typed errors belong here;
- policy and security decisions belong to the daemon and gateway;
- the CLI and TUI consume this module instead of daemon internals.

## Usage

```go
client, err := sandboxes.New(sandboxes.Config{
	Address: "/path/to/sandboxes.sock",
})
if err != nil {
	return err
}
defer client.Close()

sb, err := client.Sandboxes().Get(ctx, "dev")
```

`client.RegistryCredentials().Login` and `.Logout` manage host-side registry
credential entries. `RegistryLoginRequest.Password` is sent only to the local
daemon; callers should clear the byte slice after the call. The SDK does not
log credentials or make policy decisions. Guest registry pulls remain
unsupported until the host broker is connected to the gateway.

`sandboxes.Accounts(client)` optionally exposes host-side OAuth account login
and logout. It accepts only a provider name; the daemon resolves endpoints and
client registration from trusted host configuration. OAuth tokens are never
returned by the SDK. Existing implementations of `Client` remain compatible;
clients without account RPC support return an `unsupported` error.

## Development

Requires Go 1.27.

```sh
make test
make check
make lint
```
