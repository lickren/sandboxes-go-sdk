# Changelog

## v0.0.16 — 2026-11-06

- Add the optional `DynamicSecretCreator` capability for host-side references or shell commands, refresh controls, and captured 1Password account/AWS profile selectors; fail closed unless daemon API v0.0.16 or newer is available.

## v0.0.15 — 2026-11-05

### Added

- Add nested Docker Kits v2-shaped OAuth credential configuration to sandbox Create requests; this does not imply daemon runtime support.
- Add the optional `SecretCreator` capability for atomic create-only writes; existing `SecretService` implementations remain source compatible.
- Fail closed before sending OAuth metadata when daemon API version support cannot be verified or is older than 0.0.15.
- Preserve absent optional OAuth messages in the protobuf request, including sentinels omitted for passthrough credentials.


## v0.0.12 — 2026-11-03

### Added

- Add Windows named-pipe transport with contract tests for the local daemon.
- Expose account device-login and credential-presence status APIs from `sandboxes-api v0.0.12`.
- Publish a CycloneDX module SBOM as a CI artifact.

### Changed

- Normalize the Go module path to the lowercase `github.com/quoiner/sandboxes-go-sdk` namespace.
- Update `golang.org/x/net` to v0.62.0.

### Compatibility

- Windows SDK transport support does not imply Windows daemon or VM runtime support.

