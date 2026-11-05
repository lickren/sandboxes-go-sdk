package sandboxes

import (
	"context"
	"strconv"
	"strings"
)

const oauthCredentialsMinimumAPIVersion = "0.0.15"

func apiVersionAtLeast(actual, minimum string) bool {
	parse := func(version string) ([3]uint64, bool) {
		version = strings.TrimPrefix(version, "v")
		if strings.Contains(version, "-") {
			return [3]uint64{}, false
		}
		if base, metadata, ok := strings.Cut(version, "+"); ok {
			if !validBuildMetadata(metadata) {
				return [3]uint64{}, false
			}
			version = base
		}
		parts := strings.Split(version, ".")
		if len(parts) != 3 {
			return [3]uint64{}, false
		}
		var parsed [3]uint64
		for i, part := range parts {
			n, err := strconv.ParseUint(part, 10, 64)
			if err != nil || strconv.FormatUint(n, 10) != part {
				return [3]uint64{}, false
			}
			parsed[i] = n
		}
		return parsed, true
	}
	got, ok := parse(actual)
	if !ok {
		return false
	}
	want, ok := parse(minimum)
	if !ok {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return got[i] > want[i]
		}
	}
	return true
}

func validBuildMetadata(metadata string) bool {
	if metadata == "" {
		return false
	}
	for _, identifier := range strings.Split(metadata, ".") {
		if identifier == "" {
			return false
		}
		for i := range identifier {
			char := identifier[i]
			if (char >= '0' && char <= '9') || (char >= 'A' && char <= 'Z') ||
				(char >= 'a' && char <= 'z') || char == '-' {
				continue
			}
			return false
		}
	}
	return true
}

// VersionInfo describes the daemon and API contract versions.
type VersionInfo struct {
	// Version is the daemon version.
	Version string
	// APIVersion is the local sandbox contract version implemented by the daemon.
	APIVersion string
}

// VersionService reports daemon and API contract versions.
type VersionService interface {
	Get(ctx context.Context) (VersionInfo, error)
}

// VersionServiceProvider is optionally implemented by root clients that expose
// daemon version inspection without changing the root Client interface.
type VersionServiceProvider interface {
	VersionService() VersionService
}

// Version returns the optional version service.
func Version(c Client) VersionService {
	if provider, ok := c.(VersionServiceProvider); ok {
		if service := provider.VersionService(); service != nil {
			return service
		}
	}
	return unsupportedVersionService{}
}

type unsupportedVersionService struct{}

func (unsupportedVersionService) Get(context.Context) (VersionInfo, error) {
	return VersionInfo{}, &Error{Code: errorCodeUnsupported, Message: "version inspection is not supported by this client"}
}
