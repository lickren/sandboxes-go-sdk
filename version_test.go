package sandboxes

import "testing"

func TestAPIVersionAtLeast(t *testing.T) {
	tests := []struct {
		name    string
		actual  string
		minimum string
		want    bool
	}{
		{name: "same version", actual: "0.0.15", minimum: "0.0.15", want: true},
		{name: "newer patch", actual: "v0.0.16", minimum: "0.0.15", want: true},
		{name: "newer minor", actual: "0.1.0", minimum: "0.0.15", want: true},
		{name: "older patch", actual: "0.0.14", minimum: "0.0.15"},
		{name: "prerelease fails closed", actual: "0.0.15-rc.1", minimum: "0.0.15"},
		{name: "build metadata", actual: "0.0.15+build.1", minimum: "0.0.15", want: true},
		{name: "empty build metadata", actual: "0.0.15+", minimum: "0.0.15"},
		{name: "empty build metadata identifier", actual: "0.0.15+build..1", minimum: "0.0.15"},
		{name: "invalid build metadata character", actual: "0.0.15+build!", minimum: "0.0.15"},
		{name: "multiple build separators", actual: "0.0.15+build+local", minimum: "0.0.15"},
		{name: "leading zero", actual: "0.0.015", minimum: "0.0.15"},
		{name: "malformed version", actual: "unknown", minimum: "0.0.15"},
		{name: "incomplete version", actual: "0.0", minimum: "0.0.15"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := apiVersionAtLeast(tt.actual, tt.minimum); got != tt.want {
				t.Fatalf("apiVersionAtLeast(%q, %q) = %t, want %t", tt.actual, tt.minimum, got, tt.want)
			}
		})
	}
}
