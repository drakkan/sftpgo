package dataprovider

import "testing"

func TestNormalizeIPListProtocol(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"SFTP":         protocolSSH,
		"SCP":          protocolSSH,
		protocolSSH:    protocolSSH,
		protocolFTP:    protocolFTP,
		protocolWebDAV: protocolWebDAV,
		protocolHTTP:   protocolHTTP,
		"HTTPShare":    protocolHTTP,
		"OIDC":         protocolHTTP,
	}

	for input, expected := range cases {
		if got := normalizeIPListProtocol(input); got != expected {
			t.Fatalf("normalizeIPListProtocol(%q) = %q, want %q", input, got, expected)
		}
	}
}

func TestIPFilterModeDefaultsAndValidation(t *testing.T) {
	t.Parallel()

	t.Setenv(envIPFilterMode, "")
	if got := getIPFilterMode(); got != ipFilterModeAllowUnmatched {
		t.Fatalf("default filter mode = %q, want %q", got, ipFilterModeAllowUnmatched)
	}

	t.Setenv(envIPFilterMode, ipFilterModeDenyUnmatched)
	if got := getIPFilterMode(); got != ipFilterModeDenyUnmatched {
		t.Fatalf("deny_unmatched filter mode = %q, want %q", got, ipFilterModeDenyUnmatched)
	}

	t.Setenv(envIPFilterMode, "invalid")
	if got := getIPFilterMode(); got != ipFilterModeAllowUnmatched {
		t.Fatalf("invalid filter mode fallback = %q, want %q", got, ipFilterModeAllowUnmatched)
	}
}

func TestIPFilterScopeDefaultsAndValidation(t *testing.T) {
	t.Parallel()

	t.Setenv(envIPFilterScope, "")
	if got := getIPFilterScope(); got != ipFilterScopeDataOnly {
		t.Fatalf("default filter scope = %q, want %q", got, ipFilterScopeDataOnly)
	}

	t.Setenv(envIPFilterScope, ipFilterScopeAllRequests)
	if got := getIPFilterScope(); got != ipFilterScopeAllRequests {
		t.Fatalf("all_requests filter scope = %q, want %q", got, ipFilterScopeAllRequests)
	}

	t.Setenv(envIPFilterScope, "invalid")
	if got := getIPFilterScope(); got != ipFilterScopeDataOnly {
		t.Fatalf("invalid filter scope fallback = %q, want %q", got, ipFilterScopeDataOnly)
	}
}
