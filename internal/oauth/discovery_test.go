package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dezer32/mcp-remote/internal/config"
	"github.com/dezer32/mcp-remote/internal/logging"
)

func TestParseWWWAuthenticate(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want map[string]string
	}{
		{
			name: "nil for non-Bearer",
			in:   `Basic realm="x"`,
			want: nil,
		},
		{
			name: "empty",
			in:   ``,
			want: nil,
		},
		{
			name: "single quoted",
			in:   `Bearer realm="x"`,
			want: map[string]string{"realm": "x"},
		},
		{
			name: "multiple quoted",
			in:   `Bearer realm="x", resource_metadata="https://a/.well-known/oauth-protected-resource", scope="mcp"`,
			want: map[string]string{
				"realm":             "x",
				"resource_metadata": "https://a/.well-known/oauth-protected-resource",
				"scope":             "mcp",
			},
		},
		{
			name: "unquoted",
			in:   `Bearer realm=x, scope=mcp`,
			want: map[string]string{"realm": "x", "scope": "mcp"},
		},
		{
			name: "case-insensitive scheme + extra spaces",
			in:   `bearer  realm = "x" ,  scope = mcp  `,
			want: map[string]string{"realm": "x", "scope": "mcp"},
		},
		{
			name: "escaped quote in value",
			in:   `Bearer realm="he said \"hi\""`,
			want: map[string]string{"realm": `he said "hi"`},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseWWWAuthenticate(tc.in)
			if !mapEqual(got, tc.want) {
				t.Fatalf("parseWWWAuthenticate(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func mapEqual(a, b map[string]string) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

func newTestProvider(t *testing.T, cfg *config.Config) *Provider {
	t.Helper()
	if cfg == nil {
		cfg = &config.Config{}
	}
	return New(cfg, &fakeOpener{}, logging.Discard())
}

func TestDiscoveryPRMPath(t *testing.T) {
	var asURL string

	asMux := http.NewServeMux()
	asMux.HandleFunc(wellKnownAS, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get(headerMCPProtocolVersion); got != mcpProtocolVersion {
			t.Errorf("AS metadata: missing/wrong MCP version: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"authorization_endpoint": asURL + "/auth",
			"token_endpoint":         asURL + "/tok",
			"registration_endpoint":  asURL + "/reg",
		})
	})
	asSrv := httptest.NewServer(asMux)
	defer asSrv.Close()
	asURL = asSrv.URL

	prmMux := http.NewServeMux()
	prmMux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get(headerMCPProtocolVersion); got != mcpProtocolVersion {
			t.Errorf("PRM: missing/wrong MCP version: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":              "https://api.example.com/mcp",
			"authorization_servers": []string{asSrv.URL},
		})
	})
	prmSrv := httptest.NewServer(prmMux)
	defer prmSrv.Close()

	p := newTestProvider(t, &config.Config{ServerURL: "https://ignored.example/mcp"})
	meta, resource, err := p.discover(context.Background(), prmSrv.URL+"/.well-known/oauth-protected-resource", "https://ignored.example/mcp", "")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if want := asURL + "/auth"; meta.AuthorizationEndpoint != want {
		t.Fatalf("auth endpoint = %s, want %s", meta.AuthorizationEndpoint, want)
	}
	if want := asURL + "/tok"; meta.TokenEndpoint != want {
		t.Fatalf("token endpoint = %s, want %s", meta.TokenEndpoint, want)
	}
	if resource != "https://api.example.com/mcp" {
		t.Fatalf("resource = %s, want https://api.example.com/mcp", resource)
	}
}

func TestDiscoveryRFC8414Fallback(t *testing.T) {
	asMux := http.NewServeMux()
	asMux.HandleFunc(wellKnownAS, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"authorization_endpoint": "https://issuer/auth",
			"token_endpoint":         "https://issuer/tok",
		})
	})
	asSrv := httptest.NewServer(asMux)
	defer asSrv.Close()

	p := newTestProvider(t, &config.Config{ServerURL: asSrv.URL + "/some/mcp/path"})
	meta, resource, err := p.discover(context.Background(), "", asSrv.URL+"/some/mcp/path", "")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if meta.AuthorizationEndpoint != "https://issuer/auth" {
		t.Fatalf("auth endpoint = %s", meta.AuthorizationEndpoint)
	}
	if resource != "" {
		t.Fatalf("resource = %s, want empty", resource)
	}
}

func TestDiscoveryDefaultPathsOn404(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc(wellKnownAS, func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := newTestProvider(t, &config.Config{ServerURL: srv.URL})
	meta, resource, err := p.discover(context.Background(), "", srv.URL, "")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if !strings.HasSuffix(meta.AuthorizationEndpoint, "/authorize") {
		t.Fatalf("default auth endpoint missing: %s", meta.AuthorizationEndpoint)
	}
	if !strings.HasSuffix(meta.TokenEndpoint, "/token") {
		t.Fatalf("default token endpoint missing: %s", meta.TokenEndpoint)
	}
	if !strings.HasSuffix(meta.RegistrationEndpoint, "/register") {
		t.Fatalf("default register endpoint missing: %s", meta.RegistrationEndpoint)
	}
	if resource != "" {
		t.Fatalf("resource = %s, want empty", resource)
	}
}

func TestDiscoveryResourceOverride(t *testing.T) {
	asMux := http.NewServeMux()
	asMux.HandleFunc(wellKnownAS, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"authorization_endpoint": "https://x/authorize",
			"token_endpoint":         "https://x/token",
		})
	})
	asSrv := httptest.NewServer(asMux)
	defer asSrv.Close()

	prmMux := http.NewServeMux()
	prmMux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":              "auto",
			"authorization_servers": []string{asSrv.URL},
		})
	})
	prmSrv := httptest.NewServer(prmMux)
	defer prmSrv.Close()

	p := newTestProvider(t, &config.Config{ServerURL: "https://srv"})
	_, resource, err := p.discover(context.Background(), prmSrv.URL+"/.well-known/oauth-protected-resource", "https://srv", "override")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if resource != "override" {
		t.Fatalf("resource = %s, want override", resource)
	}
}

func TestAuthBaseFromServerURL(t *testing.T) {
	got, err := authBaseFromServerURL("https://example.com:8443/some/path?x=1")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "https://example.com:8443" {
		t.Fatalf("got %s", got)
	}
	if _, err := authBaseFromServerURL(""); err == nil {
		t.Fatalf("expected error for empty URL")
	}
	if _, err := authBaseFromServerURL("not a url"); err == nil {
		t.Fatalf("expected error for invalid URL")
	}
}
