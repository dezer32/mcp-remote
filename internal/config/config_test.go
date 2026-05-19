package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// withCleanConfigEnv изолирует env vars, влияющие на разрешение ConfigDir,
// чтобы тесты не зависели от окружения CI.
func withCleanConfigEnv(t *testing.T) {
	t.Helper()
	// t.Setenv автоматически восстанавливает прежнее значение по завершении.
	// Чтобы получить "нет переменной", сначала очищаем (мы не хотим, чтобы случайно
	// унаследованный MCP_REMOTE_CONFIG_DIR из shell ломал defaults-кейс).
	t.Setenv("MCP_REMOTE_CONFIG_DIR", "")
	if err := os.Unsetenv("MCP_REMOTE_CONFIG_DIR"); err != nil {
		t.Fatalf("unsetenv MCP_REMOTE_CONFIG_DIR: %v", err)
	}
}

func TestParse_ValidURLOnly(t *testing.T) {
	withCleanConfigEnv(t)
	cfg, err := Parse([]string{"https://example.com/mcp"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ServerURL != "https://example.com/mcp" {
		t.Errorf("ServerURL = %q, want %q", cfg.ServerURL, "https://example.com/mcp")
	}
	if cfg.Port != 0 {
		t.Errorf("Port = %d, want 0", cfg.Port)
	}
	if cfg.AllowHTTP {
		t.Error("AllowHTTP should default to false")
	}
	if cfg.AuthTimeout != 30*time.Second {
		t.Errorf("AuthTimeout = %v, want 30s", cfg.AuthTimeout)
	}
	if cfg.Host != "127.0.0.1" {
		t.Errorf("Host = %q, want 127.0.0.1", cfg.Host)
	}
	if cfg.ConfigDir == "" {
		t.Error("ConfigDir should have a default value")
	}
	if len(cfg.Headers) != 0 {
		t.Errorf("Headers should be empty, got %v", cfg.Headers)
	}
}

func TestParse_ValidURLAndPort(t *testing.T) {
	withCleanConfigEnv(t)
	cfg, err := Parse([]string{"https://example.com", "8080"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Port != 8080 {
		t.Errorf("Port = %d, want 8080", cfg.Port)
	}
}

func TestParse_SingleHeader(t *testing.T) {
	withCleanConfigEnv(t)
	cfg, err := Parse([]string{"https://example.com", "--header", "X-Foo: bar"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []Header{{Name: "X-Foo", Value: "bar"}}
	if !reflect.DeepEqual(cfg.Headers, want) {
		t.Errorf("Headers = %#v, want %#v", cfg.Headers, want)
	}
}

func TestParse_HeaderEnvInterpolation(t *testing.T) {
	withCleanConfigEnv(t)
	t.Setenv("HOME", "/h")
	cfg, err := Parse([]string{"https://example.com", "--header", "X-Foo: prefix-${HOME}-suffix"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Headers) != 1 || cfg.Headers[0].Value != "prefix-/h-suffix" {
		t.Errorf("Headers = %#v, want value 'prefix-/h-suffix'", cfg.Headers)
	}
}

func TestParse_MultipleHeaders(t *testing.T) {
	withCleanConfigEnv(t)
	cfg, err := Parse([]string{
		"https://example.com",
		"--header", "X-A: 1",
		"--header", "X-B: 2",
		"--header", "X-C:3",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []Header{
		{Name: "X-A", Value: "1"},
		{Name: "X-B", Value: "2"},
		{Name: "X-C", Value: "3"},
	}
	if !reflect.DeepEqual(cfg.Headers, want) {
		t.Errorf("Headers = %#v, want %#v", cfg.Headers, want)
	}
}

func TestParse_AllFlags(t *testing.T) {
	withCleanConfigEnv(t)
	cfg, err := Parse([]string{
		"https://example.com",
		"9090",
		"--header", "Authorization: Bearer tok",
		"--allow-http",
		"--debug",
		"--silent",
		"--auth-timeout", "45s",
		"--static-oauth-client-metadata", `{"client_name":"x"}`,
		"--static-oauth-client-info", `{"client_id":"y"}`,
		"--resource", "https://res.example.com",
		"--host", "0.0.0.0",
		"--config-dir", "/tmp/cfg",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Port != 9090 {
		t.Errorf("Port = %d, want 9090", cfg.Port)
	}
	if !cfg.AllowHTTP || !cfg.Debug || !cfg.Silent {
		t.Errorf("bool flags not set: AllowHTTP=%v Debug=%v Silent=%v", cfg.AllowHTTP, cfg.Debug, cfg.Silent)
	}
	if cfg.AuthTimeout != 45*time.Second {
		t.Errorf("AuthTimeout = %v, want 45s", cfg.AuthTimeout)
	}
	if string(cfg.StaticOAuthClientMetadataJSON) != `{"client_name":"x"}` {
		t.Errorf("StaticOAuthClientMetadataJSON = %s", cfg.StaticOAuthClientMetadataJSON)
	}
	if string(cfg.StaticOAuthClientInfoJSON) != `{"client_id":"y"}` {
		t.Errorf("StaticOAuthClientInfoJSON = %s", cfg.StaticOAuthClientInfoJSON)
	}
	if cfg.Resource != "https://res.example.com" {
		t.Errorf("Resource = %q", cfg.Resource)
	}
	if cfg.Host != "0.0.0.0" {
		t.Errorf("Host = %q", cfg.Host)
	}
	if cfg.ConfigDir != "/tmp/cfg" {
		t.Errorf("ConfigDir = %q", cfg.ConfigDir)
	}
	if len(cfg.Headers) != 1 || cfg.Headers[0].Name != "Authorization" || cfg.Headers[0].Value != "Bearer tok" {
		t.Errorf("Headers = %#v", cfg.Headers)
	}
}

func TestParse_StaticOAuthClientMetadataFromFile(t *testing.T) {
	withCleanConfigEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "meta.json")
	body := []byte(`{"client_name":"x"}`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write tmp: %v", err)
	}
	cfg, err := Parse([]string{
		"https://example.com",
		"--static-oauth-client-metadata", "@" + path,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(cfg.StaticOAuthClientMetadataJSON, body) {
		t.Errorf("got %s, want %s", cfg.StaticOAuthClientMetadataJSON, body)
	}
}

func TestParse_StaticOAuthClientInfoInline(t *testing.T) {
	withCleanConfigEnv(t)
	cfg, err := Parse([]string{
		"https://example.com",
		"--static-oauth-client-info", `{"client_id":"x"}`,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(cfg.StaticOAuthClientInfoJSON) != `{"client_id":"x"}` {
		t.Errorf("StaticOAuthClientInfoJSON = %s", cfg.StaticOAuthClientInfoJSON)
	}
}

func TestParse_AuthTimeoutSecondsAndDuration(t *testing.T) {
	withCleanConfigEnv(t)
	tests := []struct {
		in   string
		want time.Duration
	}{
		{"60", 60 * time.Second},
		{"2m", 2 * time.Minute},
		{"500ms", 500 * time.Millisecond},
	}
	for _, tc := range tests {
		cfg, err := Parse([]string{"https://example.com", "--auth-timeout", tc.in})
		if err != nil {
			t.Fatalf("--auth-timeout %s: %v", tc.in, err)
		}
		if cfg.AuthTimeout != tc.want {
			t.Errorf("--auth-timeout %s: got %v, want %v", tc.in, cfg.AuthTimeout, tc.want)
		}
	}
}

func TestParse_ConfigDirEnv(t *testing.T) {
	t.Setenv("MCP_REMOTE_CONFIG_DIR", "/custom")
	cfg, err := Parse([]string{"https://example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ConfigDir != "/custom" {
		t.Errorf("ConfigDir = %q, want /custom", cfg.ConfigDir)
	}
}

func TestParse_ConfigDirFlagOverridesEnv(t *testing.T) {
	t.Setenv("MCP_REMOTE_CONFIG_DIR", "/from-env")
	cfg, err := Parse([]string{"https://example.com", "--config-dir", "/flag-wins"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ConfigDir != "/flag-wins" {
		t.Errorf("ConfigDir = %q, want /flag-wins", cfg.ConfigDir)
	}
}

func TestParse_HTTPRequiresAllowFlag(t *testing.T) {
	withCleanConfigEnv(t)
	_, err := Parse([]string{"http://example.com"})
	if err == nil {
		t.Fatal("expected error for http:// without --allow-http")
	}
	if !strings.Contains(err.Error(), "--allow-http") {
		t.Errorf("error message = %q, want mention of --allow-http", err.Error())
	}
}

func TestParse_HTTPWithAllowFlagOK(t *testing.T) {
	withCleanConfigEnv(t)
	cfg, err := Parse([]string{"http://example.com", "--allow-http"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.AllowHTTP {
		t.Error("AllowHTTP should be true")
	}
	if cfg.ServerURL != "http://example.com" {
		t.Errorf("ServerURL = %q", cfg.ServerURL)
	}
}

func TestParse_AuthorizationHeaderAllowed(t *testing.T) {
	withCleanConfigEnv(t)
	cfg, err := Parse([]string{"https://example.com", "--header", "Authorization: Bearer x"})
	if err != nil {
		t.Fatalf("Authorization header should be allowed, got error: %v", err)
	}
	if len(cfg.Headers) != 1 || cfg.Headers[0].Name != "Authorization" {
		t.Errorf("Headers = %#v", cfg.Headers)
	}
}

func TestParse_Errors(t *testing.T) {
	withCleanConfigEnv(t)
	tests := []struct {
		name    string
		args    []string
		errFrag string
	}{
		{
			name:    "empty args",
			args:    nil,
			errFrag: "ServerURL required",
		},
		{
			name:    "empty url string",
			args:    []string{""},
			errFrag: "ServerURL required",
		},
		{
			name:    "header with space in name",
			args:    []string{"https://x", "--header", "Bad Name: v"},
			errFrag: "invalid header name",
		},
		{
			name:    "header value with LF",
			args:    []string{"https://x", "--header", "X-Foo: line1\nline2"},
			errFrag: "CR, LF or NUL",
		},
		{
			name:    "header value with CR",
			args:    []string{"https://x", "--header", "X-Foo: line1\rline2"},
			errFrag: "CR, LF or NUL",
		},
		{
			name:    "header value with NUL",
			args:    []string{"https://x", "--header", "X-Foo: with\x00nul"},
			errFrag: "CR, LF or NUL",
		},
		{
			name:    "reserved Mcp-Session-Id",
			args:    []string{"https://x", "--header", "Mcp-Session-Id: x"},
			errFrag: "reserved",
		},
		{
			name:    "reserved case-insensitive ACCEPT",
			args:    []string{"https://x", "--header", "ACCEPT: x"},
			errFrag: "reserved",
		},
		{
			name:    "reserved Content-Type",
			args:    []string{"https://x", "--header", "content-type: x"},
			errFrag: "reserved",
		},
		{
			name:    "header without colon",
			args:    []string{"https://x", "--header", "X-Foo bar"},
			errFrag: `missing ":" separator`,
		},
		{
			name:    "static metadata invalid json",
			args:    []string{"https://x", "--static-oauth-client-metadata", "not-json"},
			errFrag: "invalid JSON",
		},
		{
			name:    "static metadata missing file",
			args:    []string{"https://x", "--static-oauth-client-metadata", "@/nonexistent/file-zzz"},
			errFrag: "read",
		},
		{
			name:    "static info invalid json",
			args:    []string{"https://x", "--static-oauth-client-info", "not-json"},
			errFrag: "invalid JSON",
		},
		{
			name:    "auth-timeout invalid",
			args:    []string{"https://x", "--auth-timeout", "invalid"},
			errFrag: "--auth-timeout",
		},
		{
			name:    "port zero",
			args:    []string{"https://x", "0"},
			errFrag: "out of range",
		},
		{
			name:    "port too big",
			args:    []string{"https://x", "70000"},
			errFrag: "out of range",
		},
		{
			name:    "port not a number",
			args:    []string{"https://x", "notanumber"},
			errFrag: "parse port",
		},
		{
			name:    "unknown flag",
			args:    []string{"https://x", "--no-such-flag"},
			errFrag: "unknown flag",
		},
		{
			name:    "url without scheme",
			args:    []string{"example.com"},
			errFrag: "scheme",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Parse(tc.args)
			if err == nil {
				t.Fatalf("expected error, got cfg=%#v", cfg)
			}
			if cfg != nil {
				t.Errorf("on error, *Config must be nil; got %#v", cfg)
			}
			if !strings.Contains(err.Error(), tc.errFrag) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.errFrag)
			}
		})
	}
}

func TestParse_HelpReturnsErrHelp(t *testing.T) {
	withCleanConfigEnv(t)
	for _, arg := range []string{"-h", "--help"} {
		cfg, err := Parse([]string{arg})
		if !errors.Is(err, ErrHelp) {
			t.Errorf("Parse(%q) error = %v, want ErrHelp", arg, err)
		}
		if cfg != nil {
			t.Errorf("Parse(%q) cfg = %#v, want nil", arg, cfg)
		}
	}
}

func TestParse_HeaderEqualsSyntax(t *testing.T) {
	withCleanConfigEnv(t)
	// Поддержка --flag=value формы для всех --флагов, не только --header.
	cfg, err := Parse([]string{"https://example.com", "--header=X-Foo: bar"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Headers) != 1 || cfg.Headers[0].Name != "X-Foo" || cfg.Headers[0].Value != "bar" {
		t.Errorf("Headers = %#v", cfg.Headers)
	}
}

func TestParse_FlagsBeforeAndAfterPositional(t *testing.T) {
	withCleanConfigEnv(t)
	// Допускаем флаги перед позиционными аргументами и наоборот.
	cfg, err := Parse([]string{"--debug", "https://example.com", "--silent", "8080"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.Debug || !cfg.Silent {
		t.Errorf("flags lost: %#v", cfg)
	}
	if cfg.Port != 8080 || cfg.ServerURL != "https://example.com" {
		t.Errorf("positional lost: %#v", cfg)
	}
}

func TestParse_TooManyPositional(t *testing.T) {
	withCleanConfigEnv(t)
	_, err := Parse([]string{"https://example.com", "8080", "extra"})
	if err == nil || !strings.Contains(err.Error(), "unexpected positional") {
		t.Errorf("expected unexpected positional error, got %v", err)
	}
}

func TestParse_FlagRequiresValue(t *testing.T) {
	withCleanConfigEnv(t)
	_, err := Parse([]string{"https://example.com", "--header"})
	if err == nil || !strings.Contains(err.Error(), "requires a value") {
		t.Errorf("expected 'requires a value', got %v", err)
	}
}
