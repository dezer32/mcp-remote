package oauth

// Тесты hardening-проверок discovery: транспортная политика эндпоинтов,
// issuer/resource, политика редиректов.

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dezer32/mcp-remote/internal/config"
	"github.com/dezer32/mcp-remote/internal/logging"
)

// newTLSProvider создаёт Provider, доверяющий сертификату tlsSrv (транспорт
// берётся из tlsSrv.Client(); CheckRedirect, заданный в New, сохраняется).
func newTLSProvider(t *testing.T, cfg *config.Config, tlsSrv *httptest.Server) *Provider {
	t.Helper()
	p := New(cfg, newFakeOpener(), logging.Discard())
	p.httpClient.Transport = tlsSrv.Client().Transport
	return p
}

// asMetadataHandler отдаёт заданный документ AS metadata.
func asMetadataHandler(doc map[string]any) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(wellKnownAS, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})
	return mux
}

func TestValidateEndpointURL(t *testing.T) {
	tests := []struct {
		name      string
		in        string
		allowHTTP bool
		wantErr   bool
	}{
		{name: "https ok", in: "https://auth.example.com/token"},
		{name: "https with port and query", in: "https://auth.example.com:8443/a?x=1&y=2"},
		{name: "http without allow", in: "http://auth.example.com/token", wantErr: true},
		{name: "http with allow", in: "http://auth.example.com/token", allowHTTP: true},
		{name: "https with allow", in: "https://auth.example.com/token", allowHTTP: true},
		{name: "javascript rejected without allow", in: "javascript:alert(1)", wantErr: true},
		{name: "javascript rejected with allow", in: "javascript:alert(1)", allowHTTP: true, wantErr: true},
		{name: "file rejected without allow", in: "file:///etc/passwd", wantErr: true},
		{name: "file rejected with allow", in: "file:///etc/passwd", allowHTTP: true, wantErr: true},
		{name: "relative", in: "/token", wantErr: true},
		{name: "relative with allow", in: "/token", allowHTTP: true, wantErr: true},
		{name: "host only", in: "auth.example.com/token", wantErr: true},
		{name: "userinfo", in: "https://login.example.com@evil.example/token", wantErr: true},
		{name: "userinfo with password", in: "https://u:p@auth.example.com/token", wantErr: true},
		{name: "empty host", in: "https:///token", wantErr: true},
		{name: "empty", in: "", wantErr: true},
		{name: "control char", in: "https://auth.example.com/\x00", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u, err := validateEndpointURL(tc.in, tc.allowHTTP)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("validateEndpointURL(%q, %v) = %v, want error", tc.in, tc.allowHTTP, u)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateEndpointURL(%q, %v): %v", tc.in, tc.allowHTTP, err)
			}
			if u == nil || u.Host == "" {
				t.Fatalf("validateEndpointURL(%q): bad result %v", tc.in, u)
			}
		})
	}
}

func TestDiscoveryHTTPTokenEndpointPolicy(t *testing.T) {
	doc := map[string]any{
		"authorization_endpoint": "https://auth.example.com/authorize",
		"token_endpoint":         "http://auth.example.com/token",
	}
	srv := httptest.NewTLSServer(asMetadataHandler(doc))
	defer srv.Close()

	t.Run("without allow-http", func(t *testing.T) {
		p := newTLSProvider(t, &config.Config{ServerURL: srv.URL + "/mcp"}, srv)
		_, _, err := p.discover(context.Background(), "", srv.URL+"/mcp", "")
		if err == nil || !strings.Contains(err.Error(), "token_endpoint") {
			t.Fatalf("discover err = %v, want token_endpoint error", err)
		}
	})

	t.Run("with allow-http", func(t *testing.T) {
		p := newTLSProvider(t, &config.Config{ServerURL: srv.URL + "/mcp", AllowHTTP: true}, srv)
		meta, _, err := p.discover(context.Background(), "", srv.URL+"/mcp", "")
		if err != nil {
			t.Fatalf("discover: %v", err)
		}
		if meta.TokenEndpoint != "http://auth.example.com/token" {
			t.Fatalf("token endpoint = %q", meta.TokenEndpoint)
		}
	})
}

func TestDiscoveryRejectsBadEndpointSchemes(t *testing.T) {
	tests := []struct {
		field string
		doc   map[string]any
	}{
		{"authorization_endpoint", map[string]any{"authorization_endpoint": "javascript:alert(1)", "token_endpoint": "https://a.example/token"}},
		{"authorization_endpoint", map[string]any{"authorization_endpoint": "file:///etc/passwd", "token_endpoint": "https://a.example/token"}},
		{"token_endpoint", map[string]any{"authorization_endpoint": "https://a.example/authorize", "token_endpoint": "ftp://a.example/token"}},
		{"registration_endpoint", map[string]any{"authorization_endpoint": "https://a.example/authorize", "token_endpoint": "https://a.example/token", "registration_endpoint": "javascript:1"}},
		{"authorization_endpoint", map[string]any{"authorization_endpoint": "https://user@a.example/authorize", "token_endpoint": "https://a.example/token"}},
	}
	for _, tc := range tests {
		srv := httptest.NewServer(asMetadataHandler(tc.doc))
		// allow-http включён: недопустимые схемы отклоняются и с ним.
		p := newTestProvider(t, &config.Config{ServerURL: srv.URL + "/mcp"})
		_, _, err := p.discover(context.Background(), "", srv.URL+"/mcp", "")
		srv.Close()
		if err == nil || !strings.Contains(err.Error(), tc.field) {
			t.Fatalf("doc %v: err = %v, want error mentioning %s", tc.doc, err, tc.field)
		}
	}
}

// authorization_endpoint с javascript: — флоу падает до открытия браузера.
func TestHandleUnauthorizedBadAuthorizationEndpointDoesNotOpenBrowser(t *testing.T) {
	srv := httptest.NewServer(asMetadataHandler(map[string]any{
		"authorization_endpoint": "javascript:alert(1)",
		"token_endpoint":         "https://a.example/token",
	}))
	defer srv.Close()

	opener := newFakeOpener()
	p := New(&config.Config{
		ServerURL:   srv.URL + "/mcp",
		ConfigDir:   t.TempDir(),
		AuthTimeout: time.Second,
		AllowHTTP:   true,
	}, opener, logging.Discard())

	err := p.HandleUnauthorized(context.Background(), "")
	if err == nil {
		t.Fatal("expected error")
	}
	select {
	case u := <-opener.openedURL:
		t.Fatalf("opener called with %q", u)
	default:
	}
}

func TestDiscoveryRejectsHTTPResourceMetadataAndAS(t *testing.T) {
	var hits atomic.Int64
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.NotFound(w, nil)
	}))
	defer plain.Close()

	t.Run("http resource_metadata not requested", func(t *testing.T) {
		p := New(&config.Config{ServerURL: "https://srv.example/mcp"}, newFakeOpener(), logging.Discard())
		_, _, err := p.discover(context.Background(), plain.URL+"/.well-known/oauth-protected-resource", "https://srv.example/mcp", "")
		if err == nil || !strings.Contains(err.Error(), "resource_metadata") {
			t.Fatalf("err = %v, want resource_metadata error", err)
		}
		if n := hits.Load(); n != 0 {
			t.Fatalf("server got %d requests, want 0", n)
		}
	})

	t.Run("http authorization_servers[0] not requested", func(t *testing.T) {
		prm := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"resource":              "https://srv.example/mcp",
				"authorization_servers": []string{plain.URL},
			})
		}))
		defer prm.Close()
		p := newTLSProvider(t, &config.Config{ServerURL: "https://srv.example/mcp"}, prm)
		_, _, err := p.discover(context.Background(), prm.URL+"/prm", "https://srv.example/mcp", "")
		if err == nil || !strings.Contains(err.Error(), "authorization_servers") {
			t.Fatalf("err = %v, want authorization_servers error", err)
		}
		if n := hits.Load(); n != 0 {
			t.Fatalf("AS server got %d requests, want 0", n)
		}
	})
}

// POST на token/registration endpoint не следует редиректам: второй сервер
// не получает ни одного запроса.
func TestPostRedirectsAreNotFollowed(t *testing.T) {
	var victimHits atomic.Int64
	victim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		victimHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer victim.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, victim.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	p := New(&config.Config{AllowHTTP: true}, newFakeOpener(), logging.Discard())

	form := url.Values{"grant_type": {"authorization_code"}, "code_verifier": {"secret-verifier"}}
	_, err := p.postToken(context.Background(), redirector.URL+"/token", form)
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("postToken err = %v, want redirect error", err)
	}
	_, err = p.registerClient(context.Background(), redirector.URL+"/register", "http://127.0.0.1:1/callback")
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("registerClient err = %v, want redirect error", err)
	}
	if n := victimHits.Load(); n != 0 {
		t.Fatalf("redirect target got %d requests, want 0", n)
	}
}

// Редирект AS metadata с https на http без --allow-http: discovery падает,
// http-сервер запросов не получает. С --allow-http тот же редирект проходит
// (заодно проверяет, что CheckRedirect не теряется при замене Transport).
func TestDiscoveryRedirectDowngradeBlocked(t *testing.T) {
	var plainHits atomic.Int64
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		plainHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"authorization_endpoint": "https://a.example/authorize",
			"token_endpoint":         "https://a.example/token",
		})
	}))
	defer plain.Close()

	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+wellKnownAS, http.StatusFound)
	}))
	defer tlsSrv.Close()

	t.Run("blocked without allow-http", func(t *testing.T) {
		p := newTLSProvider(t, &config.Config{ServerURL: tlsSrv.URL + "/mcp"}, tlsSrv)
		_, _, err := p.discover(context.Background(), "", tlsSrv.URL+"/mcp", "")
		if err == nil || !strings.Contains(err.Error(), "not allowed") {
			t.Fatalf("discover err = %v, want downgrade error", err)
		}
		if n := plainHits.Load(); n != 0 {
			t.Fatalf("http server got %d requests, want 0", n)
		}
	})

	t.Run("allowed with allow-http", func(t *testing.T) {
		p := newTLSProvider(t, &config.Config{ServerURL: tlsSrv.URL + "/mcp", AllowHTTP: true}, tlsSrv)
		if _, _, err := p.discover(context.Background(), "", tlsSrv.URL+"/mcp", ""); err != nil {
			t.Fatalf("discover: %v", err)
		}
		if n := plainHits.Load(); n != 1 {
			t.Fatalf("http server got %d requests, want 1", n)
		}
	})
}

// Цепочка из пяти редиректов проходит, шестой редирект — ошибка.
func TestDiscoveryRedirectLimit(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/hop/", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/hop/"))
		if n >= 6 {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
			return
		}
		http.Redirect(w, r, "/hop/"+strconv.Itoa(n+1), http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := newTestProvider(t, &config.Config{})

	// /hop/1 -> ... -> /hop/6: пять редиректов, финальный ответ 200.
	if _, err := p.httpGetJSON(context.Background(), srv.URL+"/hop/1"); err != nil {
		t.Fatalf("5 redirects must be followed: %v", err)
	}
	// /hop/0 -> ... -> /hop/6: шесть редиректов.
	_, err := p.httpGetJSON(context.Background(), srv.URL+"/hop/0")
	if err == nil || !strings.Contains(err.Error(), "redirects") {
		t.Fatalf("6th redirect err = %v, want redirect limit error", err)
	}
}

// bufLogger возвращает slog-логгер, пишущий в буфер (для проверки Warn).
func bufLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})), &buf
}

func TestFetchASIssuerCheck(t *testing.T) {
	newSrv := func(issuer string, omit bool) *httptest.Server {
		var srv *httptest.Server
		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			doc := map[string]any{
				"authorization_endpoint": srv.URL + "/authorize",
				"token_endpoint":         srv.URL + "/token",
			}
			if !omit {
				if issuer == "" {
					doc["issuer"] = srv.URL
				} else {
					doc["issuer"] = issuer
				}
			}
			_ = json.NewEncoder(w).Encode(doc)
		}))
		return srv
	}
	newP := func(log *slog.Logger) *Provider {
		return New(&config.Config{AllowHTTP: true}, newFakeOpener(), log)
	}

	t.Run("match", func(t *testing.T) {
		srv := newSrv("", false)
		defer srv.Close()
		if _, err := newP(logging.Discard()).fetchAS(context.Background(), srv.URL); err != nil {
			t.Fatalf("fetchAS: %v", err)
		}
	})

	t.Run("asID with trailing slash", func(t *testing.T) {
		srv := newSrv("", false)
		defer srv.Close()
		// Идентификатор с завершающим "/" против issuer без него.
		if _, err := newP(logging.Discard()).fetchAS(context.Background(), srv.URL+"/"); err != nil {
			t.Fatalf("asID with trailing slash: %v", err)
		}
	})

	t.Run("issuer differs only by trailing slash", func(t *testing.T) {
		var srv *httptest.Server
		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 srv.URL + "/",
				"authorization_endpoint": srv.URL + "/authorize",
				"token_endpoint":         srv.URL + "/token",
			})
		}))
		defer srv.Close()
		if _, err := newP(logging.Discard()).fetchAS(context.Background(), srv.URL); err != nil {
			t.Fatalf("fetchAS: %v", err)
		}
	})

	t.Run("mismatch", func(t *testing.T) {
		srv := newSrv("https://evil.example", false)
		defer srv.Close()
		_, err := newP(logging.Discard()).fetchAS(context.Background(), srv.URL)
		if err == nil || !strings.Contains(err.Error(), "https://evil.example") || !strings.Contains(err.Error(), srv.URL) {
			t.Fatalf("err = %v, want error naming both issuer and AS", err)
		}
	})

	t.Run("missing issuer warns", func(t *testing.T) {
		srv := newSrv("", true)
		defer srv.Close()
		log, buf := bufLogger()
		if _, err := newP(log).fetchAS(context.Background(), srv.URL); err != nil {
			t.Fatalf("fetchAS: %v", err)
		}
		if out := buf.String(); !strings.Contains(out, "level=WARN") || !strings.Contains(out, "no issuer") {
			t.Fatalf("log = %q, want issuer warning", out)
		}
	})

	t.Run("404 defaults skip the check", func(t *testing.T) {
		srv := httptest.NewServer(http.NotFoundHandler())
		defer srv.Close()
		if _, err := newP(logging.Discard()).fetchAS(context.Background(), srv.URL); err != nil {
			t.Fatalf("fetchAS: %v", err)
		}
	})
}

// Несовпадение issuer прерывает флоу до открытия браузера.
func TestHandleUnauthorizedIssuerMismatchDoesNotOpenBrowser(t *testing.T) {
	srv := httptest.NewServer(asMetadataHandler(map[string]any{
		"issuer":                 "https://evil.example",
		"authorization_endpoint": "https://a.example/authorize",
		"token_endpoint":         "https://a.example/token",
	}))
	defer srv.Close()

	opener := newFakeOpener()
	p := New(&config.Config{
		ServerURL: srv.URL + "/mcp", ConfigDir: t.TempDir(),
		AuthTimeout: time.Second, AllowHTTP: true,
	}, opener, logging.Discard())

	if err := p.HandleUnauthorized(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "issuer") {
		t.Fatalf("err = %v, want issuer error", err)
	}
	select {
	case u := <-opener.openedURL:
		t.Fatalf("opener called with %q", u)
	default:
	}
}

func TestDiscoveryPRMResourceCheck(t *testing.T) {
	tests := []struct {
		name      string
		resource  string
		serverURL string
		override  string
		wantErr   bool
		wantWarn  bool
	}{
		{name: "origin resource for /mcp server", resource: "https://mcp.example.com", serverURL: "https://mcp.example.com/mcp"},
		{name: "same path", resource: "https://mcp.example.com/mcp", serverURL: "https://mcp.example.com/mcp"},
		{name: "trailing slashes ignored", resource: "https://mcp.example.com/mcp/", serverURL: "https://mcp.example.com/mcp"},
		{name: "parent path", resource: "https://mcp.example.com/api", serverURL: "https://mcp.example.com/api/v1/mcp"},
		{name: "other host", resource: "https://other.example.com/mcp", serverURL: "https://mcp.example.com/mcp", wantErr: true},
		{name: "other scheme", resource: "http://mcp.example.com/mcp", serverURL: "https://mcp.example.com/mcp", wantErr: true},
		{name: "segment boundary", resource: "https://mcp.example.com/mcp", serverURL: "https://mcp.example.com/mcp-admin", wantErr: true},
		{name: "resource deeper than server", resource: "https://mcp.example.com/mcp/v2", serverURL: "https://mcp.example.com/mcp", wantErr: true},
		{name: "default https port equals none", resource: "https://mcp.example.com:443", serverURL: "https://mcp.example.com/mcp"},
		{name: "default http port equals none", resource: "http://mcp.example.com:80/mcp", serverURL: "http://mcp.example.com/mcp"},
		{name: "other port", resource: "https://mcp.example.com:8443/mcp", serverURL: "https://mcp.example.com/mcp", wantErr: true},
		{name: "scheme and host case-insensitive", resource: "HTTPS://MCP.Example.COM/mcp", serverURL: "https://mcp.example.com/mcp"},
		{name: "query ignored", resource: "https://mcp.example.com/mcp?x=1", serverURL: "https://mcp.example.com/mcp"},
		{name: "override skips check", resource: "https://other.example.com", serverURL: "https://mcp.example.com/mcp", override: "https://custom.example/api"},
		{name: "empty resource warns", resource: "", serverURL: "https://mcp.example.com/mcp", wantWarn: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var asHits atomic.Int64
			var asSrv *httptest.Server
			asSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				asHits.Add(1)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"issuer":                 asSrv.URL,
					"authorization_endpoint": asSrv.URL + "/authorize",
					"token_endpoint":         asSrv.URL + "/token",
				})
			}))
			defer asSrv.Close()
			prmSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"resource":              tc.resource,
					"authorization_servers": []string{asSrv.URL},
				})
			}))
			defer prmSrv.Close()

			log, buf := bufLogger()
			p := New(&config.Config{ServerURL: tc.serverURL, AllowHTTP: true}, newFakeOpener(), log)
			_, got, err := p.discover(context.Background(), prmSrv.URL+"/prm", tc.serverURL, tc.override)
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), tc.resource) {
					t.Fatalf("err = %v, want resource mismatch error", err)
				}
				if n := asHits.Load(); n != 0 {
					t.Fatalf("AS got %d requests after resource mismatch, want 0", n)
				}
				return
			}
			if err != nil {
				t.Fatalf("discover: %v", err)
			}
			if tc.override != "" && got != tc.override {
				t.Fatalf("resource = %q, want override %q", got, tc.override)
			}
			if warned := strings.Contains(buf.String(), "no resource"); warned != tc.wantWarn {
				t.Fatalf("warn logged = %v, want %v (log %q)", warned, tc.wantWarn, buf.String())
			}
		})
	}
}
