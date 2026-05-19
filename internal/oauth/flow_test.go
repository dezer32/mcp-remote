package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dezer32/mcp-remote/internal/config"
	"github.com/dezer32/mcp-remote/internal/logging"
)

// fakeOpener — тестовый Opener. Сохраняет URL и не делает HTTP-запрос сам.
// HTTP-запрос на authorize выполняет тестовая горутина, имитирующая user-agent.
type fakeOpener struct {
	openedURL chan string
}

func newFakeOpener() *fakeOpener {
	return &fakeOpener{openedURL: make(chan string, 1)}
}

func (f *fakeOpener) Open(_ context.Context, u string) error {
	select {
	case f.openedURL <- u:
	default:
	}
	return nil
}

// --- as fixture -------------------------------------------------------------

type asFixture struct {
	t      *testing.T
	srv    *httptest.Server
	mux    *http.ServeMux
	tokens atomic.Int64 // счётчик выданных tokens (для unique access_token)

	mu             sync.Mutex
	clients        map[string]*ClientInfo // by client_id
	codes          map[string]codeInfo    // by code
	refresh        map[string]string      // refresh_token -> client_id
	dcrCalls       int
	tokenCalls     int
	registerHit    bool
	expiresIn      int64 // ответ token endpoint
	denyRegister   bool
	skipDCRSupport bool
}

type codeInfo struct {
	clientID    string
	verifier    string
	challenge   string
	redirectURI string
	resource    string
}

func newASFixture(t *testing.T) *asFixture {
	t.Helper()
	f := &asFixture{
		t:         t,
		mux:       http.NewServeMux(),
		clients:   map[string]*ClientInfo{},
		codes:     map[string]codeInfo{},
		refresh:   map[string]string{},
		expiresIn: 3600,
	}
	f.srv = httptest.NewServer(f.mux)

	f.mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		m := map[string]any{
			"issuer":                 f.srv.URL,
			"authorization_endpoint": f.srv.URL + "/authorize",
			"token_endpoint":         f.srv.URL + "/token",
		}
		if !f.skipDCRSupport {
			m["registration_endpoint"] = f.srv.URL + "/register"
		}
		_ = json.NewEncoder(w).Encode(m)
	})

	f.mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":              f.srv.URL + "/resource",
			"authorization_servers": []string{f.srv.URL},
		})
	})

	f.mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.registerHit = true
		f.dcrCalls++
		if f.denyRegister {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		clientID := "client-" + randID()
		ci := &ClientInfo{ClientID: clientID, TokenEndpointAuthMethod: "none"}
		if uris, ok := body["redirect_uris"].([]any); ok {
			for _, u := range uris {
				if s, ok := u.(string); ok {
					ci.RedirectURIs = append(ci.RedirectURIs, s)
				}
			}
		}
		f.clients[clientID] = ci
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ci)
	})

	f.mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		f.mu.Lock()
		defer f.mu.Unlock()
		clientID := q.Get("client_id")
		if _, ok := f.clients[clientID]; !ok {
			// Если static client — добавим on-the-fly.
			f.clients[clientID] = &ClientInfo{ClientID: clientID}
		}
		code := "code-" + randID()
		f.codes[code] = codeInfo{
			clientID:    clientID,
			challenge:   q.Get("code_challenge"),
			redirectURI: q.Get("redirect_uri"),
			resource:    q.Get("resource"),
		}
		redirect := q.Get("redirect_uri") + "?code=" + url.QueryEscape(code) +
			"&state=" + url.QueryEscape(q.Get("state"))
		http.Redirect(w, r, redirect, http.StatusFound)
	})

	f.mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		defer f.mu.Unlock()
		f.tokenCalls++
		grant := r.PostFormValue("grant_type")
		switch grant {
		case "authorization_code":
			code := r.PostFormValue("code")
			ci, ok := f.codes[code]
			if !ok {
				http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
				return
			}
			delete(f.codes, code)
			verifier := r.PostFormValue("code_verifier")
			if challengeS256(verifier) != ci.challenge {
				http.Error(w, `{"error":"invalid_grant","error_description":"pkce mismatch"}`, http.StatusBadRequest)
				return
			}
			at, rt := f.newTokens(ci.clientID)
			f.writeToken(w, at, rt)
		case "refresh_token":
			rt := r.PostFormValue("refresh_token")
			cid, ok := f.refresh[rt]
			if !ok {
				http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
				return
			}
			delete(f.refresh, rt)
			at, newRT := f.newTokens(cid)
			f.writeToken(w, at, newRT)
		default:
			http.Error(w, `{"error":"unsupported_grant_type"}`, http.StatusBadRequest)
		}
	})

	t.Cleanup(func() {
		f.srv.Close()
	})
	return f
}

func (f *asFixture) newTokens(clientID string) (string, string) {
	n := strconv.FormatInt(f.tokens.Add(1), 10)
	at := "AT-" + clientID + "-" + n
	rt := "RT-" + clientID + "-" + n
	f.refresh[rt] = clientID
	return at, rt
}

func (f *asFixture) writeToken(w http.ResponseWriter, at, rt string) {
	w.Header().Set("Content-Type", "application/json")
	resp := map[string]any{
		"access_token":  at,
		"token_type":    "Bearer",
		"refresh_token": rt,
	}
	if f.expiresIn > 0 {
		resp["expires_in"] = f.expiresIn
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func (f *asFixture) wwwAuthenticate() string {
	return `Bearer realm="mcp", resource_metadata="` + f.srv.URL + `/.well-known/oauth-protected-resource"`
}

func randID() string {
	v, _ := generateState()
	return v[:8]
}

// runUserAgent имитирует браузер: получает opener URL и делает GET по нему,
// следуя редиректу на callback. Если authorize вернул редирект — Go
// http.Client follow-ит его по умолчанию.
func runUserAgent(t *testing.T, openedURL string) {
	t.Helper()
	cli := &http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := cli.Get(openedURL)
	if err != nil {
		t.Errorf("user-agent: GET %s: %v", openedURL, err)
		return
	}
	_ = resp.Body.Close()
}

// --- tests ------------------------------------------------------------------

func TestHandleUnauthorizedEndToEnd(t *testing.T) {
	t.Parallel()
	as := newASFixture(t)
	opener := newFakeOpener()

	cfg := &config.Config{
		ServerURL:   "https://mcp.example/server",
		ConfigDir:   t.TempDir(),
		AuthTimeout: 10 * time.Second,
	}
	p := New(cfg, opener, logging.Discard())

	done := make(chan error, 1)
	go func() {
		done <- p.HandleUnauthorized(context.Background(), as.wwwAuthenticate())
	}()

	select {
	case authURL := <-opener.openedURL:
		runUserAgent(t, authURL)
	case <-time.After(3 * time.Second):
		t.Fatalf("opener was never called")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("HandleUnauthorized: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("HandleUnauthorized did not complete")
	}

	tok, err := p.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok == "" || !strings.HasPrefix(tok, "AT-") {
		t.Fatalf("unexpected token: %q", tok)
	}

	// tokens.json создан.
	if p.storage == nil {
		t.Fatalf("storage nil")
	}
	if _, err := p.storage.LoadTokens(); err != nil {
		t.Fatalf("LoadTokens: %v", err)
	}
	// client.json создан (DCR).
	if _, err := p.storage.LoadClient(); err != nil {
		t.Fatalf("LoadClient: %v", err)
	}

	if !as.registerHit {
		t.Fatalf("expected DCR call")
	}
}

func TestHandleUnauthorizedStaticClientNoDCR(t *testing.T) {
	t.Parallel()
	as := newASFixture(t)
	as.denyRegister = true // DCR не должен вызываться
	opener := newFakeOpener()

	staticCI, _ := json.Marshal(map[string]any{"client_id": "static-1"})
	cfg := &config.Config{
		ServerURL:                 "https://mcp.example/server",
		ConfigDir:                 t.TempDir(),
		AuthTimeout:               5 * time.Second,
		StaticOAuthClientInfoJSON: staticCI,
	}
	p := New(cfg, opener, logging.Discard())

	done := make(chan error, 1)
	go func() {
		done <- p.HandleUnauthorized(context.Background(), as.wwwAuthenticate())
	}()

	select {
	case u := <-opener.openedURL:
		runUserAgent(t, u)
	case <-time.After(3 * time.Second):
		t.Fatalf("opener not called")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("HandleUnauthorized: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("HandleUnauthorized did not complete")
	}

	if as.dcrCalls != 0 {
		t.Fatalf("DCR called %d times, expected 0", as.dcrCalls)
	}
	tok, err := p.Token(context.Background())
	if err != nil || tok == "" {
		t.Fatalf("Token: %q err=%v", tok, err)
	}
	if !strings.Contains(tok, "static-1") {
		t.Fatalf("token = %s, expected to be issued for static-1", tok)
	}
}

func TestHandleUnauthorizedRefreshSuccess(t *testing.T) {
	t.Parallel()
	as := newASFixture(t)
	opener := newFakeOpener()
	cfg := &config.Config{
		ServerURL:   "https://mcp.example/server",
		ConfigDir:   t.TempDir(),
		AuthTimeout: 5 * time.Second,
	}
	p := New(cfg, opener, logging.Discard())

	// прогон 1: полный flow.
	done := make(chan error, 1)
	go func() { done <- p.HandleUnauthorized(context.Background(), as.wwwAuthenticate()) }()
	runUserAgent(t, <-opener.openedURL)
	if err := <-done; err != nil {
		t.Fatalf("initial auth: %v", err)
	}
	beforeTok, _ := p.Token(context.Background())

	// прогон 2: refresh. HandleUnauthorized должен использовать refresh_token и
	// НЕ вызвать opener.
	go func() { done <- p.HandleUnauthorized(context.Background(), as.wwwAuthenticate()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("refresh path: %v", err)
		}
	case u := <-opener.openedURL:
		t.Fatalf("opener was called during refresh: %s", u)
	case <-time.After(2 * time.Second):
		t.Fatalf("HandleUnauthorized hung")
	}
	afterTok, _ := p.Token(context.Background())
	if afterTok == beforeTok {
		t.Fatalf("token did not rotate after refresh: %s", afterTok)
	}
}

func TestHandleUnauthorizedRefreshFailFallsBackToFullFlow(t *testing.T) {
	t.Parallel()
	as := newASFixture(t)
	opener := newFakeOpener()
	cfg := &config.Config{
		ServerURL:   "https://mcp.example/server",
		ConfigDir:   t.TempDir(),
		AuthTimeout: 5 * time.Second,
	}
	p := New(cfg, opener, logging.Discard())

	// первая полная авторизация
	done := make(chan error, 1)
	go func() { done <- p.HandleUnauthorized(context.Background(), as.wwwAuthenticate()) }()
	runUserAgent(t, <-opener.openedURL)
	if err := <-done; err != nil {
		t.Fatalf("initial: %v", err)
	}

	// портим refresh-token в storage и сбрасываем кэш в Provider.
	p.mu.Lock()
	p.cachedTokens.RefreshToken = "BROKEN"
	_ = p.storage.SaveTokens(p.cachedTokens)
	p.mu.Unlock()

	// HandleUnauthorized: refresh упадёт → full flow → opener будет вызван
	go func() { done <- p.HandleUnauthorized(context.Background(), as.wwwAuthenticate()) }()
	select {
	case u := <-opener.openedURL:
		runUserAgent(t, u)
	case <-time.After(3 * time.Second):
		t.Fatalf("opener was not called for fallback")
	}
	if err := <-done; err != nil {
		t.Fatalf("HandleUnauthorized: %v", err)
	}
}

func TestHandleUnauthorizedNoDCRNoStatic(t *testing.T) {
	t.Parallel()
	as := newASFixture(t)
	as.skipDCRSupport = true // metadata без registration_endpoint
	opener := newFakeOpener()
	cfg := &config.Config{
		ServerURL:   "https://mcp.example/server",
		ConfigDir:   t.TempDir(),
		AuthTimeout: 1 * time.Second,
	}
	p := New(cfg, opener, logging.Discard())

	err := p.HandleUnauthorized(context.Background(), as.wwwAuthenticate())
	if err == nil {
		t.Fatalf("expected error about no DCR and no static client")
	}
	if !strings.Contains(err.Error(), "DCR") && !strings.Contains(err.Error(), "client") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHandleUnauthorizedCallbackError(t *testing.T) {
	t.Parallel()
	// Минимальный AS, у которого authorize всегда редиректит с error.
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":              "https://api/resource",
			"authorization_servers": []string{srv.URL},
		})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint":         srv.URL + "/token",
			"registration_endpoint":  srv.URL + "/register",
		})
	})
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"client_id": "cid"})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		redirect := q.Get("redirect_uri") + "?error=access_denied&error_description=user%20rejected" +
			"&state=" + url.QueryEscape(q.Get("state"))
		http.Redirect(w, r, redirect, http.StatusFound)
	})

	opener := newFakeOpener()
	cfg := &config.Config{
		ServerURL:   "https://mcp.example/server",
		ConfigDir:   t.TempDir(),
		AuthTimeout: 5 * time.Second,
	}
	p := New(cfg, opener, logging.Discard())

	www := `Bearer resource_metadata="` + srv.URL + `/.well-known/oauth-protected-resource"`
	done := make(chan error, 1)
	go func() { done <- p.HandleUnauthorized(context.Background(), www) }()
	select {
	case u := <-opener.openedURL:
		runUserAgent(t, u)
	case <-time.After(3 * time.Second):
		t.Fatalf("opener not called")
	}
	err := <-done
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "access_denied") {
		t.Fatalf("error = %v, want access_denied", err)
	}
}

func TestTokenExpiryAndAutoRefresh(t *testing.T) {
	t.Parallel()
	as := newASFixture(t)
	opener := newFakeOpener()
	cfg := &config.Config{
		ServerURL:   "https://mcp.example/server",
		ConfigDir:   t.TempDir(),
		AuthTimeout: 5 * time.Second,
	}
	p := New(cfg, opener, logging.Discard())

	// Полная авторизация.
	done := make(chan error, 1)
	go func() { done <- p.HandleUnauthorized(context.Background(), as.wwwAuthenticate()) }()
	runUserAgent(t, <-opener.openedURL)
	if err := <-done; err != nil {
		t.Fatalf("auth: %v", err)
	}

	// Принудительно делаем токен просроченным.
	p.mu.Lock()
	p.cachedTokens.ExpiresAt = time.Now().Add(-time.Minute)
	_ = p.storage.SaveTokens(p.cachedTokens)
	prevTok := p.cachedTokens.AccessToken
	p.mu.Unlock()

	tok, err := p.Token(context.Background())
	if err != nil {
		t.Fatalf("Token after expiry: %v", err)
	}
	if tok == "" {
		t.Fatalf("expected refreshed token, got empty")
	}
	if tok == prevTok {
		t.Fatalf("token did not change after refresh")
	}
}

func TestTokenNoTokensYet(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{
		ServerURL: "https://mcp.example/server",
		ConfigDir: t.TempDir(),
	}
	p := New(cfg, newFakeOpener(), logging.Discard())
	tok, err := p.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok != "" {
		t.Fatalf("expected empty token, got %q", tok)
	}
}

func TestProviderImplementsOpenerAndTokenProvider(t *testing.T) {
	t.Parallel()
	// compile-time: тип Provider реализует TokenProvider (проверяется в main.go).
	// Здесь — просто smoke-проверка, что методы реальны.
	cfg := &config.Config{}
	p := New(cfg, DefaultOpener{}, logging.Discard())
	if _, err := p.Token(context.Background()); err != nil {
		t.Fatalf("Token on empty cfg: %v", err)
	}
	// HandleUnauthorized с пустым ServerURL ожидаемо вернёт ошибку.
	if err := p.HandleUnauthorized(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "ServerURL") {
		t.Fatalf("unexpected err: %v", err)
	}
}

func TestNewWithBadStaticClientInfoIsTolerated(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{
		ServerURL:                 "https://mcp.example/server",
		ConfigDir:                 t.TempDir(),
		StaticOAuthClientInfoJSON: []byte("not-json"),
	}
	p := New(cfg, newFakeOpener(), logging.Discard())
	if p.cachedClient != nil {
		t.Fatalf("expected cachedClient nil for invalid static JSON")
	}
}

func TestBuildAuthorizeURLContainsRequiredParams(t *testing.T) {
	t.Parallel()
	meta := &AuthServerMetadata{
		AuthorizationEndpoint: "https://as/auth",
		ScopesSupported:       []string{"a", "b"},
	}
	ci := &ClientInfo{ClientID: "cid"}
	u := buildAuthorizeURL(meta, ci, "http://127.0.0.1:9/callback", "CHAL", "STATE", "RES")
	parsed, err := url.Parse(u)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	q := parsed.Query()
	check := map[string]string{
		"response_type":         "code",
		"client_id":             "cid",
		"redirect_uri":          "http://127.0.0.1:9/callback",
		"code_challenge":        "CHAL",
		"code_challenge_method": "S256",
		"state":                 "STATE",
		"resource":              "RES",
	}
	for k, want := range check {
		if got := q.Get(k); got != want {
			t.Errorf("query[%q] = %q, want %q", k, got, want)
		}
	}
	if q.Get("scope") != "a b" {
		t.Errorf("scope = %q", q.Get("scope"))
	}
}

func TestPostTokenErrorPath(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
	}))
	defer srv.Close()
	p := New(&config.Config{}, &fakeOpener{}, logging.Discard())
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	_, err := p.postToken(context.Background(), srv.URL, form)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Fatalf("err = %v", err)
	}
}

// Concurrent Token calls должны быть безопасны (под -race).
func TestTokenConcurrentSafe(t *testing.T) {
	t.Parallel()
	p := New(&config.Config{}, DefaultOpener{}, logging.Discard())
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = p.Token(context.Background())
		}()
	}
	wg.Wait()
}
