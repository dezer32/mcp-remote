package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
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
	calls     atomic.Int32
}

func newFakeOpener() *fakeOpener {
	return &fakeOpener{openedURL: make(chan string, 1)}
}

func (f *fakeOpener) Open(_ context.Context, u string) error {
	f.calls.Add(1)
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
	refreshCalls   int
	registerHit    bool
	expiresIn      int64 // ответ token endpoint
	denyRegister   bool
	skipDCRSupport bool
	// omitDCRRedirectURIs — ответ /register без redirect_uris.
	omitDCRRedirectURIs bool
}

type codeInfo struct {
	clientID    string
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
			"resource":              "https://mcp.example/server",
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
		resp := *ci
		if f.omitDCRRedirectURIs {
			resp.RedirectURIs = nil
		}
		_ = json.NewEncoder(w).Encode(&resp)
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
			f.refreshCalls++
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
		AllowHTTP:   true,
		ConfigDir:   t.TempDir(),
		AuthTimeout: 10 * time.Second,
	}
	p := New(cfg, opener, logging.Discard())

	done := make(chan error, 1)
	go func() {
		done <- handleUnauthorized(p, as.wwwAuthenticate())
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
		AllowHTTP:                 true,
		ConfigDir:                 t.TempDir(),
		AuthTimeout:               5 * time.Second,
		StaticOAuthClientInfoJSON: staticCI,
	}
	p := New(cfg, opener, logging.Discard())

	done := make(chan error, 1)
	go func() {
		done <- handleUnauthorized(p, as.wwwAuthenticate())
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
		AllowHTTP:   true,
		ConfigDir:   t.TempDir(),
		AuthTimeout: 5 * time.Second,
	}
	p := New(cfg, opener, logging.Discard())

	// прогон 1: полный flow.
	done := make(chan error, 1)
	go func() { done <- handleUnauthorized(p, as.wwwAuthenticate()) }()
	runUserAgent(t, <-opener.openedURL)
	if err := <-done; err != nil {
		t.Fatalf("initial auth: %v", err)
	}
	beforeTok, _ := p.Token(context.Background())

	// прогон 2: refresh. HandleUnauthorized должен использовать refresh_token и
	// НЕ вызвать opener.
	go func() { done <- handleUnauthorized(p, as.wwwAuthenticate()) }()
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
		AllowHTTP:   true,
		ConfigDir:   t.TempDir(),
		AuthTimeout: 5 * time.Second,
	}
	p := New(cfg, opener, logging.Discard())

	// первая полная авторизация
	done := make(chan error, 1)
	go func() { done <- handleUnauthorized(p, as.wwwAuthenticate()) }()
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
	go func() { done <- handleUnauthorized(p, as.wwwAuthenticate()) }()
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
		AllowHTTP:   true,
		ConfigDir:   t.TempDir(),
		AuthTimeout: 1 * time.Second,
	}
	p := New(cfg, opener, logging.Discard())

	err := handleUnauthorized(p, as.wwwAuthenticate())
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
			"resource":              "https://mcp.example/server",
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
		AllowHTTP:   true,
		ConfigDir:   t.TempDir(),
		AuthTimeout: 5 * time.Second,
	}
	p := New(cfg, opener, logging.Discard())

	www := `Bearer resource_metadata="` + srv.URL + `/.well-known/oauth-protected-resource"`
	done := make(chan error, 1)
	go func() { done <- handleUnauthorized(p, www) }()
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
		AllowHTTP:   true,
		ConfigDir:   t.TempDir(),
		AuthTimeout: 5 * time.Second,
	}
	p := New(cfg, opener, logging.Discard())

	// Полная авторизация.
	done := make(chan error, 1)
	go func() { done <- handleUnauthorized(p, as.wwwAuthenticate()) }()
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
	if err := handleUnauthorized(p, ""); err == nil || !strings.Contains(err.Error(), "ServerURL") {
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
	p := New(&config.Config{AllowHTTP: true}, &fakeOpener{}, logging.Discard())
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

// handleUnauthorized — вызов HandleUnauthorized так, как его делает httpmcp на
// первый 401 запроса: с текущим токеном провайдера и разрешённым refresh.
// Возвращает только ошибку — для тестов, которым не важен authorized.
func handleUnauthorized(p *Provider, www string) error {
	p.mu.Lock()
	_ = p.ensureLoadedLocked()
	rejected := ""
	if p.cachedTokens != nil {
		rejected = p.cachedTokens.AccessToken
	}
	p.mu.Unlock()
	_, err := p.HandleUnauthorized(context.Background(), www, rejected, true)
	return err
}

// --- решение refresh/authorize по цепочке запроса ---------------------------

// authorizeOnce проводит полный флоу (первый 401 без токенов) и возвращает
// выданный access-токен.
func authorizeOnce(t *testing.T, p *Provider, as *asFixture, opener *fakeOpener) string {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- handleUnauthorized(p, as.wwwAuthenticate()) }()
	select {
	case u := <-opener.openedURL:
		runUserAgent(t, u)
	case <-time.After(3 * time.Second):
		t.Fatal("opener was not called")
	}
	if err := <-done; err != nil {
		t.Fatalf("initial auth: %v", err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cachedTokens.AccessToken
}

func (f *asFixture) counters() (tokenCalls, refreshCalls, dcrCalls int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tokenCalls, f.refreshCalls, f.dcrCalls
}

func newChainProvider(t *testing.T, opener *fakeOpener, log *slog.Logger) *Provider {
	t.Helper()
	cfg := &config.Config{
		ServerURL:   "https://mcp.example/server",
		AllowHTTP:   true,
		ConfigDir:   t.TempDir(),
		AuthTimeout: 5 * time.Second,
	}
	return New(cfg, opener, log)
}

func TestHandleUnauthorizedReplacedTokenNoNetwork(t *testing.T) {
	t.Parallel()
	as := newASFixture(t)
	opener := newFakeOpener()
	p := newChainProvider(t, opener, logging.Discard())
	current := authorizeOnce(t, p, as, opener)
	tokenBefore, _, _ := as.counters()
	opensBefore := opener.calls.Load()

	for _, allowRefresh := range []bool{true, false} {
		authorized, err := p.HandleUnauthorized(context.Background(), as.wwwAuthenticate(), "AT-stale", allowRefresh)
		if err != nil || authorized {
			t.Fatalf("allowRefresh=%v: got (%v, %v), want (false, nil)", allowRefresh, authorized, err)
		}
	}
	tokenAfter, _, _ := as.counters()
	if tokenAfter != tokenBefore {
		t.Fatalf("token endpoint called %d times for replaced token", tokenAfter-tokenBefore)
	}
	if n := opener.calls.Load(); n != opensBefore {
		t.Fatalf("opener called %d times for replaced token", n-opensBefore)
	}
	tok, _ := p.Token(context.Background())
	if tok != current {
		t.Fatalf("token changed: %q -> %q", current, tok)
	}
}

func TestHandleUnauthorizedNoRefreshAfterRejected(t *testing.T) {
	t.Parallel()
	as := newASFixture(t)
	opener := newFakeOpener()
	p := newChainProvider(t, opener, logging.Discard())
	current := authorizeOnce(t, p, as, opener)
	_, refreshBefore, _ := as.counters()
	opensBefore := opener.calls.Load()

	type result struct {
		authorized bool
		err        error
	}
	done := make(chan result, 1)
	go func() {
		a, err := p.HandleUnauthorized(context.Background(), as.wwwAuthenticate(), current, false)
		done <- result{a, err}
	}()
	select {
	case u := <-opener.openedURL:
		runUserAgent(t, u)
	case <-time.After(3 * time.Second):
		t.Fatal("opener was not called with allowRefresh=false")
	}
	res := <-done
	if res.err != nil || !res.authorized {
		t.Fatalf("got (%v, %v), want (true, nil)", res.authorized, res.err)
	}
	if n := opener.calls.Load() - opensBefore; n != 1 {
		t.Fatalf("opener called %d times, want 1", n)
	}
	if _, refreshAfter, _ := as.counters(); refreshAfter != refreshBefore {
		t.Fatalf("refresh grant called %d times with allowRefresh=false", refreshAfter-refreshBefore)
	}
	tok, _ := p.Token(context.Background())
	if tok == current || tok == "" {
		t.Fatalf("token was not replaced by full flow: %q", tok)
	}
}

// syncBuffer — потокобезопасный буфер для захвата slog-вывода.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// Сценарий «протухший grant» на уровне провайдера: refresh проходит, выданный
// токен отвергнут, следующий вызов идёт в браузер. Лог показывает оба шага и
// не содержит значений токенов.
func TestHandleUnauthorizedStaleGrantLogs(t *testing.T) {
	t.Parallel()
	as := newASFixture(t)
	opener := newFakeOpener()
	var logBuf syncBuffer
	log := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	p := newChainProvider(t, opener, log)

	// secrets — все выданные access/refresh токены: ни один не должен попасть в лог.
	var secrets []string
	collectSecrets := func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.cachedTokens != nil {
			secrets = append(secrets, p.cachedTokens.AccessToken, p.cachedTokens.RefreshToken)
		}
	}

	first := authorizeOnce(t, p, as, opener)
	collectSecrets()
	authorized, err := p.HandleUnauthorized(context.Background(), as.wwwAuthenticate(), first, true)
	if err != nil || authorized {
		t.Fatalf("refresh step: got (%v, %v), want (false, nil)", authorized, err)
	}
	refreshed, _ := p.Token(context.Background())
	if refreshed == first {
		t.Fatal("refresh did not rotate token")
	}
	collectSecrets()

	done := make(chan error, 1)
	go func() {
		_, err := p.HandleUnauthorized(context.Background(), as.wwwAuthenticate(), refreshed, false)
		done <- err
	}()
	select {
	case u := <-opener.openedURL:
		runUserAgent(t, u)
	case <-time.After(3 * time.Second):
		t.Fatal("opener was not called after rejected refresh token")
	}
	if err := <-done; err != nil {
		t.Fatalf("full flow: %v", err)
	}
	collectSecrets()

	out := logBuf.String()
	iRefresh := strings.Index(out, "token refreshed")
	iRejected := strings.Index(out, "token rejected after refresh, starting full authorization")
	if iRefresh < 0 || iRejected < 0 || iRefresh > iRejected {
		t.Fatalf("expected 'token refreshed' before 'token rejected after refresh' in log:\n%s", out)
	}
	if len(secrets) != 6 {
		t.Fatalf("collected %d token values, want 6", len(secrets))
	}
	for _, secret := range secrets {
		if secret == "" || strings.Contains(out, secret) {
			t.Fatalf("log contains token value %q:\n%s", secret, out)
		}
	}
}

// --- callback-порт и повторная регистрация клиента -------------------------

// reauthEnv — провайдер с захватом debug-лога для сценариев повторной
// авторизации.
type reauthEnv struct {
	as     *asFixture
	opener *fakeOpener
	log    *syncBuffer
	p      *Provider
}

func newReauthEnv(t *testing.T, mutate func(as *asFixture, cfg *config.Config)) *reauthEnv {
	t.Helper()
	e := &reauthEnv{as: newASFixture(t), opener: newFakeOpener(), log: &syncBuffer{}}
	cfg := &config.Config{
		ServerURL:   "https://mcp.example/server",
		AllowHTTP:   true,
		ConfigDir:   t.TempDir(),
		AuthTimeout: 5 * time.Second,
	}
	if mutate != nil {
		mutate(e.as, cfg)
	}
	log := slog.New(slog.NewTextHandler(e.log, &slog.HandlerOptions{Level: slog.LevelDebug}))
	e.p = New(cfg, e.opener, log)
	return e
}

func (e *reauthEnv) saveClient(t *testing.T, ci *ClientInfo) {
	t.Helper()
	if err := e.p.storage.SaveClient(ci); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}
}

// authorize проводит полный флоу и возвращает параметры URL авторизации.
func (e *reauthEnv) authorize(t *testing.T) url.Values {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- handleUnauthorized(e.p, e.as.wwwAuthenticate()) }()
	var opened string
	select {
	case opened = <-e.opener.openedURL:
		runUserAgent(t, opened)
	case <-time.After(3 * time.Second):
		t.Fatal("opener was not called")
	}
	if err := <-done; err != nil {
		t.Fatalf("authorize: %v\nlog:\n%s", err, e.log.String())
	}
	u, err := url.Parse(opened)
	if err != nil {
		t.Fatalf("parse auth URL: %v", err)
	}
	return u.Query()
}

func callbackFor(port int) string {
	return "http://127.0.0.1:" + strconv.Itoa(port) + "/callback"
}

func TestReauthUsesRegisteredPort(t *testing.T) {
	t.Parallel()
	e := newReauthEnv(t, nil)
	saved := callbackFor(freePort(t))
	e.saveClient(t, &ClientInfo{ClientID: "saved", RedirectURIs: []string{saved}})

	q := e.authorize(t)
	if q.Get("redirect_uri") != saved || q.Get("client_id") != "saved" {
		t.Fatalf("redirect_uri=%q client_id=%q, want %q/saved", q.Get("redirect_uri"), q.Get("client_id"), saved)
	}
	if _, _, dcr := e.as.counters(); dcr != 0 {
		t.Fatalf("/register called %d times, want 0", dcr)
	}
}

func TestReauthBusyPortReregisters(t *testing.T) {
	t.Parallel()
	e := newReauthEnv(t, nil)
	busy := callbackFor(holdPort(t))
	e.saveClient(t, &ClientInfo{ClientID: "saved", RedirectURIs: []string{busy}})

	q := e.authorize(t)
	if _, _, dcr := e.as.counters(); dcr != 1 {
		t.Fatalf("/register called %d times, want 1", dcr)
	}
	stored, err := e.p.storage.LoadClient()
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	if stored.ClientID == "saved" || q.Get("client_id") != stored.ClientID {
		t.Fatalf("client_id: url=%q stored=%q, want new registration", q.Get("client_id"), stored.ClientID)
	}
	if q.Get("redirect_uri") == busy || !slices.Contains(stored.RedirectURIs, q.Get("redirect_uri")) {
		t.Fatalf("redirect_uri=%q, stored=%v", q.Get("redirect_uri"), stored.RedirectURIs)
	}
	if out := e.log.String(); !strings.Contains(out, "re-registering client") || !strings.Contains(out, "reason=port_unavailable") {
		t.Fatalf("log has no re-registration with reason:\n%s", out)
	}
}

func TestReauthClientWithoutRedirectURIsReregisters(t *testing.T) {
	t.Parallel()
	e := newReauthEnv(t, nil)
	e.saveClient(t, &ClientInfo{ClientID: "saved"})

	q := e.authorize(t)
	if _, _, dcr := e.as.counters(); dcr != 1 {
		t.Fatalf("/register called %d times, want 1", dcr)
	}
	stored, _ := e.p.storage.LoadClient()
	if stored == nil || !slices.Contains(stored.RedirectURIs, q.Get("redirect_uri")) {
		t.Fatalf("stored client = %+v, want redirect_uris with %q", stored, q.Get("redirect_uri"))
	}
	if out := e.log.String(); !strings.Contains(out, "reason=no_redirect_uris") {
		t.Fatalf("log has no reason=no_redirect_uris:\n%s", out)
	}
}

func TestReauthStaticClientNeverRegisters(t *testing.T) {
	t.Parallel()
	busy := callbackFor(holdPort(t))
	e := newReauthEnv(t, func(as *asFixture, cfg *config.Config) {
		as.denyRegister = true
		cfg.StaticOAuthClientInfoJSON, _ = json.Marshal(map[string]any{
			"client_id":     "static-1",
			"redirect_uris": []string{busy},
		})
	})

	q := e.authorize(t)
	if _, _, dcr := e.as.counters(); dcr != 0 {
		t.Fatalf("/register called %d times, want 0", dcr)
	}
	if q.Get("client_id") != "static-1" || q.Get("redirect_uri") == busy {
		t.Fatalf("client_id=%q redirect_uri=%q", q.Get("client_id"), q.Get("redirect_uri"))
	}
	out := e.log.String()
	if !strings.Contains(out, "level=WARN") || !strings.Contains(out, "callback_url="+q.Get("redirect_uri")) {
		t.Fatalf("log has no warn with callback URL:\n%s", out)
	}
}

func TestReauthNoRegistrationEndpointWarns(t *testing.T) {
	t.Parallel()
	e := newReauthEnv(t, func(as *asFixture, _ *config.Config) { as.skipDCRSupport = true })
	e.saveClient(t, &ClientInfo{ClientID: "saved", RedirectURIs: []string{callbackFor(holdPort(t))}})

	q := e.authorize(t)
	if q.Get("client_id") != "saved" {
		t.Fatalf("client_id=%q, want saved", q.Get("client_id"))
	}
	if _, _, dcr := e.as.counters(); dcr != 0 {
		t.Fatalf("/register called %d times, want 0", dcr)
	}
	if out := e.log.String(); !strings.Contains(out, "level=WARN") || !strings.Contains(out, "no registration_endpoint") {
		t.Fatalf("log has no warn:\n%s", out)
	}
	if tok, _ := e.p.Token(context.Background()); tok == "" {
		t.Fatal("flow did not issue a token")
	}
}

func TestDCRResponseWithoutRedirectURIsKeepsSent(t *testing.T) {
	t.Parallel()
	e := newReauthEnv(t, func(as *asFixture, _ *config.Config) { as.omitDCRRedirectURIs = true })

	q := e.authorize(t)
	stored, err := e.p.storage.LoadClient()
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	if len(stored.RedirectURIs) != 1 || stored.RedirectURIs[0] != q.Get("redirect_uri") {
		t.Fatalf("stored redirect_uris = %v, want [%s]", stored.RedirectURIs, q.Get("redirect_uri"))
	}
	if _, _, dcr := e.as.counters(); dcr != 1 {
		t.Fatalf("/register called %d times, want 1", dcr)
	}
}

// Сценарий «Параллельные запросы с одним протухшим токеном»: два 401 на один
// и тот же токен обрабатываются одновременно — refresh выполняется один раз,
// второй вызов видит уже заменённый токен.
func TestHandleUnauthorizedConcurrentSameTokenRefreshesOnce(t *testing.T) {
	t.Parallel()
	as := newASFixture(t)
	opener := newFakeOpener()
	p := newChainProvider(t, opener, logging.Discard())
	stale := authorizeOnce(t, p, as, opener)
	_, refreshBefore, _ := as.counters()
	opensBefore := opener.calls.Load()

	type result struct {
		authorized bool
		err        error
	}
	const n = 2
	start := make(chan struct{})
	results := make(chan result, n)
	for range n {
		go func() {
			<-start
			a, err := p.HandleUnauthorized(context.Background(), as.wwwAuthenticate(), stale, true)
			results <- result{a, err}
		}()
	}
	close(start)
	for range n {
		select {
		case r := <-results:
			if r.err != nil || r.authorized {
				t.Fatalf("got (%v, %v), want (false, nil)", r.authorized, r.err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("HandleUnauthorized hung")
		}
	}
	if _, refreshAfter, _ := as.counters(); refreshAfter-refreshBefore != 1 {
		t.Fatalf("refresh grants = %d, want 1", refreshAfter-refreshBefore)
	}
	if n := opener.calls.Load() - opensBefore; n != 0 {
		t.Fatalf("opener called %d times, want 0", n)
	}
	if tok, _ := p.Token(context.Background()); tok == stale || tok == "" {
		t.Fatalf("token was not replaced: %q", tok)
	}
}

// Явный порт перекрывает порт сохранённого клиента; DCR-клиент
// регистрируется заново с reason=explicit_port.
func TestReauthExplicitPortReregisters(t *testing.T) {
	t.Parallel()
	savedPort, explicitPort := freePort(t), freePort(t)
	e := newReauthEnv(t, func(_ *asFixture, cfg *config.Config) { cfg.Port = explicitPort })
	e.saveClient(t, &ClientInfo{ClientID: "saved", RedirectURIs: []string{callbackFor(savedPort)}})

	q := e.authorize(t)
	if got, want := q.Get("redirect_uri"), callbackFor(explicitPort); got != want {
		t.Fatalf("redirect_uri=%q, want %q", got, want)
	}
	if _, _, dcr := e.as.counters(); dcr != 1 {
		t.Fatalf("/register called %d times, want 1", dcr)
	}
	stored, err := e.p.storage.LoadClient()
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	if stored.ClientID == "saved" || q.Get("client_id") != stored.ClientID {
		t.Fatalf("client_id: url=%q stored=%q, want new registration", q.Get("client_id"), stored.ClientID)
	}
	if out := e.log.String(); !strings.Contains(out, "reason=explicit_port") {
		t.Fatalf("log has no reason=explicit_port:\n%s", out)
	}
}
