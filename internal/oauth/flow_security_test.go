package oauth

// Тесты hardening-проверок OAuth-флоу: небезопасные URL, транспортная
// политика эндпоинтов, issuer/resource, редиректы.

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dezer32/mcp-remote/internal/config"
	"github.com/dezer32/mcp-remote/internal/logging"
)

// errOpener — Opener, всегда возвращающий заданную ошибку.
type errOpener struct {
	err    error
	called chan string
}

func newErrOpener(err error) *errOpener {
	return &errOpener{err: err, called: make(chan string, 4)}
}

func (o *errOpener) Open(_ context.Context, u string) error {
	select {
	case o.called <- u:
	default:
	}
	return o.err
}

// captureStderr подменяет os.Stderr на pipe на время fn и возвращает то, что
// было записано. Нельзя вызывать из параллельных тестов.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	defer func() { os.Stderr = old }()

	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	_ = w.Close()
	return <-done
}

// Opener отказал из-за небезопасного URL: авторизация завершается ошибкой,
// URL не печатается в stderr, token endpoint не вызывается.
func TestHandleUnauthorizedUnsafeURLAbortsFlow(t *testing.T) {
	as := newASFixture(t)
	opener := newErrOpener(errUnsafeURL)

	cfg := &config.Config{
		ServerURL:   "https://mcp.example/server",
		ConfigDir:   t.TempDir(),
		AuthTimeout: 2 * time.Second,
		AllowHTTP:   true,
	}
	log, logBuf := bufLogger()
	p := New(cfg, opener, log)

	var err error
	stderr := captureStderr(t, func() {
		err = p.HandleUnauthorized(context.Background(), as.wwwAuthenticate())
	})
	if err == nil {
		t.Fatal("HandleUnauthorized: expected error")
	}
	if !errors.Is(err, errUnsafeURL) {
		t.Fatalf("err = %v, want errors.Is errUnsafeURL", err)
	}
	authorizeURL := as.srv.URL + "/authorize"
	if strings.Contains(stderr, "Open this URL") || strings.Contains(stderr, authorizeURL) {
		t.Fatalf("unsafe URL leaked to stderr: %q", stderr)
	}
	if strings.Contains(logBuf.String(), authorizeURL) {
		t.Fatalf("unsafe URL leaked to log: %q", logBuf.String())
	}
	as.mu.Lock()
	tokenCalls := as.tokenCalls
	as.mu.Unlock()
	if tokenCalls != 0 {
		t.Fatalf("token endpoint called %d times, want 0", tokenCalls)
	}
}

// Прочие ошибки opener-а — прежнее поведение: URL печатается в stderr, флоу
// продолжает ждать callback (здесь завершается по таймауту).
func TestHandleUnauthorizedOtherOpenerErrorPrintsURL(t *testing.T) {
	as := newASFixture(t)
	opener := newErrOpener(errors.New("no browser"))

	cfg := &config.Config{
		ServerURL:   "https://mcp.example/server",
		ConfigDir:   t.TempDir(),
		AuthTimeout: 300 * time.Millisecond,
		AllowHTTP:   true,
	}
	p := New(cfg, opener, logging.Discard())

	var err error
	stderr := captureStderr(t, func() {
		err = p.HandleUnauthorized(context.Background(), as.wwwAuthenticate())
	})
	if err == nil {
		t.Fatal("expected callback timeout error")
	}
	if errors.Is(err, errUnsafeURL) {
		t.Fatalf("unexpected errUnsafeURL: %v", err)
	}
	if !strings.Contains(stderr, "Open this URL to authorize: "+as.srv.URL+"/authorize") {
		t.Fatalf("stderr = %q, want authorize URL", stderr)
	}
}

// postToken и registerClient сами проверяют политику эндпоинтов: так
// отсекаются и метаданные, загруженные с диска.
func TestPostTokenAndRegisterRejectHTTPWithoutAllow(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.Error(w, "nope", http.StatusTeapot)
	}))
	defer srv.Close()

	p := New(&config.Config{}, newFakeOpener(), logging.Discard())

	if _, err := p.postToken(context.Background(), srv.URL+"/token", url.Values{"grant_type": {"refresh_token"}}); err == nil || !strings.Contains(err.Error(), "token endpoint") {
		t.Fatalf("postToken err = %v, want token endpoint policy error", err)
	}
	if _, err := p.registerClient(context.Background(), srv.URL+"/register", "http://127.0.0.1:1/callback"); err == nil || !strings.Contains(err.Error(), "registration endpoint") {
		t.Fatalf("registerClient err = %v, want registration endpoint policy error", err)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("server got %d requests, want 0", n)
	}
}

// metadata.json со старого запуска содержит http token_endpoint; без
// --allow-http refresh не уходит на этот адрес, токены очищаются, и
// HandleUnauthorized переходит к полному флоу с новым discovery.
func TestStoredHTTPTokenEndpointFallsBackToFullFlow(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.Error(w, "nope", http.StatusTeapot)
	}))
	defer srv.Close()

	cfg := &config.Config{
		// Порт 1 заведомо не слушается: новый discovery падает быстро.
		ServerURL:   "https://127.0.0.1:1/mcp",
		ConfigDir:   t.TempDir(),
		AuthTimeout: time.Second,
	}
	p := New(cfg, newFakeOpener(), logging.Discard())
	if p.storage == nil {
		t.Fatal("storage is nil")
	}
	if err := p.storage.SaveTokens(&Tokens{AccessToken: "old-at", RefreshToken: "old-rt"}); err != nil {
		t.Fatalf("SaveTokens: %v", err)
	}
	if err := p.storage.SaveClient(&ClientInfo{ClientID: "stored-client"}); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}
	if err := p.storage.SaveMetadata(&AuthServerMetadata{
		AuthorizationEndpoint: srv.URL + "/authorize",
		TokenEndpoint:         srv.URL + "/token",
	}, ""); err != nil {
		t.Fatalf("SaveMetadata: %v", err)
	}

	err := p.HandleUnauthorized(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "discovery") {
		t.Fatalf("err = %v, want full-flow discovery error", err)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("stored http token endpoint got %d requests, want 0", n)
	}
	if _, err := p.storage.LoadTokens(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("LoadTokens err = %v, want ErrNotExist (tokens cleared)", err)
	}
}

// callbackHostWarned прогоняет authorizeLocked с заданным --host и
// сообщает, было ли записано предупреждение о не-loopback callback.
func callbackHostWarned(t *testing.T, host string) bool {
	t.Helper()
	as := newASFixture(t)
	log, buf := bufLogger()
	p := New(&config.Config{
		ServerURL:   "https://mcp.example/server",
		ConfigDir:   t.TempDir(),
		AuthTimeout: 200 * time.Millisecond,
		AllowHTTP:   true,
		Host:        host,
	}, newErrOpener(errUnsafeURL), log) // opener сразу прерывает флоу после listen
	_ = p.HandleUnauthorized(context.Background(), as.wwwAuthenticate())
	return strings.Contains(buf.String(), "non-loopback")
}

func TestCallbackNonLoopbackHostWarns(t *testing.T) {
	if !callbackHostWarned(t, "0.0.0.0") {
		t.Fatal("no warning for --host 0.0.0.0")
	}
	if callbackHostWarned(t, "") {
		t.Fatal("unexpected warning for default host")
	}
	if callbackHostWarned(t, "127.0.0.1") {
		t.Fatal("unexpected warning for 127.0.0.1")
	}
}
