//go:build integration

package test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/dezer32/mcp-remote/internal/oauth"
)

const (
	defaultOpTimeout = 10 * time.Second
	recoveryTimeout  = 5 * time.Second
)

// ---------------------------------------------------------------------------
// Build helpers.

// projectRoot возвращает корень репозитория (родитель папки test/).
func projectRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller failed")
	}
	// .../<repo>/test/integration_test.go → .../<repo>
	return filepath.Dir(filepath.Dir(file))
}

// buildBinary компилирует mcp-remote в t.TempDir() и возвращает путь к бинарю.
func buildBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "mcp-remote")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = projectRoot(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build mcp-remote: %v\n%s", err, out)
	}
	return bin
}

// buildBrowserHelper компилирует тестовый browser_helper в t.TempDir().
func buildBrowserHelper(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "browser_helper")
	cmd := exec.Command("go", "build", "-tags=integration", "-o", bin, "./test/browser_helper")
	cmd.Dir = projectRoot(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build browser_helper: %v\n%s", err, out)
	}
	return bin
}

// ---------------------------------------------------------------------------
// Process helpers.

// testLogWriter перенаправляет stderr дочернего процесса в t.Logf, чтобы при
// падении было видно логи прокси. Работает корректно после завершения теста
// (через atomic-флаг — не пишет в t после FinalReport).
type testLogWriter struct {
	t      *testing.T
	prefix string
	mu     sync.Mutex
	dead   atomic.Bool
	buf    bytes.Buffer
}

func newTestLogWriter(t *testing.T, prefix string) *testLogWriter {
	w := &testLogWriter{t: t, prefix: prefix}
	t.Cleanup(func() { w.dead.Store(true) })
	return w
}

func (w *testLogWriter) Write(p []byte) (int, error) {
	if w.dead.Load() {
		return len(p), nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(p)
	for {
		i := bytes.IndexByte(w.buf.Bytes(), '\n')
		if i < 0 {
			break
		}
		line := string(w.buf.Bytes()[:i])
		w.buf.Next(i + 1)
		// Re-check inside loop: t.Logf на завершённом тесте паникует, поэтому
		// дешевле проверить ещё раз чем гонять t.Cleanup vs ongoing Write.
		if w.dead.Load() {
			return len(p), nil
		}
		w.t.Logf("%s%s", w.prefix, line)
	}
	return len(p), nil
}

// proxyHandle инкапсулирует запущенный процесс прокси.
type proxyHandle struct {
	stdin  io.WriteCloser
	stdout *bufio.Scanner
	stderr *lockedBuffer // копия stderr для проверок лога
	kill   func()
}

// lockedBuffer — потокобезопасный буфер.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// startProxy запускает бинарь mcp-remote с указанными args/env. stderr идёт
// в t.Logf. Стандартный buffer scanner расширен до 16 MiB.
func startProxy(t *testing.T, bin string, args []string, env []string) *proxyHandle {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), env...)
	stderr := &lockedBuffer{}
	cmd.Stderr = io.MultiWriter(newTestLogWriter(t, "[proxy] "), stderr)

	wIn, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	rOut, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start proxy: %v", err)
	}

	sc := bufio.NewScanner(rOut)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)

	var killed atomic.Bool
	kill := func() {
		if !killed.CompareAndSwap(false, true) {
			return
		}
		if cmd.Process != nil {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			done := make(chan struct{})
			go func() {
				_ = cmd.Wait()
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				_ = cmd.Process.Kill()
				<-done
			}
		}
		_ = wIn.Close()
	}
	t.Cleanup(kill)

	return &proxyHandle{
		stdin:  wIn,
		stdout: sc,
		stderr: stderr,
		kill:   kill,
	}
}

// ---------------------------------------------------------------------------
// JSON-RPC helpers.

func sendJSON(t *testing.T, w io.Writer, msg map[string]any) {
	t.Helper()
	if _, ok := msg["jsonrpc"]; !ok {
		msg["jsonrpc"] = "2.0"
	}
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	data = append(data, '\n')
	if _, err := w.Write(data); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
}

// readJSON читает одну строку из scanner с таймаутом и парсит её как JSON.
// scanner.Scan блокирующий, поэтому таймаут реализован через горутину.
func readJSON(t *testing.T, sc *bufio.Scanner, timeout time.Duration) map[string]any {
	t.Helper()
	type result struct {
		line []byte
		ok   bool
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		if sc.Scan() {
			b := sc.Bytes()
			cp := make([]byte, len(b))
			copy(cp, b)
			ch <- result{line: cp, ok: true}
			return
		}
		ch <- result{err: sc.Err()}
	}()
	select {
	case r := <-ch:
		if !r.ok {
			if r.err != nil {
				t.Fatalf("readJSON: scan error: %v", r.err)
			}
			t.Fatalf("readJSON: EOF on proxy stdout")
		}
		var out map[string]any
		if err := json.Unmarshal(r.line, &out); err != nil {
			t.Fatalf("readJSON: unmarshal %q: %v", string(r.line), err)
		}
		return out
	case <-time.After(timeout):
		t.Fatalf("readJSON: timeout after %s", timeout)
	}
	return nil
}

// readJSONByID повторяет readJSON до получения объекта c {"id": id}; ноотификации
// и server-initiated request-ы (без id или с другим id) логируются и пропускаются.
// Полезно когда proxy может проксировать promotion-уведомления вперёд response-а.
func readJSONByID(t *testing.T, sc *bufio.Scanner, id any, timeout time.Duration) map[string]any {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			t.Fatalf("readJSONByID(%v): timeout", id)
		}
		msg := readJSON(t, sc, remaining)
		if msgID, ok := msg["id"]; ok && equalIDs(msgID, id) {
			return msg
		}
		t.Logf("[proxy stdout] skipping non-matching message: %v", msg)
	}
}

// equalIDs сравнивает JSON-RPC id. json.Unmarshal даёт float64 для чисел —
// нормализуем int/float64 через число; всё прочее сводим к строке.
func equalIDs(a, b any) bool {
	if af, aok := toFloat(a); aok {
		if bf, bok := toFloat(b); bok {
			return af == bf
		}
	}
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

func toFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	}
	return 0, false
}

// initializeRequest — стандартный JSON-RPC initialize.
// "jsonrpc": "2.0" добавляет sendJSON, поэтому здесь его нет.
func initializeRequest(id int) map[string]any {
	return map[string]any{
		"id":     id,
		"method": "initialize",
		"params": map[string]any{
			"protocolVersion": "2025-03-26",
			"clientInfo": map[string]any{
				"name":    "integration-test",
				"version": "0.0.0",
			},
			"capabilities": map[string]any{},
		},
	}
}

func initializedNotification() map[string]any {
	return map[string]any{"method": "notifications/initialized"}
}

func toolsListRequest(id int) map[string]any {
	return map[string]any{"id": id, "method": "tools/list"}
}

func toolsCallEchoRequest(id int, text string) map[string]any {
	return map[string]any{
		"id":     id,
		"method": "tools/call",
		"params": map[string]any{
			"name":      "echo",
			"arguments": map[string]any{"text": text},
		},
	}
}

// resultMap извлекает result как map[string]any.
func resultMap(t *testing.T, msg map[string]any) map[string]any {
	t.Helper()
	if errObj, ok := msg["error"]; ok && errObj != nil {
		t.Fatalf("jsonrpc error in response: %v", errObj)
	}
	r, ok := msg["result"].(map[string]any)
	if !ok {
		t.Fatalf("response has no result map: %v", msg)
	}
	return r
}

// waitFor вызывает f в цикле с интервалом 50ms до тех пор, пока f не вернёт
// true, или пока не истечёт timeout.
func waitFor(timeout time.Duration, f func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if f() {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return f()
}

// ---------------------------------------------------------------------------
// Tests.

// TestIntegration_Basic — happy path: build → fake server → initialize →
// tools/list → tools/call.
func TestIntegration_Basic(t *testing.T) {
	bin := buildBinary(t)
	srv := NewFakeServer(t)
	defer srv.Close()

	cfgDir := t.TempDir()
	home := t.TempDir()
	h := startProxy(t, bin,
		[]string{"--allow-http", srv.URL + "/mcp"},
		[]string{
			"MCP_REMOTE_CONFIG_DIR=" + cfgDir,
			"HOME=" + home,
		},
	)

	// initialize.
	sendJSON(t, h.stdin, initializeRequest(1))
	resp := readJSONByID(t, h.stdout, 1, defaultOpTimeout)
	res := resultMap(t, resp)
	if pv, _ := res["protocolVersion"].(string); pv != "2025-03-26" {
		t.Fatalf("initialize: protocolVersion = %q, want %q", pv, "2025-03-26")
	}

	// notifications/initialized — ответа быть не должно.
	sendJSON(t, h.stdin, initializedNotification())

	// tools/list.
	sendJSON(t, h.stdin, toolsListRequest(2))
	resp = readJSONByID(t, h.stdout, 2, defaultOpTimeout)
	res = resultMap(t, resp)
	tools, ok := res["tools"].([]any)
	if !ok || len(tools) == 0 {
		t.Fatalf("tools/list: no tools in result: %v", res)
	}
	first, _ := tools[0].(map[string]any)
	if name, _ := first["name"].(string); name != "echo" {
		t.Fatalf("tools/list: first tool name = %q, want echo", name)
	}

	// tools/call name=echo args.text=hello.
	sendJSON(t, h.stdin, toolsCallEchoRequest(3, "hello"))
	resp = readJSONByID(t, h.stdout, 3, defaultOpTimeout)
	res = resultMap(t, resp)
	content, _ := res["content"].([]any)
	if len(content) == 0 {
		t.Fatalf("tools/call: empty content: %v", res)
	}
	c0, _ := content[0].(map[string]any)
	if got, _ := c0["text"].(string); got != "hello" {
		t.Fatalf("tools/call: content[0].text = %q, want hello", got)
	}

	// Проверка: сервер увидел MCP-Protocol-Version после initialize.
	if pv := srv.SeenProtocolVersion(); pv != "2025-03-26" {
		t.Fatalf("fakeServer.seenProtocolV = %q, want 2025-03-26", pv)
	}
}

// TestIntegration_SessionRecovery — после ExpireSession следующий запрос
// должен пройти recovery (re-initialize + retry) прозрачно.
func TestIntegration_SessionRecovery(t *testing.T) {
	bin := buildBinary(t)
	srv := NewFakeServer(t)
	defer srv.Close()

	cfgDir := t.TempDir()
	home := t.TempDir()
	h := startProxy(t, bin,
		[]string{"--allow-http", srv.URL + "/mcp"},
		[]string{
			"MCP_REMOTE_CONFIG_DIR=" + cfgDir,
			"HOME=" + home,
		},
	)

	sendJSON(t, h.stdin, initializeRequest(1))
	readJSONByID(t, h.stdout, 1, defaultOpTimeout)
	sendJSON(t, h.stdin, initializedNotification())

	// Первый tools/list — должен пройти.
	sendJSON(t, h.stdin, toolsListRequest(2))
	resp := readJSONByID(t, h.stdout, 2, defaultOpTimeout)
	resultMap(t, resp)

	if got := srv.InitializeCount(); got < 1 {
		t.Fatalf("after first initialize: initializeCount = %d, want >= 1", got)
	}

	srv.ExpireSession()

	// Второй tools/list — должен в итоге успешно вернуться после прозрачного recovery.
	sendJSON(t, h.stdin, toolsListRequest(3))
	resp = readJSONByID(t, h.stdout, 3, defaultOpTimeout+recoveryTimeout)
	resultMap(t, resp)

	if got := srv.InitializeCount(); got < 2 {
		t.Fatalf("after recovery: initializeCount = %d, want >= 2", got)
	}
}

// TestIntegration_StaticHeaderAuth — пользователь передал Authorization вручную;
// OAuth не должен запускаться.
func TestIntegration_StaticHeaderAuth(t *testing.T) {
	bin := buildBinary(t)
	srv := NewFakeOAuthServer(t)
	defer srv.Close()
	srv.GrantToken("hardcoded-token")

	cfgDir := t.TempDir()
	home := t.TempDir()

	// BROWSER=/usr/bin/false (или несуществующий путь) — если прокси попытается
	// открыть браузер, тест должен зафейлиться по таймауту.
	h := startProxy(t, bin,
		[]string{
			"--allow-http",
			srv.URL + "/mcp",
			"--header", "Authorization: Bearer hardcoded-token",
		},
		[]string{
			"MCP_REMOTE_CONFIG_DIR=" + cfgDir,
			"HOME=" + home,
			"BROWSER=/nonexistent/should-not-be-called",
		},
	)

	sendJSON(t, h.stdin, initializeRequest(1))
	resp := readJSONByID(t, h.stdout, 1, defaultOpTimeout)
	res := resultMap(t, resp)
	if pv, _ := res["protocolVersion"].(string); pv != "2025-03-26" {
		t.Fatalf("initialize: protocolVersion = %q, want 2025-03-26", pv)
	}
	sendJSON(t, h.stdin, initializedNotification())

	sendJSON(t, h.stdin, toolsListRequest(2))
	resp = readJSONByID(t, h.stdout, 2, defaultOpTimeout)
	resultMap(t, resp)
}

// TestIntegration_OAuth — полный OAuth-flow: PRM-discovery → DCR → authorize
// (через browser_helper) → token → retry initialize. По завершении должен
// существовать tokens.json в config_dir.
func TestIntegration_OAuth(t *testing.T) {
	bin := buildBinary(t)
	helper := buildBrowserHelper(t)

	srv := NewFakeOAuthServer(t)
	defer srv.Close()
	// Изначально требуемый токен пуст — сервер отвечает 401 + PRM-challenge.
	// browser_helper закроет 302→callback; /token переключит requireBearer.

	cfgDir := t.TempDir()
	home := t.TempDir()
	h := startProxy(t, bin,
		[]string{"--allow-http", srv.URL + "/mcp"},
		[]string{
			"BROWSER=" + helper,
			"MCP_REMOTE_CONFIG_DIR=" + cfgDir,
			"HOME=" + home,
		},
	)

	// OAuth полностью отрабатывает в фоне — initialize вернётся после grant-а.
	sendJSON(t, h.stdin, initializeRequest(1))
	resp := readJSONByID(t, h.stdout, 1, 30*time.Second)
	res := resultMap(t, resp)
	if pv, _ := res["protocolVersion"].(string); pv != "2025-03-26" {
		t.Fatalf("initialize: protocolVersion = %q, want 2025-03-26", pv)
	}
	sendJSON(t, h.stdin, initializedNotification())

	sendJSON(t, h.stdin, toolsListRequest(2))
	resp = readJSONByID(t, h.stdout, 2, defaultOpTimeout)
	resultMap(t, resp)

	// Должен быть создан tokens.json под config_dir/<server-hash>/tokens.json.
	if !waitFor(5*time.Second, func() bool { return hasTokensFile(cfgDir) }) {
		t.Fatalf("tokens.json not created under %s", cfgDir)
	}
}

// hasTokensFile рекурсивно ищет любой файл tokens.json под root.
func hasTokensFile(root string) bool {
	found := false
	_ = filepath.WalkDir(root, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() && strings.EqualFold(d.Name(), "tokens.json") {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

// TestIntegration_OAuthStaleGrant — «протухший grant»: в хранилище истёкший
// access и рабочий refresh_token, но ресурс отвергает любые токены, выданные
// refresh-ем. Прокси не должен упереться в refresh: после отказа он сам
// проходит полный флоу (browser_helper), и initialize возвращает result.
func TestIntegration_OAuthStaleGrant(t *testing.T) {
	bin := buildBinary(t)
	helper := buildBrowserHelper(t)

	srv := NewFakeOAuthServer(t)
	defer srv.Close()
	srv.SetRejectRefreshedTokens(true)

	serverURL := srv.URL + "/mcp"
	cfgDir := t.TempDir()
	st, err := oauth.NewStorage(cfgDir, serverURL)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	callback := "http://127.0.0.1:" + strconv.Itoa(freeTCPPort(t)) + "/callback"
	srv.RegisterClient("stale-client", []string{callback})
	if err := st.SaveClient(&oauth.ClientInfo{ClientID: "stale-client", RedirectURIs: []string{callback}, TokenEndpointAuthMethod: "none"}); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}
	if err := st.SaveMetadata(&oauth.AuthServerMetadata{
		Issuer:                srv.URL,
		AuthorizationEndpoint: srv.URL + "/authorize",
		TokenEndpoint:         srv.URL + "/token",
		RegistrationEndpoint:  srv.URL + "/register",
	}, serverURL); err != nil {
		t.Fatalf("SaveMetadata: %v", err)
	}
	if err := st.SaveTokens(&oauth.Tokens{
		AccessToken:  "expired-access",
		RefreshToken: "stale-refresh",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatalf("SaveTokens: %v", err)
	}

	h := startProxy(t, bin,
		[]string{"--allow-http", "--debug", serverURL},
		[]string{
			"BROWSER=" + helper,
			"MCP_REMOTE_CONFIG_DIR=" + cfgDir,
			"HOME=" + t.TempDir(),
		},
	)

	sendJSON(t, h.stdin, initializeRequest(1))
	resp := readJSONByID(t, h.stdout, 1, 30*time.Second)
	res := resultMap(t, resp)
	if pv, _ := res["protocolVersion"].(string); pv != "2025-03-26" {
		t.Fatalf("initialize: protocolVersion = %q, want 2025-03-26", pv)
	}

	// До браузера было два refresh: истёкший токен в Token() и первый 401.
	if n := srv.RefreshGrantCount(); n < 2 {
		t.Fatalf("refresh grants = %d, want >= 2", n)
	}
	log := h.stderr.String()
	iRefreshed := strings.Index(log, "token refreshed")
	iRejected := strings.Index(log, "token rejected after refresh, starting full authorization")
	if iRefreshed < 0 || iRejected < 0 || iRefreshed > iRejected {
		t.Fatalf("log must contain 'token refreshed' before 'token rejected after refresh':\n%s", log)
	}
	if !strings.Contains(log, "remote 401") || !strings.Contains(log, "error=invalid_token") {
		t.Fatalf("log has no 'remote 401' with error=invalid_token:\n%s", log)
	}
	for _, secret := range []string{"refreshed-token-", "stale-refresh", "expired-access"} {
		if strings.Contains(log, secret) {
			t.Fatalf("log contains token value %q", secret)
		}
	}
}

// TestIntegration_OAuthReusesRegisteredPort — повторная авторизация на
// строгом сервере: второй запуск после удаления tokens.json поднимает
// callback на зарегистрированном порту, и новая регистрация не нужна.
func TestIntegration_OAuthReusesRegisteredPort(t *testing.T) {
	bin := buildBinary(t)
	helper := buildBrowserHelper(t)

	srv := NewFakeOAuthServer(t)
	defer srv.Close()
	srv.SetStrictRedirectURI(true)

	cfgDir := t.TempDir()
	home := t.TempDir()
	run := func(name string) {
		t.Helper()
		h := startProxy(t, bin,
			[]string{"--allow-http", "--auth-timeout", "20s", srv.URL + "/mcp"},
			[]string{
				"BROWSER=" + helper,
				"MCP_REMOTE_CONFIG_DIR=" + cfgDir,
				"HOME=" + home,
			},
		)
		sendJSON(t, h.stdin, initializeRequest(1))
		resp := readJSONByID(t, h.stdout, 1, 30*time.Second)
		if _, ok := resp["result"]; !ok {
			t.Fatalf("%s: initialize = %v", name, resp)
		}
		h.kill()
	}

	run("first run")
	if n := srv.RegistrationCount(); n != 1 {
		t.Fatalf("registrations after first run = %d, want 1", n)
	}
	srv.GrantToken("") // ресурс снова требует авторизацию
	removed := 0
	_ = filepath.WalkDir(cfgDir, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && d.Name() == "tokens.json" {
			if os.Remove(path) == nil {
				removed++
			}
		}
		return nil
	})
	if removed != 1 {
		t.Fatalf("removed %d tokens.json files, want 1", removed)
	}

	run("second run")
	if n := srv.RegistrationCount(); n != 1 {
		t.Fatalf("registrations after second run = %d, want 1", n)
	}
}

// TestIntegration_OAuthTokenRejectedAfterAuthorization — ресурс отвергает
// любой токен, сохранённых токенов нет: браузер открывается ровно один раз, а
// клиент получает JSON-RPC ошибку с кодом ошибки сервера (invalid_token).
func TestIntegration_OAuthTokenRejectedAfterAuthorization(t *testing.T) {
	bin := buildBinary(t)
	helper := buildBrowserHelper(t)

	srv := NewFakeOAuthServer(t)
	defer srv.Close()
	srv.SetRejectAllTokens(true)

	h := startProxy(t, bin,
		[]string{"--allow-http", srv.URL + "/mcp"},
		[]string{
			"BROWSER=" + helper,
			"MCP_REMOTE_CONFIG_DIR=" + t.TempDir(),
			"HOME=" + t.TempDir(),
		},
	)

	sendJSON(t, h.stdin, initializeRequest(1))
	resp := readJSONByID(t, h.stdout, 1, 30*time.Second)
	if _, ok := resp["result"]; ok {
		t.Fatalf("initialize: got result, want error: %v", resp)
	}
	errObj, ok := resp["error"].(map[string]any)
	if !ok {
		t.Fatalf("initialize: no error object: %v", resp)
	}
	msg, _ := errObj["message"].(string)
	if !strings.Contains(msg, "token rejected right after authorization") || !strings.Contains(msg, "invalid_token") {
		t.Fatalf("error message = %q, want 'token rejected right after authorization' and 'invalid_token'", msg)
	}
	if n := srv.AuthorizeCount(); n != 1 {
		t.Fatalf("authorize hits = %d, want 1 (browser opened exactly once)", n)
	}
}

// freeTCPPort возвращает порт, который только что был свободен на 127.0.0.1.
func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}
