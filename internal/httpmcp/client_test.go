package httpmcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dezer32/mcp-remote/internal/config"
	"github.com/dezer32/mcp-remote/internal/jsonrpc"
	"github.com/dezer32/mcp-remote/internal/logging"
	"github.com/dezer32/mcp-remote/internal/proxy"
)

// fakeTP — inline TokenProvider для тестов.
type fakeTP struct {
	mu             sync.Mutex
	token          string
	tokenErr       error
	onUnauth       func(ctx context.Context, www string) error
	unauthCalled   int
	lastUnauthArg  string
	tokenCallCount int
}

func (f *fakeTP) Token(ctx context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokenCallCount++
	return f.token, f.tokenErr
}

func (f *fakeTP) HandleUnauthorized(ctx context.Context, www string) error {
	f.mu.Lock()
	f.unauthCalled++
	f.lastUnauthArg = www
	cb := f.onUnauth
	f.mu.Unlock()
	if cb != nil {
		return cb(ctx, www)
	}
	return nil
}

func (f *fakeTP) snapshot() (int, string, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.unauthCalled, f.lastUnauthArg, f.tokenCallCount
}

// newClient — фабрика для типовых тестов.
func newClient(t *testing.T, serverURL string, tp TokenProvider, headers ...config.Header) *Client {
	t.Helper()
	cfg := &config.Config{ServerURL: serverURL, Headers: headers}
	c, err := New(cfg, tp, logging.Discard())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// notification — простой helper.
func notification(method string) jsonrpc.Message {
	return jsonrpc.Message{JSONRPC: jsonrpc.Version, Method: method}
}

// request — request с id.
func request(id int, method string) jsonrpc.Message {
	idRaw, _ := json.Marshal(id)
	return jsonrpc.Message{JSONRPC: jsonrpc.Version, ID: idRaw, Method: method}
}

// response — response на id.
func responseMsg(id int, result string) jsonrpc.Message {
	idRaw, _ := json.Marshal(id)
	res, _ := json.Marshal(result)
	return jsonrpc.Message{JSONRPC: jsonrpc.Version, ID: idRaw, Result: res}
}

// collect собирает все элементы канала с timeout.
func collect(t *testing.T, ch <-chan proxy.MessageOrError, timeout time.Duration) []proxy.MessageOrError {
	t.Helper()
	var got []proxy.MessageOrError
	deadline := time.After(timeout)
	for {
		select {
		case moe, ok := <-ch:
			if !ok {
				return got
			}
			got = append(got, moe)
		case <-deadline:
			t.Fatalf("timeout collecting from channel after %d items", len(got))
			return nil
		}
	}
}

// --- 1. POST notification → 202 ---
func TestSend_Notification202(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("unexpected method: %s", r.Method)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	c := newClient(t, srv.URL, nil)
	ch, err := c.Send(context.Background(), notification("ping"))
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	got := collect(t, ch, 2*time.Second)
	if len(got) != 0 {
		t.Fatalf("expected 0 items, got %d: %+v", len(got), got)
	}
}

// --- 2. POST request → 200 application/json (single) ---
func TestSend_OK_JSON_Single(t *testing.T) {
	resp := responseMsg(1, "pong")
	body, _ := jsonrpc.Encode(resp)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(body)
	}))
	defer srv.Close()
	c := newClient(t, srv.URL, nil)
	ch, err := c.Send(context.Background(), request(1, "ping"))
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	got := collect(t, ch, 2*time.Second)
	if len(got) != 1 {
		t.Fatalf("expected 1 item, got %d", len(got))
	}
	if got[0].Err != nil {
		t.Fatalf("unexpected err: %v", got[0].Err)
	}
	if string(got[0].Msg.ID) != "1" {
		t.Errorf("id mismatch: %s", got[0].Msg.ID)
	}
}

// --- 3. POST request → 200 application/json (batch array) ---
func TestSend_OK_JSON_Batch(t *testing.T) {
	body := []byte(`[
		{"jsonrpc":"2.0","id":1,"result":"a"},
		{"jsonrpc":"2.0","id":2,"result":"b"}
	]`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(body)
	}))
	defer srv.Close()
	c := newClient(t, srv.URL, nil)
	ch, _ := c.Send(context.Background(), request(1, "ping"))
	got := collect(t, ch, 2*time.Second)
	if len(got) != 2 {
		t.Fatalf("expected 2 items, got %d", len(got))
	}
	if string(got[0].Msg.ID) != "1" || string(got[1].Msg.ID) != "2" {
		t.Errorf("ordering broken: %s %s", got[0].Msg.ID, got[1].Msg.ID)
	}
}

// --- 4. POST request → 200 SSE (single event) ---
func TestSend_OK_SSE_Single(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		fmt.Fprintf(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"x\"}\n\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}))
	defer srv.Close()
	c := newClient(t, srv.URL, nil)
	ch, _ := c.Send(context.Background(), request(1, "ping"))
	got := collect(t, ch, 2*time.Second)
	if len(got) != 1 {
		t.Fatalf("expected 1 item, got %d: %+v", len(got), got)
	}
	if got[0].Err != nil {
		t.Fatalf("err: %v", got[0].Err)
	}
}

// --- 5. POST → 200 SSE с batched data ---
func TestSend_OK_SSE_BatchedData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w,
			"data: [{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"a\"},{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":\"b\"}]\n\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}))
	defer srv.Close()
	c := newClient(t, srv.URL, nil)
	ch, _ := c.Send(context.Background(), request(1, "ping"))
	got := collect(t, ch, 2*time.Second)
	if len(got) != 2 {
		t.Fatalf("expected 2 items, got %d", len(got))
	}
}

// --- 6. POST → 200 SSE multi-line data ---
func TestSend_OK_SSE_MultiLineData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"jsonrpc\":\"2.0\",\"id\":1,\ndata: \"result\":\"ok\"}\n\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}))
	defer srv.Close()
	c := newClient(t, srv.URL, nil)
	ch, _ := c.Send(context.Background(), request(1, "ping"))
	got := collect(t, ch, 2*time.Second)
	if len(got) != 1 {
		t.Fatalf("expected 1 item, got %d: %+v", len(got), got)
	}
	if got[0].Err != nil {
		t.Fatalf("err: %v", got[0].Err)
	}
}

// --- 7. SSE с комментами ---
func TestSend_OK_SSE_Comments(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, ":keep-alive\n\n:another\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"x\"}\n\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}))
	defer srv.Close()
	c := newClient(t, srv.URL, nil)
	ch, _ := c.Send(context.Background(), request(1, "ping"))
	got := collect(t, ch, 2*time.Second)
	if len(got) != 1 {
		t.Fatalf("expected 1, got %d", len(got))
	}
}

// --- 8. POST → 401 → HandleUnauthorized → retry → 200 ---
func TestSend_401_Recover(t *testing.T) {
	var calls int32
	resp := responseMsg(1, "ok")
	body, _ := jsonrpc.Encode(resp)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="x"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(body)
	}))
	defer srv.Close()

	tp := &fakeTP{}
	c := newClient(t, srv.URL, tp)
	ch, _ := c.Send(context.Background(), request(1, "ping"))
	got := collect(t, ch, 2*time.Second)
	if len(got) != 1 || got[0].Err != nil {
		t.Fatalf("expected single msg, got %+v", got)
	}
	uc, arg, _ := tp.snapshot()
	if uc != 1 {
		t.Errorf("unauthCalled=%d", uc)
	}
	if arg != `Bearer realm="x"` {
		t.Errorf("www-authenticate arg mismatch: %q", arg)
	}
}

// --- 9. POST → 401 → success TP → retry → 401 (no double-retry) ---
func TestSend_401_RetryFails(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("WWW-Authenticate", "Bearer")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	tp := &fakeTP{}
	c := newClient(t, srv.URL, tp)
	ch, _ := c.Send(context.Background(), request(1, "ping"))
	got := collect(t, ch, 2*time.Second)
	if len(got) != 1 || got[0].Err == nil {
		t.Fatalf("expected single err, got %+v", got)
	}
	uc, _, _ := tp.snapshot()
	if uc != 1 {
		t.Errorf("unauthCalled=%d, want 1", uc)
	}
	if n := atomic.LoadInt32(&calls); n != 2 {
		t.Errorf("server hits=%d, want 2", n)
	}
}

// --- 10. POST → 401 без WWW-Authenticate ---
func TestSend_401_NoChallenge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	tp := &fakeTP{onUnauth: func(ctx context.Context, www string) error {
		if www != "" {
			return fmt.Errorf("expected empty, got %q", www)
		}
		return errors.New("no challenge")
	}}
	c := newClient(t, srv.URL, tp)
	ch, _ := c.Send(context.Background(), request(1, "ping"))
	got := collect(t, ch, 2*time.Second)
	if len(got) != 1 || got[0].Err == nil {
		t.Fatalf("expected err, got %+v", got)
	}
	_, arg, _ := tp.snapshot()
	if arg != "" {
		t.Errorf("arg=%q want empty", arg)
	}
}

// --- 11. POST → 404 после сохранённого sessionID → ErrSessionLost ---
func TestSend_404_SessionLost(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		if n == 1 {
			w.Header().Set("Mcp-Session-Id", "sess-abc")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			b, _ := jsonrpc.Encode(responseMsg(1, "ok"))
			w.Write(b)
			return
		}
		// Sessionful client now expects session, but we 404.
		if r.Header.Get("Mcp-Session-Id") != "sess-abc" {
			t.Errorf("missing session header on second call")
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	c := newClient(t, srv.URL, nil)
	ch, _ := c.Send(context.Background(), request(1, "init"))
	if got := collect(t, ch, 2*time.Second); len(got) != 1 {
		t.Fatalf("initial send: got %d items", len(got))
	}
	ch2, _ := c.Send(context.Background(), request(2, "next"))
	got := collect(t, ch2, 2*time.Second)
	if len(got) != 1 {
		t.Fatalf("expected 1 item, got %d", len(got))
	}
	if !errors.Is(got[0].Err, proxy.ErrSessionLost) {
		t.Fatalf("expected ErrSessionLost, got %v", got[0].Err)
	}
}

// --- 12. Mcp-Session-Id из 200 response сохраняется ---
func TestSend_SessionIDPersisted(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		if n == 1 {
			if r.Header.Get("Mcp-Session-Id") != "" {
				t.Errorf("first request has session id: %s", r.Header.Get("Mcp-Session-Id"))
			}
			w.Header().Set("Mcp-Session-Id", "sess-42")
		} else {
			if got := r.Header.Get("Mcp-Session-Id"); got != "sess-42" {
				t.Errorf("second request session id=%q", got)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		b, _ := jsonrpc.Encode(responseMsg(int(n), "ok"))
		w.Write(b)
	}))
	defer srv.Close()
	c := newClient(t, srv.URL, nil)
	ch1, _ := c.Send(context.Background(), request(1, "init"))
	collect(t, ch1, 2*time.Second)
	ch2, _ := c.Send(context.Background(), request(2, "second"))
	collect(t, ch2, 2*time.Second)
	if c.session.getSessionID() != "sess-42" {
		t.Errorf("sessionID=%q", c.session.getSessionID())
	}
}

// --- 13. MCP-Protocol-Version появляется только после SetProtocolVersion ---
func TestSend_ProtocolVersionHeader(t *testing.T) {
	var hits int32
	var lastPV atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		lastPV.Store(r.Header.Get("MCP-Protocol-Version"))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		b, _ := jsonrpc.Encode(responseMsg(1, "ok"))
		w.Write(b)
	}))
	defer srv.Close()
	c := newClient(t, srv.URL, nil)
	ch, _ := c.Send(context.Background(), request(1, "init"))
	collect(t, ch, 2*time.Second)
	if pv, _ := lastPV.Load().(string); pv != "" {
		t.Errorf("first request had MCP-Protocol-Version=%q", pv)
	}
	c.SetProtocolVersion("2025-03-26")
	ch2, _ := c.Send(context.Background(), request(2, "next"))
	collect(t, ch2, 2*time.Second)
	if pv, _ := lastPV.Load().(string); pv != "2025-03-26" {
		t.Errorf("second request MCP-Protocol-Version=%q", pv)
	}
}

// --- 14. Listen → 405 → пустой chan, close без error ---
func TestListen_405(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("method=%s", r.Method)
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer srv.Close()
	c := newClient(t, srv.URL, nil)
	ch, err := c.Listen(context.Background())
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	got := collect(t, ch, 2*time.Second)
	if len(got) != 0 {
		t.Fatalf("expected 0, got %+v", got)
	}
}

// --- 15. Listen → 200 SSE → reconnect on disconnect → Last-Event-ID ---
func TestListen_Reconnect_LastEventID(t *testing.T) {
	var connects int32
	lastEventIDCh := make(chan string, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&connects, 1)
		lastEventIDCh <- r.Header.Get("Last-Event-ID")
		w.Header().Set("Content-Type", "text/event-stream")
		f, _ := w.(http.Flusher)
		if n == 1 {
			fmt.Fprint(w, "id: 7\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"x\"}\n\n")
			if f != nil {
				f.Flush()
			}
			// Close stream — should reconnect.
			return
		}
		// Second connect: emit then keep open until test cancels.
		fmt.Fprint(w, "id: 8\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":\"y\"}\n\n")
		if f != nil {
			f.Flush()
		}
		<-r.Context().Done()
	}))
	defer srv.Close()
	c := newClient(t, srv.URL, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, _ := c.Listen(ctx)

	// Collect 2 messages, then cancel.
	var got []proxy.MessageOrError
	timeout := time.After(10 * time.Second)
loop:
	for len(got) < 2 {
		select {
		case moe, ok := <-ch:
			if !ok {
				break loop
			}
			got = append(got, moe)
		case <-timeout:
			t.Fatalf("timeout waiting messages: got %d", len(got))
		}
	}
	cancel()
	// Drain
	for range ch {
	}
	if len(got) < 2 {
		t.Fatalf("expected 2 msgs, got %d", len(got))
	}
	// Check Last-Event-ID was sent on second connect.
	close(lastEventIDCh)
	var ids []string
	for s := range lastEventIDCh {
		ids = append(ids, s)
	}
	if len(ids) < 2 {
		t.Fatalf("ids=%v", ids)
	}
	if ids[0] != "" {
		t.Errorf("first connect Last-Event-ID=%q, want empty", ids[0])
	}
	if ids[1] != "7" {
		t.Errorf("second connect Last-Event-ID=%q, want 7", ids[1])
	}
}

// --- 16. CheckRedirect: cross-origin блочится ---
func TestSend_RedirectCrossOriginBlocked(t *testing.T) {
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("second server should not be reached")
	}))
	defer srv2.Close()
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv2.URL, http.StatusFound)
	}))
	defer srv1.Close()
	c := newClient(t, srv1.URL, nil)
	ch, _ := c.Send(context.Background(), request(1, "ping"))
	got := collect(t, ch, 2*time.Second)
	if len(got) != 1 || got[0].Err == nil {
		t.Fatalf("expected err, got %+v", got)
	}
	if !strings.Contains(got[0].Err.Error(), "cross-origin") {
		t.Errorf("want cross-origin err, got %v", got[0].Err)
	}
}

// --- 17. CheckRedirect: same-origin до 5 хопов ok (4 редиректа + 200) ---
func TestSend_RedirectSameOriginOK(t *testing.T) {
	var hops int32
	mux := http.NewServeMux()
	var serverURL string
	mux.HandleFunc("/r1", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hops, 1)
		http.Redirect(w, r, serverURL+"/r2", http.StatusFound)
	})
	mux.HandleFunc("/r2", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hops, 1)
		http.Redirect(w, r, serverURL+"/r3", http.StatusFound)
	})
	mux.HandleFunc("/r3", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hops, 1)
		http.Redirect(w, r, serverURL+"/r4", http.StatusFound)
	})
	mux.HandleFunc("/r4", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hops, 1)
		http.Redirect(w, r, serverURL+"/final", http.StatusFound)
	})
	mux.HandleFunc("/final", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		b, _ := jsonrpc.Encode(responseMsg(1, "ok"))
		w.Write(b)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	serverURL = srv.URL
	cfg := &config.Config{ServerURL: srv.URL + "/r1"}
	c, _ := New(cfg, nil, logging.Discard())
	ch, _ := c.Send(context.Background(), request(1, "ping"))
	got := collect(t, ch, 2*time.Second)
	if len(got) != 1 || got[0].Err != nil {
		t.Fatalf("got %+v", got)
	}
	if atomic.LoadInt32(&hops) != 4 {
		t.Errorf("hops=%d, want 4", hops)
	}
}

// --- 18. Headers from cfg passed through ---
func TestSend_CustomHeadersForwarded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Custom"); got != "y" {
			t.Errorf("X-Custom=%q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		b, _ := jsonrpc.Encode(responseMsg(1, "ok"))
		w.Write(b)
	}))
	defer srv.Close()
	c := newClient(t, srv.URL, nil, config.Header{Name: "X-Custom", Value: "y"})
	ch, _ := c.Send(context.Background(), request(1, "ping"))
	got := collect(t, ch, 2*time.Second)
	if len(got) != 1 || got[0].Err != nil {
		t.Fatalf("got %+v", got)
	}
}

// --- 20. Authorization в cfg.Headers перебивает OAuth ---
func TestSend_UserAuthorizationOverridesOAuth(t *testing.T) {
	var sawAuth atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth.Store(r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		b, _ := jsonrpc.Encode(responseMsg(1, "ok"))
		w.Write(b)
	}))
	defer srv.Close()
	tp := &fakeTP{token: "OAUTH"}
	c := newClient(t, srv.URL, tp,
		config.Header{Name: "Authorization", Value: "Bearer USER"},
	)
	ch, _ := c.Send(context.Background(), request(1, "ping"))
	collect(t, ch, 2*time.Second)
	if got, _ := sawAuth.Load().(string); got != "Bearer USER" {
		t.Errorf("Authorization=%q want Bearer USER", got)
	}
	_, _, tc := tp.snapshot()
	if tc != 0 {
		t.Errorf("Token called %d times, want 0", tc)
	}
}

// --- bonus: OAuth header set when no user header ---
func TestSend_OAuthAuthorizationSetWhenAbsent(t *testing.T) {
	var sawAuth atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth.Store(r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	tp := &fakeTP{token: "OAUTH"}
	c := newClient(t, srv.URL, tp)
	ch, _ := c.Send(context.Background(), notification("x"))
	collect(t, ch, 2*time.Second)
	if got, _ := sawAuth.Load().(string); got != "Bearer OAUTH" {
		t.Errorf("Authorization=%q want Bearer OAUTH", got)
	}
}

// --- bonus: empty oauth token → no Authorization ---
func TestSend_NoAuthorizationWhenTokenEmpty(t *testing.T) {
	var sawAuth atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth.Store(r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	tp := &fakeTP{token: ""}
	c := newClient(t, srv.URL, tp)
	ch, _ := c.Send(context.Background(), notification("x"))
	collect(t, ch, 2*time.Second)
	if got, _ := sawAuth.Load().(string); got != "" {
		t.Errorf("Authorization=%q want empty", got)
	}
}

// --- bonus: Close DELETE only when sessionID set ---
func TestClose_SendsDelete(t *testing.T) {
	var hits atomic.Int32
	var sawMethod atomic.Value
	var sawSession atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		sawMethod.Store(r.Method)
		sawSession.Store(r.Header.Get("Mcp-Session-Id"))
		if r.Method == "POST" {
			w.Header().Set("Mcp-Session-Id", "sess-1")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			b, _ := jsonrpc.Encode(responseMsg(1, "ok"))
			w.Write(b)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	c := newClient(t, srv.URL, nil)
	ch, _ := c.Send(context.Background(), request(1, "init"))
	collect(t, ch, 2*time.Second)
	if err := c.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got, _ := sawMethod.Load().(string); got != "DELETE" {
		t.Errorf("close method=%q want DELETE", got)
	}
	if got, _ := sawSession.Load().(string); got != "sess-1" {
		t.Errorf("close session=%q", got)
	}
}

func TestClose_NoSessionNoCall(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer srv.Close()
	c := newClient(t, srv.URL, nil)
	if err := c.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if hits.Load() != 0 {
		t.Errorf("hits=%d want 0", hits.Load())
	}
}

// --- bonus: ResetSession clears stored id ---
func TestResetSession(t *testing.T) {
	c := newClient(t, "http://example.invalid/", nil)
	c.session.setSessionID("abc")
	c.ResetSession()
	if got := c.session.getSessionID(); got != "" {
		t.Errorf("sessionID=%q want empty", got)
	}
}

// --- bonus: 5xx with body excerpt in error ---
func TestSend_5xxErrorBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("oops something failed"))
	}))
	defer srv.Close()
	c := newClient(t, srv.URL, nil)
	ch, _ := c.Send(context.Background(), request(1, "ping"))
	got := collect(t, ch, 2*time.Second)
	if len(got) != 1 || got[0].Err == nil {
		t.Fatalf("expected err, got %+v", got)
	}
	if !strings.Contains(got[0].Err.Error(), "http 500") {
		t.Errorf("err=%v", got[0].Err)
	}
	if !strings.Contains(got[0].Err.Error(), "oops") {
		t.Errorf("expected body in err: %v", got[0].Err)
	}
}

// --- bonus: 404 without session → plain http 404 (not ErrSessionLost) ---
func TestSend_404_NoSession(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	c := newClient(t, srv.URL, nil)
	ch, _ := c.Send(context.Background(), request(1, "ping"))
	got := collect(t, ch, 2*time.Second)
	if len(got) != 1 || got[0].Err == nil {
		t.Fatalf("expected err, got %+v", got)
	}
	if errors.Is(got[0].Err, proxy.ErrSessionLost) {
		t.Errorf("must not be ErrSessionLost when no session: %v", got[0].Err)
	}
}

// --- bonus: ctx cancel during Send → channel closes ---
func TestSend_CtxCancel(t *testing.T) {
	// Server holds the request open so client must abort via ctx.
	hangCh := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		select {
		case <-hangCh:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(hangCh)
	c := newClient(t, srv.URL, nil)
	ctx, cancel := context.WithCancel(context.Background())
	ch, _ := c.Send(ctx, request(1, "ping"))
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	// Drain — must close eventually.
	deadline := time.After(5 * time.Second)
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return
			}
		case <-deadline:
			t.Fatal("channel not closed after ctx cancel")
		}
	}
}

// --- bonus: unknown content-type → error ---
func TestSend_UnknownContentType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		w.Write([]byte("hi"))
	}))
	defer srv.Close()
	c := newClient(t, srv.URL, nil)
	ch, _ := c.Send(context.Background(), request(1, "ping"))
	got := collect(t, ch, 2*time.Second)
	if len(got) != 1 || got[0].Err == nil {
		t.Fatalf("expected err, got %+v", got)
	}
	if !strings.Contains(got[0].Err.Error(), "unexpected content-type") {
		t.Errorf("err=%v", got[0].Err)
	}
}

// --- bonus: content-type with charset parameter parses correctly ---
func TestSend_OK_JSON_WithCharset(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(200)
		b, _ := jsonrpc.Encode(responseMsg(1, "ok"))
		w.Write(b)
	}))
	defer srv.Close()
	c := newClient(t, srv.URL, nil)
	ch, _ := c.Send(context.Background(), request(1, "ping"))
	got := collect(t, ch, 2*time.Second)
	if len(got) != 1 || got[0].Err != nil {
		t.Fatalf("got %+v", got)
	}
}

// --- bonus: non-ASCII Mcp-Session-Id not persisted ---
func TestSend_NonPrintableSessionIDIgnored(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Send a value with space (which is allowed in HTTP header values but
		// not ASCII-printable per our session rules).
		w.Header()["Mcp-Session-Id"] = []string{"bad value"}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		b, _ := jsonrpc.Encode(responseMsg(1, "ok"))
		w.Write(b)
	}))
	defer srv.Close()
	c := newClient(t, srv.URL, nil)
	ch, _ := c.Send(context.Background(), request(1, "ping"))
	collect(t, ch, 2*time.Second)
	if id := c.session.getSessionID(); id != "" {
		t.Errorf("sessionID=%q want empty", id)
	}
}

// --- bonus: SSE decode error emits but does not abort stream ---
func TestSend_OK_SSE_BadJSONContinues(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: NOT_JSON\n\n")
		fmt.Fprint(w, "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"ok\"}\n\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}))
	defer srv.Close()
	c := newClient(t, srv.URL, nil)
	ch, _ := c.Send(context.Background(), request(1, "ping"))
	got := collect(t, ch, 2*time.Second)
	if len(got) != 2 {
		t.Fatalf("expected 2 items, got %d: %+v", len(got), got)
	}
	if got[0].Err == nil {
		t.Errorf("first should be err, got msg=%+v", got[0].Msg)
	}
	if got[1].Err != nil {
		t.Errorf("second should be msg, got err=%v", got[1].Err)
	}
}
