package proxy_test

// Тест listener-а поверх реальных httpmcp.Client и stdio.Transport. Внешний
// пакет: httpmcp импортирует proxy, во внутреннем тесте был бы цикл импортов.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/dezer32/mcp-remote/internal/config"
	"github.com/dezer32/mcp-remote/internal/httpmcp"
	"github.com/dezer32/mcp-remote/internal/jsonrpc"
	"github.com/dezer32/mcp-remote/internal/logging"
	"github.com/dezer32/mcp-remote/internal/proxy"
	"github.com/dezer32/mcp-remote/internal/stdio"
)

// sessionServer — MCP-сервер с сессиями: initialize выдаёт S<k>, GET держит SSE
// текущей сессии; запросы с истёкшим sid → 404. Recovery-handshake (initialize
// после первого) ждёт replayGate.
type sessionServer struct {
	t *testing.T

	mu         sync.Mutex
	initN      int
	current    string
	expired    map[string]bool
	getSIDs    []string
	violations []string
	streams    map[string]chan string

	getOpened     chan string
	replayArrived chan struct{}
	replayGate    chan struct{}
}

func newSessionServer(t *testing.T) (*sessionServer, *httptest.Server) {
	s := &sessionServer{
		t:             t,
		expired:       make(map[string]bool),
		streams:       make(map[string]chan string),
		getOpened:     make(chan string, 8),
		replayArrived: make(chan struct{}),
		replayGate:    make(chan struct{}),
	}
	return s, httptest.NewServer(http.HandlerFunc(s.handle))
}

func (s *sessionServer) handle(w http.ResponseWriter, r *http.Request) {
	sid := r.Header.Get("Mcp-Session-Id")
	switch r.Method {
	case http.MethodGet:
		s.handleGet(w, r, sid)
		return
	case http.MethodDelete:
		w.WriteHeader(http.StatusOK)
		return
	}

	var m struct {
		Method string          `json:"method"`
		ID     json.RawMessage `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	expired := sid != "" && s.expired[sid]
	s.mu.Unlock()
	if expired {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	switch m.Method {
	case "initialize":
		s.mu.Lock()
		s.initN++
		k := s.initN
		s.mu.Unlock()
		if k > 1 {
			close(s.replayArrived)
			select {
			case <-s.replayGate:
			case <-r.Context().Done():
				return
			}
		}
		newSID := fmt.Sprintf("S%d", k)
		s.mu.Lock()
		s.current = newSID
		s.mu.Unlock()
		w.Header().Set("Mcp-Session-Id", newSID)
		writeResult(w, m.ID, `{"protocolVersion":"2025-03-26"}`)
	case "":
		http.Error(w, "no method", http.StatusBadRequest)
	default:
		if len(m.ID) == 0 {
			w.WriteHeader(http.StatusAccepted) // notification
			return
		}
		writeResult(w, m.ID, `{}`)
	}
}

func (s *sessionServer) handleGet(w http.ResponseWriter, r *http.Request, sid string) {
	s.mu.Lock()
	s.getSIDs = append(s.getSIDs, sid)
	if sid == "" || s.expired[sid] || sid != s.current {
		s.violations = append(s.violations, fmt.Sprintf("GET with sid %q (current %q)", sid, s.current))
		s.mu.Unlock()
		http.Error(w, "bad session", http.StatusBadRequest)
		return
	}
	push := make(chan string, 4)
	s.streams[sid] = push
	s.mu.Unlock()

	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	f, _ := w.(http.Flusher)
	f.Flush()
	s.getOpened <- sid

	for {
		select {
		case data := <-push:
			fmt.Fprintf(w, "data: %s\n\n", data)
			f.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (s *sessionServer) expire(sid string) {
	s.mu.Lock()
	s.expired[sid] = true
	s.mu.Unlock()
}

func (s *sessionServer) push(sid, data string) {
	s.mu.Lock()
	ch := s.streams[sid]
	s.mu.Unlock()
	ch <- data
}

func (s *sessionServer) snapshot() (gets, violations []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.getSIDs), slices.Clone(s.violations)
}

func writeResult(w http.ResponseWriter, id json.RawMessage, result string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	b, _ := jsonrpc.Encode(jsonrpc.Message{JSONRPC: jsonrpc.Version, ID: id, Result: json.RawMessage(result)})
	_, _ = w.Write(b)
}

func waitSID(t *testing.T, ch <-chan string, what string) string {
	t.Helper()
	select {
	case sid := <-ch:
		return sid
	case <-time.After(5 * time.Second):
		t.Fatalf("timeout waiting for %s", what)
		return ""
	}
}

// Listener открывает GET только на валидной сессии: не до initialize, не во
// время recovery и не со старым sid; после recovery стрим переоткрыт на новой
// сессии и server-initiated сообщения по нему доходят до stdout.
func TestListenerFollowsSessionAcrossRecovery(t *testing.T) {
	srv, hs := newSessionServer(t)
	defer hs.Close()

	log := logging.Discard()
	client, err := httpmcp.New(&config.Config{ServerURL: hs.URL}, nil, log)
	if err != nil {
		t.Fatalf("httpmcp.New: %v", err)
	}

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	t.Cleanup(func() {
		_ = inW.Close()
		_ = inR.Close()
		_ = outW.Close()
		_ = outR.Close()
	})

	p := proxy.New(stdio.New(inR, outW, log), client, log)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- p.Run(ctx) }()

	out := make(chan jsonrpc.Message, 16)
	go func() {
		sc := bufio.NewScanner(outR)
		for sc.Scan() {
			if m, derr := jsonrpc.Decode(sc.Bytes()); derr == nil {
				out <- m
			}
		}
	}()
	send := func(line string) {
		t.Helper()
		if _, werr := io.WriteString(inW, line+"\n"); werr != nil {
			t.Fatalf("write stdin: %v", werr)
		}
	}
	expect := func(what string, match func(jsonrpc.Message) bool) {
		t.Helper()
		deadline := time.After(5 * time.Second)
		for {
			select {
			case m := <-out:
				if match(m) {
					return
				}
			case <-deadline:
				t.Fatalf("timeout waiting for %s on stdout", what)
			}
		}
	}
	isResult := func(id string) func(jsonrpc.Message) bool {
		return func(m jsonrpc.Message) bool {
			return string(m.ID) == id && m.Error == nil && len(m.Result) > 0
		}
	}

	send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	expect("initialize response", isResult("1"))
	send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if sid := waitSID(t, srv.getOpened, "first GET"); sid != "S1" {
		t.Fatalf("first GET sid=%q, want S1", sid)
	}

	// Сессия истекла; POST получает 404 → recovery. Handshake задержан сервером.
	srv.expire("S1")
	send(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`)
	select {
	case <-srv.replayArrived:
	case <-time.After(5 * time.Second):
		t.Fatal("recovery initialize not received")
	}
	close(srv.replayGate)

	expect("replayed tools/list response", isResult("2"))
	if sid := waitSID(t, srv.getOpened, "GET after recovery"); sid != "S2" {
		t.Fatalf("GET after recovery sid=%q, want S2", sid)
	}

	srv.push("S2", `{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info"}}`)
	expect("server-initiated message", func(m jsonrpc.Message) bool {
		return m.Method == "notifications/message"
	})

	gets, violations := srv.snapshot()
	if len(violations) > 0 {
		t.Fatalf("GETs with empty/stale session: %v", violations)
	}
	if !slices.Equal(gets, []string{"S1", "S2"}) {
		t.Fatalf("GET sids=%v, want [S1 S2]", gets)
	}

	_ = inW.Close()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after stdin EOF")
	}
}

// Compile-time: тест опирается на реальные реализации контрактов proxy.
var (
	_ proxy.Remote    = (*httpmcp.Client)(nil)
	_ proxy.Transport = (*stdio.Transport)(nil)
)
