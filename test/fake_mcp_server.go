//go:build integration

// Package test содержит интеграционные хелперы и тесты для бинаря mcp-remote.
// Все файлы в этом пакете под build-tag "integration".
package test

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// FakeServer — stateful httptest-сервер, реализующий минимальный MCP
// Streamable HTTP transport (спецификация 2025-03-26) и опциональные OAuth-routes.
//
// Использование:
//
//	srv := NewFakeServer(t)            // обычный режим
//	srv := NewFakeOAuthServer(t)       // тот же сервер + OAuth-эндпоинты + 401
//	defer srv.Close()
//
// Контракт зафиксирован в plan unit-6.
type FakeServer struct {
	URL    string
	server *httptest.Server

	mu              sync.Mutex
	sessionID       string
	seenProtocolV   string
	callLog         []string
	initializeCount int

	// expired[sessionID]==true → следующий запрос с этим sessionID отдаёт 404,
	// после чего флаг сбрасывается (recovery после ResetSession продолжится).
	expired map[string]bool

	// OAuth mode.
	oauthMode     bool
	requireBearer string
}

// NewFakeServer создаёт сервер без OAuth.
func NewFakeServer(t *testing.T) *FakeServer {
	t.Helper()
	return newFakeServer(t, false)
}

// NewFakeOAuthServer создаёт сервер с OAuth-routes (PRM/AS/register/authorize/token)
// и требует Authorization: Bearer <granted-token> для /mcp.
func NewFakeOAuthServer(t *testing.T) *FakeServer {
	t.Helper()
	return newFakeServer(t, true)
}

func newFakeServer(t *testing.T, oauthMode bool) *FakeServer {
	t.Helper()
	s := &FakeServer{
		oauthMode: oauthMode,
		expired:   make(map[string]bool),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", s.handleMCP)
	mux.HandleFunc("/.well-known/oauth-protected-resource", s.handlePRM)
	mux.HandleFunc("/.well-known/oauth-authorization-server", s.handleAS)
	mux.HandleFunc("/register", s.handleRegister)
	mux.HandleFunc("/authorize", s.handleAuthorize)
	mux.HandleFunc("/token", s.handleToken)

	s.server = httptest.NewServer(mux)
	s.URL = s.server.URL
	return s
}

// Close останавливает HTTP-сервер.
func (s *FakeServer) Close() {
	if s.server != nil {
		s.server.Close()
	}
}

// Reset очищает session/log state. OAuth-конфигурацию НЕ трогает.
func (s *FakeServer) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessionID = ""
	s.seenProtocolV = ""
	s.callLog = nil
	s.initializeCount = 0
	s.expired = make(map[string]bool)
}

// ExpireSession помечает текущий sessionID как истёкший: на ближайший
// запрос с этим sessionID сервер ответит 404. После hit-а флаг снимается,
// чтобы прокси мог пере-initialize-ить сессию и продолжить работу.
func (s *FakeServer) ExpireSession() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessionID != "" {
		s.expired[s.sessionID] = true
	}
}

// GrantToken переключает требуемый Bearer-токен. Если "" — авторизация
// перестаёт требоваться (для тестов без OAuth-эндпоинтов).
func (s *FakeServer) GrantToken(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requireBearer = token
}

// SeenProtocolVersion возвращает последний MCP-Protocol-Version, увиденный
// сервером в заголовке запроса.
func (s *FakeServer) SeenProtocolVersion() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seenProtocolV
}

// InitializeCount возвращает количество прошедших initialize-запросов.
func (s *FakeServer) InitializeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.initializeCount
}

// CallLog возвращает копию call-log (методы JSON-RPC).
func (s *FakeServer) CallLog() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.callLog))
	copy(out, s.callLog)
	return out
}

// ---------------------------------------------------------------------------
// MCP endpoint.

func (s *FakeServer) handleMCP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// SSE listen — не покрывается тестами; по спеке 405 допустим.
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	case http.MethodDelete:
		w.WriteHeader(http.StatusOK)
		return
	case http.MethodPost:
		// ok
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// OAuth: требуем Bearer перед обработкой тела.
	if s.oauthMode {
		s.mu.Lock()
		req := s.requireBearer
		s.mu.Unlock()
		if req != "" {
			auth := r.Header.Get("Authorization")
			if auth != "Bearer "+req {
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(
					`Bearer realm="x", resource_metadata="%s/.well-known/oauth-protected-resource"`,
					s.URL,
				))
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		} else {
			// До grantToken — отдаём 401 c PRM-challenge, чтобы клиент стартанул OAuth-flow.
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(
				`Bearer realm="x", resource_metadata="%s/.well-known/oauth-protected-resource"`,
				s.URL,
			))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}

	// Записываем MCP-Protocol-Version.
	if pv := r.Header.Get("MCP-Protocol-Version"); pv != "" {
		s.mu.Lock()
		s.seenProtocolV = pv
		s.mu.Unlock()
	}

	// Сессионная проверка: если sessionID помечен expired → 404 + plaintext.
	reqSessionID := r.Header.Get("Mcp-Session-Id")
	if reqSessionID != "" {
		s.mu.Lock()
		expired := s.expired[reqSessionID]
		if expired {
			delete(s.expired, reqSessionID)
			s.sessionID = ""
		}
		s.mu.Unlock()
		if expired {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, "session not found")
			return
		}
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	msgs, isBatch, err := decodeRPC(body)
	if err != nil {
		http.Error(w, "bad json-rpc: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Готовим ответы. Для notifications → нет ответа (202).
	var responses []map[string]any
	var assignedSession string
	allNotifications := true

	for _, m := range msgs {
		method, _ := m["method"].(string)
		_, hasID := m["id"]

		if method != "" {
			s.mu.Lock()
			s.callLog = append(s.callLog, method)
			s.mu.Unlock()
		}

		if !hasID {
			// notification (включая notifications/initialized).
			continue
		}
		allNotifications = false

		switch method {
		case "initialize":
			sid := newID()
			s.mu.Lock()
			s.sessionID = sid
			s.initializeCount++
			s.mu.Unlock()
			assignedSession = sid
			responses = append(responses, map[string]any{
				"jsonrpc": "2.0",
				"id":      m["id"],
				"result": map[string]any{
					"protocolVersion": "2025-03-26",
					"serverInfo": map[string]any{
						"name":    "fake-mcp-server",
						"version": "0.0.0",
					},
					"capabilities": map[string]any{
						"tools": map[string]any{},
					},
				},
			})
		case "tools/list":
			responses = append(responses, map[string]any{
				"jsonrpc": "2.0",
				"id":      m["id"],
				"result": map[string]any{
					"tools": []map[string]any{
						{
							"name":        "echo",
							"description": "echoes input",
							"inputSchema": map[string]any{
								"type": "object",
								"properties": map[string]any{
									"text": map[string]any{"type": "string"},
								},
							},
						},
					},
				},
			})
		case "tools/call":
			text := ""
			if params, ok := m["params"].(map[string]any); ok {
				if name, _ := params["name"].(string); name == "echo" {
					if args, ok := params["arguments"].(map[string]any); ok {
						if t, ok := args["text"].(string); ok {
							text = t
						}
					}
				}
			}
			responses = append(responses, map[string]any{
				"jsonrpc": "2.0",
				"id":      m["id"],
				"result": map[string]any{
					"content": []map[string]any{
						{"type": "text", "text": text},
					},
				},
			})
		default:
			responses = append(responses, map[string]any{
				"jsonrpc": "2.0",
				"id":      m["id"],
				"error": map[string]any{
					"code":    -32601,
					"message": "method not found: " + method,
				},
			})
		}
	}

	// Notification(-ы) без request-ов → 202 без тела.
	if allNotifications {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	if assignedSession != "" {
		w.Header().Set("Mcp-Session-Id", assignedSession)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if isBatch {
		_ = json.NewEncoder(w).Encode(responses)
		return
	}
	// single: первый response.
	if len(responses) > 0 {
		_ = json.NewEncoder(w).Encode(responses[0])
	}
}

// decodeRPC возвращает срез JSON-объектов и признак batch.
func decodeRPC(data []byte) ([]map[string]any, bool, error) {
	trimmed := strings.TrimSpace(string(data))
	if len(trimmed) == 0 {
		return nil, false, fmt.Errorf("empty body")
	}
	if trimmed[0] == '[' {
		var arr []map[string]any
		if err := json.Unmarshal([]byte(trimmed), &arr); err != nil {
			return nil, true, err
		}
		return arr, true, nil
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(trimmed), &m); err != nil {
		return nil, false, err
	}
	return []map[string]any{m}, false, nil
}

func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// ---------------------------------------------------------------------------
// OAuth endpoints.

func (s *FakeServer) handlePRM(w http.ResponseWriter, r *http.Request) {
	if !s.oauthMode {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"resource":              s.URL + "/mcp",
		"authorization_servers": []string{s.URL},
	})
}

func (s *FakeServer) handleAS(w http.ResponseWriter, r *http.Request) {
	if !s.oauthMode {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                s.URL,
		"authorization_endpoint":                s.URL + "/authorize",
		"token_endpoint":                        s.URL + "/token",
		"registration_endpoint":                 s.URL + "/register",
		"scopes_supported":                      []string{"mcp"},
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
	})
}

func (s *FakeServer) handleRegister(w http.ResponseWriter, r *http.Request) {
	if !s.oauthMode {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"client_id":                  "test-client",
		"client_id_issued_at":        time.Now().Unix(),
		"token_endpoint_auth_method": "none",
	})
}

func (s *FakeServer) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if !s.oauthMode {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")
	if redirectURI == "" {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	qs := u.Query()
	qs.Set("code", "test-code")
	if state != "" {
		qs.Set("state", state)
	}
	u.RawQuery = qs.Encode()
	w.Header().Set("Location", u.String())
	w.WriteHeader(http.StatusFound)
}

func (s *FakeServer) handleToken(w http.ResponseWriter, r *http.Request) {
	if !s.oauthMode {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "parse form: "+err.Error(), http.StatusBadRequest)
		return
	}
	grant := r.PostForm.Get("grant_type")
	resp := map[string]any{
		"token_type":   "Bearer",
		"expires_in":   3600,
		"access_token": "test-token",
	}
	switch grant {
	case "authorization_code":
		resp["access_token"] = "test-token"
		resp["refresh_token"] = "refresh-x"
		s.GrantToken("test-token")
	case "refresh_token":
		resp["access_token"] = "test-token-2"
		resp["refresh_token"] = "refresh-y"
		s.GrantToken("test-token-2")
	default:
		http.Error(w, "unsupported grant_type", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
