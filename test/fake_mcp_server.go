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
	"slices"
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

	// clients — зарегистрированные через /register клиенты: client_id →
	// redirect_uris. registrations — число вызовов /register.
	clients       map[string][]string
	registrations int
	// strictRedirectURI — /authorize отвечает 400 invalid_request, если
	// redirect_uri не входит в зарегистрированные для client_id.
	strictRedirectURI bool
	// rejectRefreshed — токены, выданные по refresh_token, ресурс отвергает
	// (401 error="invalid_token"): имитация протухшего grant-а.
	rejectRefreshed bool
	refreshGrants   int
	// rejectAll — ресурс отвергает любой токен, включая выданные по
	// authorization_code. authorizeHits — число запросов к /authorize.
	rejectAll     bool
	authorizeHits int
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
		clients:   make(map[string][]string),
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

// SetStrictRedirectURI включает строгую проверку redirect_uri в /authorize.
func (s *FakeServer) SetStrictRedirectURI(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.strictRedirectURI = on
}

// SetRejectRefreshedTokens включает режим, в котором токены, выданные по
// refresh_token, ресурс отвергает с error="invalid_token".
func (s *FakeServer) SetRejectRefreshedTokens(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rejectRefreshed = on
}

// SetRejectAllTokens включает режим, в котором ресурс отвергает любой
// токен (401 error="invalid_token"), даже только что выданный.
func (s *FakeServer) SetRejectAllTokens(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rejectAll = on
}

// AuthorizeCount — число запросов к /authorize (открытий «браузера»).
func (s *FakeServer) AuthorizeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.authorizeHits
}

// RegisterClient регистрирует клиента напрямую (как будто через /register в
// прошлом запуске), не увеличивая счётчик регистраций.
func (s *FakeServer) RegisterClient(clientID string, redirectURIs []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[clientID] = append([]string(nil), redirectURIs...)
}

// RegistrationCount — число вызовов /register.
func (s *FakeServer) RegistrationCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.registrations
}

// RefreshGrantCount — число успешных grant_type=refresh_token.
func (s *FakeServer) RefreshGrantCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refreshGrants
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

	// OAuth: требуем Bearer перед обработкой тела. До grant-а (requireBearer
	// пуст) отвергается любой запрос — клиент стартует OAuth-flow.
	if s.oauthMode {
		s.mu.Lock()
		req := s.requireBearer
		s.mu.Unlock()
		auth := r.Header.Get("Authorization")
		if req == "" || auth != "Bearer "+req {
			// С токеном — invalid_token (RFC 6750 §3.1), без — только challenge.
			errParam := ""
			if auth != "" {
				errParam = `, error="invalid_token", error_description="The access token is invalid"`
			}
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(
				`Bearer realm="x", resource_metadata="%s/.well-known/oauth-protected-resource"%s`,
				s.URL, errParam,
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
	var body struct {
		RedirectURIs []string `json:"redirect_uris"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad registration body: "+err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.registrations++
	clientID := fmt.Sprintf("test-client-%d", s.registrations)
	s.clients[clientID] = body.RedirectURIs
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"client_id":                  clientID,
		"client_id_issued_at":        time.Now().Unix(),
		"token_endpoint_auth_method": "none",
		"redirect_uris":              body.RedirectURIs,
	})
}

func (s *FakeServer) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if !s.oauthMode {
		http.NotFound(w, r)
		return
	}
	s.mu.Lock()
	s.authorizeHits++
	s.mu.Unlock()
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
	s.mu.Lock()
	strict := s.strictRedirectURI
	registered, known := s.clients[q.Get("client_id")]
	s.mu.Unlock()
	if strict && (!known || !slices.Contains(registered, redirectURI)) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_request",
			"error_description": "The specified 'redirect_uri' is not valid for this client application",
		})
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
		s.mu.Lock()
		rejectAll := s.rejectAll
		s.mu.Unlock()
		if !rejectAll {
			s.GrantToken("test-token")
		}
	case "refresh_token":
		s.mu.Lock()
		s.refreshGrants++
		n := s.refreshGrants
		reject := s.rejectRefreshed
		s.mu.Unlock()
		if reject {
			// Refresh «проходит», но ресурс такой токен не примет: requireBearer
			// не меняется. refresh_token принимается повторно.
			resp["access_token"] = fmt.Sprintf("refreshed-token-%d", n)
			resp["refresh_token"] = "refresh-stale"
			break
		}
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
