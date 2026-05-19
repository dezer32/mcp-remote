// Package oauth реализует OAuth 2.1 для MCP: PKCE + RFC 7591 Dynamic Client
// Registration + двойной discovery (RFC 9728 PRM либо RFC 8414 fallback).
//
// Provider реализует contract httpmcp.TokenProvider.
package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/dezer32/mcp-remote/internal/config"
)

// Opener абстрагирует открытие URL в браузере (для тестов).
type Opener interface {
	Open(ctx context.Context, url string) error
}

const (
	defaultAuthTimeout = 5 * time.Minute
	tokenSkew          = 30 * time.Second
	defaultHTTPTimeout = 30 * time.Second
	defaultScope       = "mcp"
	defaultClientName  = "mcp-remote (go)"
)

// tokenResponse — успешный ответ token endpoint (RFC 6749 §5.1 + RFC 7636).
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// Provider — OAuth-провайдер, реализует httpmcp.TokenProvider.
type Provider struct {
	cfg    *config.Config
	opener Opener
	log    *slog.Logger

	httpClient *http.Client

	mu             sync.Mutex
	storage        *Storage
	storageErr     error
	cachedTokens   *Tokens
	cachedClient   *ClientInfo
	cachedMeta     *AuthServerMetadata
	cachedResource string
	loaded         bool // tokens/meta/client уже подтянуты с диска
}

// New создаёт Provider. Файлы с диска не читаются здесь — lazy.
// Если в cfg есть StaticOAuthClientInfoJSON — парсит как override для DCR.
func New(cfg *config.Config, opener Opener, log *slog.Logger) *Provider {
	if log == nil {
		log = slog.Default()
	}
	p := &Provider{
		cfg:        cfg,
		opener:     opener,
		log:        log,
		httpClient: &http.Client{Timeout: defaultHTTPTimeout},
	}

	if cfg != nil && cfg.ServerURL != "" && cfg.ConfigDir != "" {
		st, err := NewStorage(cfg.ConfigDir, cfg.ServerURL)
		if err != nil {
			p.storageErr = err
			p.log.Warn("oauth: storage unavailable", slog.String("error", err.Error()))
		} else {
			p.storage = st
		}
	}

	if cfg != nil && len(cfg.StaticOAuthClientInfoJSON) > 0 {
		var ci ClientInfo
		if err := json.Unmarshal(cfg.StaticOAuthClientInfoJSON, &ci); err != nil {
			p.log.Warn("oauth: parse StaticOAuthClientInfoJSON", slog.String("error", err.Error()))
		} else {
			p.cachedClient = &ci
		}
	}

	return p
}

// Token возвращает текущий access-токен (с авто-refresh при истечении).
// "" — auth не нужен / токен ещё не выписан; вызывающий получит 401 →
// HandleUnauthorized стартует flow.
func (p *Provider) Token(ctx context.Context) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if err := p.ensureLoadedLocked(); err != nil {
		return "", err
	}

	if p.cachedTokens == nil || p.cachedTokens.AccessToken == "" {
		return "", nil
	}

	if p.tokenExpiredLocked() {
		if p.cachedTokens.RefreshToken != "" {
			if err := p.refreshTokensLocked(ctx); err != nil {
				p.log.Warn("oauth: refresh failed, clearing tokens", slog.String("error", err.Error()))
				p.clearTokensLocked()
				return "", nil
			}
			return p.cachedTokens.AccessToken, nil
		}
		// expired, нет refresh → очищаем и форсируем re-auth.
		p.clearTokensLocked()
		return "", nil
	}

	return p.cachedTokens.AccessToken, nil
}

// HandleUnauthorized обрабатывает 401: парсит challenge, делает refresh либо
// полный authorize flow. После успеха Token вернёт новый access-токен.
func (p *Provider) HandleUnauthorized(ctx context.Context, wwwAuthenticate string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if err := p.ensureLoadedLocked(); err != nil {
		return err
	}

	// Сначала пытаемся refresh, если есть refresh_token, который мы ещё не
	// "поломали" в этом вызове.
	if p.cachedTokens != nil && p.cachedTokens.RefreshToken != "" {
		if err := p.refreshTokensLocked(ctx); err == nil {
			return nil
		} else {
			p.log.Info("oauth: refresh failed, falling back to full authorize", slog.String("error", err.Error()))
			p.clearTokensLocked()
		}
	}

	return p.authorizeLocked(ctx, wwwAuthenticate)
}

// authorizeLocked — полный authorization_code flow + PKCE + DCR.
// Должен вызываться под p.mu.
func (p *Provider) authorizeLocked(ctx context.Context, wwwAuthenticate string) error {
	if p.cfg == nil || p.cfg.ServerURL == "" {
		return errors.New("oauth: ServerURL is empty")
	}

	// 1) Парсим challenge.
	var resourceMetadataURL string
	if params := parseWWWAuthenticate(wwwAuthenticate); params != nil {
		resourceMetadataURL = params["resource_metadata"]
	}

	// 2) Discovery → metadata + resource hint.
	resourceOverride := ""
	if p.cfg != nil {
		resourceOverride = p.cfg.Resource
	}
	meta, resource, err := p.discover(ctx, resourceMetadataURL, p.cfg.ServerURL, resourceOverride)
	if err != nil {
		return fmt.Errorf("oauth: discovery: %w", err)
	}
	p.cachedMeta = meta
	p.cachedResource = resource
	if p.storage != nil {
		if err := p.storage.SaveMetadata(meta, resource); err != nil {
			p.log.Warn("oauth: save metadata", slog.String("error", err.Error()))
		}
	}

	// 3) Подготавливаем PKCE / state и callback-сервер до DCR, чтобы знать
	//    redirect_uri в DCR request.
	verifier, err := generateVerifier()
	if err != nil {
		return fmt.Errorf("oauth: verifier: %w", err)
	}
	challenge := challengeS256(verifier)

	state, err := generateState()
	if err != nil {
		return fmt.Errorf("oauth: state: %w", err)
	}

	callbackURL, srv, err := listenCallback(p.cfg, state)
	if err != nil {
		return fmt.Errorf("oauth: callback listener: %w", err)
	}
	defer func() {
		shCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		_ = srv.Shutdown(shCtx)
	}()

	// 4) DCR (если cachedClient ещё пуст и есть registration endpoint).
	if p.cachedClient == nil && meta.RegistrationEndpoint != "" {
		client, err := p.registerClient(ctx, meta.RegistrationEndpoint, callbackURL)
		if err != nil {
			return fmt.Errorf("oauth: dynamic client registration: %w", err)
		}
		p.cachedClient = client
		if p.storage != nil {
			if err := p.storage.SaveClient(client); err != nil {
				p.log.Warn("oauth: save client", slog.String("error", err.Error()))
			}
		}
	}
	if p.cachedClient == nil || p.cachedClient.ClientID == "" {
		return errors.New("oauth: no DCR endpoint and no static client")
	}

	// 5) Конструируем authorize URL.
	authURL := buildAuthorizeURL(meta, p.cachedClient, callbackURL, challenge, state, resource)
	p.log.Info("oauth: opening browser for authorization", slog.String("url", authURL))

	if err := p.opener.Open(ctx, authURL); err != nil {
		// Не фатально: пользователь может открыть URL вручную. Логируем и
		// печатаем URL в stderr.
		p.log.Warn("oauth: opener failed", slog.String("error", err.Error()))
		fmt.Fprintf(os.Stderr, "Open this URL to authorize: %s\n", authURL)
	}

	// 6) Ждём callback.
	timeout := p.authTimeout()
	authCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	res := srv.Wait(authCtx)
	if res.err != nil {
		return fmt.Errorf("oauth: callback: %w", res.err)
	}

	// 7) Обмен code на токены.
	tok, err := p.exchangeCode(ctx, meta, p.cachedClient, res.code, verifier, callbackURL, resource)
	if err != nil {
		return fmt.Errorf("oauth: exchange code: %w", err)
	}

	p.cachedTokens = tok
	if p.storage != nil {
		if err := p.storage.SaveTokens(tok); err != nil {
			p.log.Warn("oauth: save tokens", slog.String("error", err.Error()))
		}
	}
	return nil
}

// registerClient выполняет RFC 7591 Dynamic Client Registration.
func (p *Provider) registerClient(ctx context.Context, regEndpoint, callbackURL string) (*ClientInfo, error) {
	body := p.dcrBody(callbackURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, regEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("new register request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set(headerMCPProtocolVersion, mcpProtocolVersion)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do register: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read register body: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("register status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var ci ClientInfo
	if err := json.Unmarshal(raw, &ci); err != nil {
		return nil, fmt.Errorf("parse register response: %w", err)
	}
	if ci.ClientID == "" {
		return nil, errors.New("register response without client_id")
	}
	return &ci, nil
}

// dcrBody возвращает тело DCR-запроса. Использует StaticOAuthClientMetadataJSON
// если задан и валиден (мердж с redirect_uris не делаем — пользовательский
// JSON в приоритете кроме случая отсутствия redirect_uris).
func (p *Provider) dcrBody(callbackURL string) []byte {
	if p.cfg != nil && len(p.cfg.StaticOAuthClientMetadataJSON) > 0 {
		// Гарантируем, что redirect_uris содержит наш callbackURL — иначе
		// authorize не пройдёт.
		var m map[string]any
		if err := json.Unmarshal(p.cfg.StaticOAuthClientMetadataJSON, &m); err == nil {
			if _, ok := m["redirect_uris"]; !ok {
				m["redirect_uris"] = []string{callbackURL}
			}
			out, err := json.Marshal(m)
			if err == nil {
				return out
			}
		}
		// если JSON не парсится — отдаём как есть, сервер ответит ошибкой.
		return p.cfg.StaticOAuthClientMetadataJSON
	}
	def := map[string]any{
		"client_name":                defaultClientName,
		"redirect_uris":              []string{callbackURL},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	}
	out, _ := json.Marshal(def)
	return out
}

// buildAuthorizeURL собирает GET-запрос на authorization_endpoint.
func buildAuthorizeURL(meta *AuthServerMetadata, client *ClientInfo, callbackURL, challenge, state, resource string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", client.ClientID)
	q.Set("redirect_uri", callbackURL)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", state)

	scope := pickScope(meta, client)
	if scope != "" {
		q.Set("scope", scope)
	}
	if resource != "" {
		q.Set("resource", resource)
	}

	sep := "?"
	if strings.Contains(meta.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	return meta.AuthorizationEndpoint + sep + q.Encode()
}

// pickScope выбирает scope для authorize: client.Scope (если есть), иначе
// meta.ScopesSupported (как разделённый пробелами список), иначе defaultScope.
func pickScope(meta *AuthServerMetadata, client *ClientInfo) string {
	if client != nil && client.Scope != "" {
		return client.Scope
	}
	if meta != nil && len(meta.ScopesSupported) > 0 {
		return strings.Join(meta.ScopesSupported, " ")
	}
	return defaultScope
}

// exchangeCode обменивает authorization code на токены.
func (p *Provider) exchangeCode(ctx context.Context, meta *AuthServerMetadata, client *ClientInfo, code, verifier, callbackURL, resource string) (*Tokens, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("code_verifier", verifier)
	form.Set("client_id", client.ClientID)
	form.Set("redirect_uri", callbackURL)
	if client.ClientSecret != "" {
		form.Set("client_secret", client.ClientSecret)
	}
	if resource != "" {
		form.Set("resource", resource)
	}
	return p.postToken(ctx, meta.TokenEndpoint, form)
}

// refreshTokensLocked делает grant_type=refresh_token. Должен вызываться
// под p.mu.
func (p *Provider) refreshTokensLocked(ctx context.Context) error {
	if p.cachedTokens == nil || p.cachedTokens.RefreshToken == "" {
		return errors.New("oauth: no refresh token")
	}
	if p.cachedMeta == nil {
		// Попробуем подтянуть metadata из storage.
		if p.storage != nil {
			if m, r, err := p.storage.LoadMetadata(); err == nil {
				p.cachedMeta = m
				if p.cachedResource == "" {
					p.cachedResource = r
				}
			}
		}
	}
	if p.cachedMeta == nil || p.cachedMeta.TokenEndpoint == "" {
		return errors.New("oauth: no token endpoint for refresh")
	}
	if p.cachedClient == nil || p.cachedClient.ClientID == "" {
		// client info обязателен для refresh.
		if p.storage != nil {
			if c, err := p.storage.LoadClient(); err == nil {
				p.cachedClient = c
			}
		}
	}
	if p.cachedClient == nil || p.cachedClient.ClientID == "" {
		return errors.New("oauth: no client for refresh")
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", p.cachedTokens.RefreshToken)
	form.Set("client_id", p.cachedClient.ClientID)
	if p.cachedClient.ClientSecret != "" {
		form.Set("client_secret", p.cachedClient.ClientSecret)
	}
	if p.cachedResource != "" {
		form.Set("resource", p.cachedResource)
	}

	tok, err := p.postToken(ctx, p.cachedMeta.TokenEndpoint, form)
	if err != nil {
		return err
	}
	// Если AS вернул пустой refresh_token — оставляем старый.
	if tok.RefreshToken == "" {
		tok.RefreshToken = p.cachedTokens.RefreshToken
	}
	p.cachedTokens = tok
	if p.storage != nil {
		if err := p.storage.SaveTokens(tok); err != nil {
			p.log.Warn("oauth: save tokens after refresh", slog.String("error", err.Error()))
		}
	}
	return nil
}

// postToken — общий POST на token endpoint с form-urlencoded body.
func (p *Provider) postToken(ctx context.Context, endpoint string, form url.Values) (*Tokens, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("new token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set(headerMCPProtocolVersion, mcpProtocolVersion)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do token request: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read token body: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("token endpoint status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var tr tokenResponse
	if err := json.Unmarshal(raw, &tr); err != nil {
		return nil, fmt.Errorf("parse token response: %w", err)
	}
	if tr.AccessToken == "" {
		return nil, errors.New("token response without access_token")
	}

	t := &Tokens{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		TokenType:    tr.TokenType,
		Scope:        tr.Scope,
	}
	if tr.ExpiresIn > 0 {
		t.ExpiresAt = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second).Add(-tokenSkew)
	}
	return t, nil
}

// ---------------------------------------------------------------------------
// внутренние утилиты (под p.mu)
// ---------------------------------------------------------------------------

func (p *Provider) ensureLoadedLocked() error {
	if p.loaded {
		return nil
	}
	p.loaded = true
	if p.storage == nil {
		return nil
	}
	if p.cachedTokens == nil {
		t, err := p.storage.LoadTokens()
		switch {
		case err == nil:
			p.cachedTokens = t
		case errors.Is(err, os.ErrNotExist):
			// нормально для первой авторизации
		default:
			p.log.Warn("oauth: load tokens", slog.String("error", err.Error()))
		}
	}
	if p.cachedClient == nil {
		c, err := p.storage.LoadClient()
		switch {
		case err == nil:
			p.cachedClient = c
		case errors.Is(err, os.ErrNotExist):
		default:
			p.log.Warn("oauth: load client", slog.String("error", err.Error()))
		}
	}
	if p.cachedMeta == nil {
		m, r, err := p.storage.LoadMetadata()
		switch {
		case err == nil:
			p.cachedMeta = m
			p.cachedResource = r
		case errors.Is(err, os.ErrNotExist):
		default:
			p.log.Warn("oauth: load metadata", slog.String("error", err.Error()))
		}
	}
	return nil
}

func (p *Provider) tokenExpiredLocked() bool {
	if p.cachedTokens == nil {
		return true
	}
	if p.cachedTokens.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(p.cachedTokens.ExpiresAt)
}

func (p *Provider) clearTokensLocked() {
	p.cachedTokens = nil
	if p.storage != nil {
		if err := p.storage.ClearTokens(); err != nil {
			p.log.Warn("oauth: clear tokens", slog.String("error", err.Error()))
		}
	}
}

func (p *Provider) authTimeout() time.Duration {
	if p.cfg != nil && p.cfg.AuthTimeout > 0 {
		return p.cfg.AuthTimeout
	}
	return defaultAuthTimeout
}
