package oauth

// OAuth discovery:
//  1) RFC 9728 PRM (если WWW-Authenticate challenge содержит
//     resource_metadata=<url>): fetch <url> → JSON
//     {authorization_servers:[...], resource:"..."}; берём
//     authorization_servers[0] и резолвим эндпоинты по RFC 8414.
//  2) RFC 8414 fallback: <auth-base>/.well-known/oauth-authorization-server
//     с заголовком MCP-Protocol-Version: 2025-03-26; на 404 — дефолтные пути
//     /authorize, /token, /register.
//
// cfg.Resource (если задан) перебивает auto-discovered resource.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

const (
	mcpProtocolVersion       = "2025-03-26"
	headerMCPProtocolVersion = "MCP-Protocol-Version"

	wellKnownAS  = "/.well-known/oauth-authorization-server"
	wellKnownPRM = "/.well-known/oauth-protected-resource"
)

// AuthServerMetadata — частичная модель ответа RFC 8414
// (Authorization Server Metadata).
type AuthServerMetadata struct {
	Issuer                            string   `json:"issuer,omitempty"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported,omitempty"`
	GrantTypesSupported               []string `json:"grant_types_supported,omitempty"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported,omitempty"`
	RevocationEndpoint                string   `json:"revocation_endpoint,omitempty"`
	JwksURI                           string   `json:"jwks_uri,omitempty"`
}

// ProtectedResourceMetadata — частичная модель ответа RFC 9728.
type ProtectedResourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
}

// validateEndpointURL проверяет URL, полученный от удалённого сервера
// (resource_metadata, authorization_servers, *_endpoint): абсолютный URL со
// схемой https (http — только при allowHTTP), непустым хостом и без userinfo.
// Другие схемы (javascript:, file: и т.п.) отклоняются всегда.
func validateEndpointURL(raw string, allowHTTP bool) (*url.URL, error) {
	if raw == "" {
		return nil, errors.New("oauth: empty endpoint URL")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("oauth: invalid endpoint URL %q: %w", raw, err)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !allowHTTP {
			return nil, fmt.Errorf("oauth: endpoint URL %q must use https (pass --allow-http for development only)", raw)
		}
	case "":
		return nil, fmt.Errorf("oauth: endpoint URL %q is not absolute", raw)
	default:
		return nil, fmt.Errorf("oauth: endpoint URL %q has unsupported scheme %q", raw, u.Scheme)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("oauth: endpoint URL %q has no host", raw)
	}
	if u.User != nil {
		return nil, fmt.Errorf("oauth: endpoint URL %q must not contain userinfo", raw)
	}
	return u, nil
}

// parseWWWAuthenticate разбирает значение заголовка WWW-Authenticate
// для схемы Bearer (RFC 6750 §3) и возвращает params в виде map.
// Возвращает nil, если challenge не Bearer.
func parseWWWAuthenticate(s string) map[string]string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	// Префикс схемы (case-insensitive).
	const scheme = "bearer"
	if len(s) < len(scheme) || !strings.EqualFold(s[:len(scheme)], scheme) {
		return nil
	}
	rest := strings.TrimSpace(s[len(scheme):])
	out := map[string]string{}
	// Разбираем list of key=value через запятую, уважая кавычки.
	pos := 0
	for pos < len(rest) {
		// skip ws/commas
		for pos < len(rest) && (rest[pos] == ' ' || rest[pos] == '\t' || rest[pos] == ',') {
			pos++
		}
		if pos >= len(rest) {
			break
		}
		// читаем key
		keyStart := pos
		for pos < len(rest) && rest[pos] != '=' && rest[pos] != ',' {
			pos++
		}
		key := strings.TrimSpace(rest[keyStart:pos])
		if key == "" {
			// нет смысла продолжать с пустым ключом — пропускаем символ.
			if pos < len(rest) {
				pos++
			}
			continue
		}
		if pos >= len(rest) || rest[pos] != '=' {
			// одиночный токен без значения — игнорируем.
			continue
		}
		pos++ // skip '='
		// skip whitespace before value
		for pos < len(rest) && (rest[pos] == ' ' || rest[pos] == '\t') {
			pos++
		}
		// читаем value: либо quoted-string, либо token до запятой.
		var val string
		if pos < len(rest) && rest[pos] == '"' {
			pos++ // skip opening quote
			var b strings.Builder
			for pos < len(rest) {
				c := rest[pos]
				if c == '\\' && pos+1 < len(rest) {
					b.WriteByte(rest[pos+1])
					pos += 2
					continue
				}
				if c == '"' {
					pos++ // skip closing quote
					break
				}
				b.WriteByte(c)
				pos++
			}
			val = b.String()
		} else {
			valStart := pos
			for pos < len(rest) && rest[pos] != ',' {
				pos++
			}
			val = strings.TrimSpace(rest[valStart:pos])
		}
		out[strings.ToLower(key)] = val
	}
	return out
}

// discover выполняет двухступенчатый discovery:
//  1. Если есть resource_metadata — RFC 9728 → берём authorization_servers[0]
//  2. RFC 8414 для AS, fallback на дефолтные пути на 404.
//
// resourceMetadataURL — значение параметра resource_metadata из challenge
// (может быть пустым).
// serverURL — cfg.ServerURL: используется как fallback auth-base когда PRM
// недоступен.
// resourceOverride — cfg.Resource: перебивает auto-discovered resource.
//
// Возвращает финальный AuthServerMetadata и resource hint (может быть "").
func (p *Provider) discover(ctx context.Context, resourceMetadataURL, serverURL, resourceOverride string) (*AuthServerMetadata, string, error) {
	var (
		asID     string // идентификатор AS как его назвал источник (PRM либо origin ServerURL)
		resource string
	)

	if resourceMetadataURL != "" {
		if _, vErr := validateEndpointURL(resourceMetadataURL, p.allowHTTP()); vErr != nil {
			return nil, "", fmt.Errorf("resource_metadata: %w", vErr)
		}
		prm, err := p.fetchPRM(ctx, resourceMetadataURL)
		if err != nil {
			return nil, "", fmt.Errorf("fetch protected resource metadata: %w", err)
		}
		if len(prm.AuthorizationServers) == 0 {
			return nil, "", errors.New("protected resource metadata has no authorization_servers")
		}
		if _, vErr := validateEndpointURL(prm.AuthorizationServers[0], p.allowHTTP()); vErr != nil {
			return nil, "", fmt.Errorf("authorization_servers[0]: %w", vErr)
		}
		asID = prm.AuthorizationServers[0]
		resource = prm.Resource
		// resource из PRM проверяем до обращений к AS. С явным --resource
		// пользователь задал значение сознательно — проверка пропускается.
		if resourceOverride == "" {
			if vErr := p.checkPRMResource(resource, serverURL); vErr != nil {
				return nil, "", vErr
			}
		}
	} else {
		base, err := authBaseFromServerURL(serverURL)
		if err != nil {
			return nil, "", err
		}
		asID = base
	}

	meta, err := p.fetchAS(ctx, asID)
	if err != nil {
		return nil, "", err
	}

	if resourceOverride != "" {
		resource = resourceOverride
	}

	return meta, resource, nil
}

// checkPRMResource проверяет resource из PRM (RFC 9728): схема, хост и порт
// (с учётом порта по умолчанию для схемы) должны совпасть с serverURL, а путь
// serverURL — равняться пути resource или лежать под ним по границе сегмента
// (без учёта завершающего "/"). Query и fragment resource игнорируются.
// Пустой resource — предупреждение и прежнее поведение.
func (p *Provider) checkPRMResource(resource, serverURL string) error {
	if resource == "" {
		p.log.Warn("oauth: protected resource metadata has no resource, skipping resource check")
		return nil
	}
	ru, err := url.Parse(resource)
	if err != nil {
		return fmt.Errorf("oauth: invalid resource %q in protected resource metadata: %w", resource, err)
	}
	su, err := url.Parse(serverURL)
	if err != nil {
		return fmt.Errorf("oauth: parse server URL: %w", err)
	}
	mismatch := func() error {
		return fmt.Errorf("oauth: protected resource metadata resource %q does not match server URL %q (use --resource to override)", resource, serverURL)
	}
	if !strings.EqualFold(ru.Scheme, su.Scheme) || !strings.EqualFold(ru.Hostname(), su.Hostname()) {
		return mismatch()
	}
	if effectivePort(ru) != effectivePort(su) {
		return mismatch()
	}
	rp := strings.TrimRight(ru.EscapedPath(), "/")
	sp := strings.TrimRight(su.EscapedPath(), "/")
	if sp != rp && !strings.HasPrefix(sp, rp+"/") {
		return mismatch()
	}
	return nil
}

// effectivePort возвращает порт URL, подставляя порт по умолчанию для схемы.
func effectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return "443"
	case "http":
		return "80"
	}
	return ""
}

// authBaseFromServerURL вычисляет origin (scheme://host[:port]) из URL.
func authBaseFromServerURL(serverURL string) (string, error) {
	if serverURL == "" {
		return "", errors.New("oauth: empty server URL")
	}
	u, err := url.Parse(serverURL)
	if err != nil {
		return "", fmt.Errorf("oauth: parse server URL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("oauth: invalid server URL %q", serverURL)
	}
	return u.Scheme + "://" + u.Host, nil
}

// fetchPRM запрашивает PRM JSON (RFC 9728).
func (p *Provider) fetchPRM(ctx context.Context, u string) (*ProtectedResourceMetadata, error) {
	body, err := p.httpGetJSON(ctx, u)
	if err != nil {
		return nil, err
	}
	var prm ProtectedResourceMetadata
	if err := json.Unmarshal(body, &prm); err != nil {
		return nil, fmt.Errorf("oauth: parse PRM: %w", err)
	}
	return &prm, nil
}

// fetchAS запрашивает Authorization Server Metadata (RFC 8414). asID —
// идентификатор сервера авторизации (authorization_servers[0] либо origin
// ServerURL); по нему строится well-known URL и проверяется issuer.
// При 404 возвращает дефолтные пути.
func (p *Provider) fetchAS(ctx context.Context, asID string) (*AuthServerMetadata, error) {
	base := strings.TrimRight(asID, "/")
	u := base + wellKnownAS

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("oauth: new AS request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set(headerMCPProtocolVersion, mcpProtocolVersion)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauth: fetch AS metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		p.log.Debug("AS metadata 404, using defaults", slog.String("base", base))
		def := defaultAuthServerMetadata(base)
		if vErr := p.validateMetadataEndpoints(def); vErr != nil {
			return nil, vErr
		}
		return def, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("oauth: AS metadata status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("oauth: read AS metadata: %w", err)
	}
	var meta AuthServerMetadata
	if err := json.Unmarshal(body, &meta); err != nil {
		return nil, fmt.Errorf("oauth: parse AS metadata: %w", err)
	}
	// issuer (RFC 8414 §3.3) должен совпадать с идентификатором AS, по которому
	// мы запросили документ, с точностью до одного завершающего "/".
	if meta.Issuer == "" {
		p.log.Warn("oauth: AS metadata has no issuer, skipping issuer check", slog.String("as", asID))
	} else if strings.TrimSuffix(meta.Issuer, "/") != strings.TrimSuffix(asID, "/") {
		return nil, fmt.Errorf("oauth: AS metadata issuer %q does not match authorization server %q", meta.Issuer, asID)
	}
	if meta.AuthorizationEndpoint == "" || meta.TokenEndpoint == "" {
		// На пустые обязательные поля возвращаем дефолты вместо ошибки —
		// плохой сервер не должен ломать клиент.
		def := defaultAuthServerMetadata(base)
		if meta.AuthorizationEndpoint == "" {
			meta.AuthorizationEndpoint = def.AuthorizationEndpoint
		}
		if meta.TokenEndpoint == "" {
			meta.TokenEndpoint = def.TokenEndpoint
		}
		if meta.RegistrationEndpoint == "" {
			meta.RegistrationEndpoint = def.RegistrationEndpoint
		}
	}
	if vErr := p.validateMetadataEndpoints(&meta); vErr != nil {
		return nil, vErr
	}
	return &meta, nil
}

// allowHTTP сообщает, допускает ли конфигурация http-эндпоинты (--allow-http).
func (p *Provider) allowHTTP() bool {
	return p.cfg != nil && p.cfg.AllowHTTP
}

// validateMetadataEndpoints применяет политику validateEndpointURL к
// authorization_endpoint, token_endpoint и непустому registration_endpoint.
func (p *Provider) validateMetadataEndpoints(meta *AuthServerMetadata) error {
	checks := []struct{ name, value string }{
		{"authorization_endpoint", meta.AuthorizationEndpoint},
		{"token_endpoint", meta.TokenEndpoint},
	}
	if meta.RegistrationEndpoint != "" {
		checks = append(checks, struct{ name, value string }{"registration_endpoint", meta.RegistrationEndpoint})
	}
	for _, c := range checks {
		if _, err := validateEndpointURL(c.value, p.allowHTTP()); err != nil {
			return fmt.Errorf("AS metadata %s: %w", c.name, err)
		}
	}
	return nil
}

// defaultAuthServerMetadata возвращает дефолтные пути относительно base.
func defaultAuthServerMetadata(base string) *AuthServerMetadata {
	base = strings.TrimRight(base, "/")
	return &AuthServerMetadata{
		Issuer:                base,
		AuthorizationEndpoint: base + "/authorize",
		TokenEndpoint:         base + "/token",
		RegistrationEndpoint:  base + "/register",
	}
}

// httpGetJSON — GET с MCP-Protocol-Version header, body как []byte.
func (p *Provider) httpGetJSON(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("oauth: new request %s: %w", u, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set(headerMCPProtocolVersion, mcpProtocolVersion)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauth: GET %s: %w", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("oauth: GET %s: status %d", u, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("oauth: read body: %w", err)
	}
	return body, nil
}
