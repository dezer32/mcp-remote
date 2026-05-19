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
		asBase   string
		resource string
	)

	if resourceMetadataURL != "" {
		prm, err := p.fetchPRM(ctx, resourceMetadataURL)
		if err != nil {
			return nil, "", fmt.Errorf("fetch protected resource metadata: %w", err)
		}
		if len(prm.AuthorizationServers) == 0 {
			return nil, "", errors.New("protected resource metadata has no authorization_servers")
		}
		asBase = strings.TrimRight(prm.AuthorizationServers[0], "/")
		resource = prm.Resource
	} else {
		base, err := authBaseFromServerURL(serverURL)
		if err != nil {
			return nil, "", err
		}
		asBase = base
	}

	meta, err := p.fetchAS(ctx, asBase)
	if err != nil {
		return nil, "", err
	}

	if resourceOverride != "" {
		resource = resourceOverride
	}

	return meta, resource, nil
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

// fetchAS запрашивает Authorization Server Metadata (RFC 8414) у base.
// При 404 возвращает дефолтные пути.
func (p *Provider) fetchAS(ctx context.Context, base string) (*AuthServerMetadata, error) {
	base = strings.TrimRight(base, "/")
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
		return defaultAuthServerMetadata(base), nil
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
	return &meta, nil
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
