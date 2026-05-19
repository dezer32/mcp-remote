package oauth

// Storage хранит токены, client_info и metadata авторизационного сервера на
// диске под единым корнем:
//   <config_dir>/<sha256(server_url)[:16]>/
//     tokens.json   (0600) — access_token, refresh_token, expires_at
//     client.json   (0600) — client_id, optional client_secret
//     metadata.json (0600) — authorization_server metadata + resource
// директории создаются с 0700. На Windows fmode игнорируется — это OK.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	fileTokens   = "tokens.json"
	fileClient   = "client.json"
	fileMetadata = "metadata.json"

	fmodeFile = 0o600
	fmodeDir  = 0o700
)

// Tokens — OAuth access/refresh tokens с моментом истечения.
type Tokens struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"` // zero = never expires (no expires_in)
	TokenType    string    `json:"token_type,omitempty"` // обычно "Bearer"
	Scope        string    `json:"scope,omitempty"`
}

// ClientInfo — данные, выданные авторизационным сервером после Dynamic Client
// Registration (RFC 7591) либо предзаданные пользователем.
type ClientInfo struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at,omitempty"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at,omitempty"`
	RegistrationAccessToken string   `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string   `json:"registration_client_uri,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
}

// storedMetadata — сериализуемый контейнер для AS metadata + resource hint.
type storedMetadata struct {
	Metadata *AuthServerMetadata `json:"metadata"`
	Resource string              `json:"resource,omitempty"`
}

// Storage — корень файлового хранилища одного MCP-сервера.
type Storage struct {
	root string
}

// NewStorage создаёт каталог под выданный configDir/serverURL и возвращает
// Storage с гарантией, что директория существует.
func NewStorage(configDir, serverURL string) (*Storage, error) {
	if configDir == "" {
		return nil, errors.New("oauth: configDir is empty")
	}
	if serverURL == "" {
		return nil, errors.New("oauth: serverURL is empty")
	}
	sum := sha256.Sum256([]byte(serverURL))
	id := hex.EncodeToString(sum[:])[:16]
	root := filepath.Join(configDir, id)
	if err := os.MkdirAll(root, fmodeDir); err != nil {
		return nil, fmt.Errorf("oauth: mkdir storage: %w", err)
	}
	return &Storage{root: root}, nil
}

// Root возвращает абсолютный путь к каталогу хранилища (для отладки/тестов).
func (s *Storage) Root() string { return s.root }

// ---------------------------------------------------------------------------
// tokens
// ---------------------------------------------------------------------------

// LoadTokens читает tokens.json. Возвращает os.ErrNotExist если файла нет.
func (s *Storage) LoadTokens() (*Tokens, error) {
	var t Tokens
	if err := s.readJSON(fileTokens, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

// SaveTokens атомарно перезаписывает tokens.json (0600).
func (s *Storage) SaveTokens(t *Tokens) error {
	if t == nil {
		return errors.New("oauth: SaveTokens nil")
	}
	return s.writeJSON(fileTokens, t)
}

// ClearTokens удаляет tokens.json; отсутствие файла — не ошибка.
func (s *Storage) ClearTokens() error {
	return s.remove(fileTokens)
}

// ---------------------------------------------------------------------------
// client
// ---------------------------------------------------------------------------

// LoadClient читает client.json.
func (s *Storage) LoadClient() (*ClientInfo, error) {
	var c ClientInfo
	if err := s.readJSON(fileClient, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// SaveClient атомарно перезаписывает client.json (0600).
func (s *Storage) SaveClient(c *ClientInfo) error {
	if c == nil {
		return errors.New("oauth: SaveClient nil")
	}
	return s.writeJSON(fileClient, c)
}

// ---------------------------------------------------------------------------
// metadata
// ---------------------------------------------------------------------------

// LoadMetadata читает metadata.json.
func (s *Storage) LoadMetadata() (*AuthServerMetadata, string, error) {
	var m storedMetadata
	if err := s.readJSON(fileMetadata, &m); err != nil {
		return nil, "", err
	}
	return m.Metadata, m.Resource, nil
}

// SaveMetadata атомарно перезаписывает metadata.json (0600).
func (s *Storage) SaveMetadata(m *AuthServerMetadata, resource string) error {
	if m == nil {
		return errors.New("oauth: SaveMetadata nil")
	}
	return s.writeJSON(fileMetadata, storedMetadata{Metadata: m, Resource: resource})
}

// ---------------------------------------------------------------------------
// internals
// ---------------------------------------------------------------------------

func (s *Storage) path(name string) string { return filepath.Join(s.root, name) }

func (s *Storage) readJSON(name string, v any) error {
	data, err := os.ReadFile(s.path(name))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("oauth: parse %s: %w", name, err)
	}
	return nil
}

func (s *Storage) writeJSON(name string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("oauth: marshal %s: %w", name, err)
	}
	if err := os.WriteFile(s.path(name), data, fmodeFile); err != nil {
		return fmt.Errorf("oauth: write %s: %w", name, err)
	}
	return nil
}

func (s *Storage) remove(name string) error {
	err := os.Remove(s.path(name))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
