// Package config описывает параметры запуска прокси (CLI флаги + env vars)
// и парсит их из argv.
package config

import (
	"errors"
	"time"
)

// Header — HTTP-заголовок, добавляемый ко всем исходящим запросам к remote.
type Header struct {
	Name  string
	Value string
}

// Config — итоговый набор параметров запуска.
type Config struct {
	// ServerURL — URL удалённого MCP-сервера (Streamable HTTP endpoint).
	ServerURL string
	// Port — необязательный позиционный аргумент (callback HTTP port hint;
	// если 0 → выбирается ОС).
	Port int
	// Headers — дополнительные HTTP-заголовки от пользователя (--header).
	Headers []Header
	// AllowHTTP — разрешить не-HTTPS ServerURL (по умолчанию запрещено).
	AllowHTTP bool
	// Debug — verbose-логирование.
	Debug bool
	// Silent — только ERROR и выше.
	Silent bool
	// AuthTimeout — таймаут локального OAuth callback сервера.
	AuthTimeout time.Duration
	// StaticOAuthClientMetadataJSON — pre-supplied client_metadata для DCR (или прямой override).
	StaticOAuthClientMetadataJSON []byte
	// StaticOAuthClientInfoJSON — pre-supplied client_id/secret (если DCR не нужен).
	StaticOAuthClientInfoJSON []byte
	// Resource — RFC9728 resource override (overrides auto-discovery).
	Resource string
	// Host — bind host для OAuth callback listener (по умолчанию 127.0.0.1).
	Host string
	// ConfigDir — корень хранения токенов и метаданных
	// (по умолчанию <user-config>/mcp-remote, можно через MCP_REMOTE_CONFIG_DIR).
	ConfigDir string
}

// Parse разбирает argv (без имени программы) в *Config.
// Реализация — unit 1.
func Parse(args []string) (*Config, error) {
	return nil, errors.New("config.Parse: not implemented")
}
