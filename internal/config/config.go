// Package config описывает параметры запуска прокси (CLI флаги + env vars)
// и парсит их из argv.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
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

// ErrHelp возвращается из Parse, когда пользователь запросил --help/-h.
// Вызывающая сторона может выбрать, печатать ли usage и завершаться с кодом 0.
var ErrHelp = errors.New("help requested")

// rfc7230Token — допустимые символы в имени HTTP-заголовка (RFC 7230, token).
var rfc7230Token = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+\-.^_` + "`" + `|~]+$`)

// reservedHeaders — заголовки, которые пользователю запрещено переопределять
// (управляются самим прокси / MCP-протоколом / транспортом).
// Authorization сознательно НЕ в этом списке — пользователь может задать
// внешний Bearer-токен, если не использует OAuth.
var reservedHeaders = map[string]struct{}{
	"mcp-session-id":       {},
	"mcp-protocol-version": {},
	"accept":               {},
	"content-type":         {},
	"content-length":       {},
	"host":                 {},
	"transfer-encoding":    {},
	"connection":           {},
}

// usageText — короткий help-блок. Печатается в stderr при --help.
const usageText = `mcp-remote — stdio↔Streamable HTTP MCP proxy.

Usage:
  mcp-remote <server-url> [port] [flags]

Positional arguments:
  server-url           Remote MCP server URL (https required unless --allow-http).
  port                 Optional callback HTTP port (1..65535).

Flags:
  --header "K: V"      Extra HTTP header, repeatable. ${ENV} interpolation supported.
  --allow-http         Allow non-https server-url (insecure; testing only).
  --debug              Verbose logging.
  --silent             Errors only.
  --auth-timeout d     OAuth callback timeout. Seconds (e.g. 60) or Go duration (e.g. 2m).
                       Default 30s.
  --static-oauth-client-metadata <json|@path>
                       Pre-supplied OAuth client_metadata. "@path" reads file.
  --static-oauth-client-info <json|@path>
                       Pre-supplied OAuth client_id/secret. "@path" reads file.
  --resource <url>     RFC 9728 resource indicator override.
  --host <h>           Callback bind host (default 127.0.0.1).
  --config-dir <path>  Token storage root. Default $MCP_REMOTE_CONFIG_DIR or
                       <os.UserConfigDir>/mcp-remote.
  -h, --help           Show this help and exit.
`

// Parse разбирает argv (без имени программы) в *Config.
//
// При ошибке возвращает (nil, err). При --help возвращает (nil, ErrHelp) и
// печатает usage в os.Stderr — вызывающая сторона решает, завершаться или нет.
func Parse(args []string) (*Config, error) {
	var (
		headers     []string
		allowHTTP   bool
		debug       bool
		silent      bool
		authTimeout string
		staticMeta  string
		staticInfo  string
		resource    string
		host        string
		configDir   string
		showHelp    bool
	)

	// Ручной разбор: standard flag не позволяет смешивать позиционные аргументы
	// с флагами в произвольном порядке (после первого non-flag — стоп). Нам нужно
	// поддерживать `URL [PORT] --flag ...`, `--flag ... URL [PORT]` и любые комбинации.
	var positionals []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-h" || a == "--help":
			showHelp = true
		case a == "--allow-http":
			allowHTTP = true
		case a == "--debug":
			debug = true
		case a == "--silent":
			silent = true
		case a == "--header" || strings.HasPrefix(a, "--header="):
			v, j, err := flagValue(args, i, "--header")
			if err != nil {
				return nil, err
			}
			i = j
			headers = append(headers, v)
		case a == "--auth-timeout" || strings.HasPrefix(a, "--auth-timeout="):
			v, j, err := flagValue(args, i, "--auth-timeout")
			if err != nil {
				return nil, err
			}
			i = j
			authTimeout = v
		case a == "--static-oauth-client-metadata" || strings.HasPrefix(a, "--static-oauth-client-metadata="):
			v, j, err := flagValue(args, i, "--static-oauth-client-metadata")
			if err != nil {
				return nil, err
			}
			i = j
			staticMeta = v
		case a == "--static-oauth-client-info" || strings.HasPrefix(a, "--static-oauth-client-info="):
			v, j, err := flagValue(args, i, "--static-oauth-client-info")
			if err != nil {
				return nil, err
			}
			i = j
			staticInfo = v
		case a == "--resource" || strings.HasPrefix(a, "--resource="):
			v, j, err := flagValue(args, i, "--resource")
			if err != nil {
				return nil, err
			}
			i = j
			resource = v
		case a == "--host" || strings.HasPrefix(a, "--host="):
			v, j, err := flagValue(args, i, "--host")
			if err != nil {
				return nil, err
			}
			i = j
			host = v
		case a == "--config-dir" || strings.HasPrefix(a, "--config-dir="):
			v, j, err := flagValue(args, i, "--config-dir")
			if err != nil {
				return nil, err
			}
			i = j
			configDir = v
		case strings.HasPrefix(a, "--"):
			return nil, fmt.Errorf("unknown flag: %s", a)
		case strings.HasPrefix(a, "-") && len(a) > 1 && a != "-":
			// Допускаем только -h как короткий алиас; всё прочее — ошибка.
			return nil, fmt.Errorf("unknown flag: %s", a)
		default:
			positionals = append(positionals, a)
		}
	}

	if showHelp {
		fmt.Fprint(os.Stderr, usageText)
		return nil, ErrHelp
	}

	cfg := &Config{
		AuthTimeout: 30 * time.Second,
		Host:        "127.0.0.1",
		AllowHTTP:   allowHTTP,
		Debug:       debug,
		Silent:      silent,
		Resource:    resource,
	}

	if len(positionals) == 0 {
		return nil, errors.New("ServerURL required")
	}
	if len(positionals) > 2 {
		return nil, fmt.Errorf("unexpected positional argument: %q", positionals[2])
	}

	rawURL := positionals[0]
	if rawURL == "" {
		return nil, errors.New("ServerURL required")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse ServerURL %q: %w", rawURL, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("parse ServerURL %q: scheme and host required", rawURL)
	}
	if u.Scheme != "https" && !allowHTTP {
		return nil, errors.New("non-https URL requires --allow-http")
	}
	cfg.ServerURL = rawURL

	if len(positionals) == 2 {
		port, err := strconv.Atoi(positionals[1])
		if err != nil {
			return nil, fmt.Errorf("parse port %q: %w", positionals[1], err)
		}
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("port out of range (1..65535): %d", port)
		}
		cfg.Port = port
	}

	for _, raw := range headers {
		h, err := parseHeader(raw)
		if err != nil {
			return nil, fmt.Errorf("parse --header %q: %w", raw, err)
		}
		cfg.Headers = append(cfg.Headers, h)
	}

	if authTimeout != "" {
		d, err := parseAuthTimeout(authTimeout)
		if err != nil {
			return nil, fmt.Errorf("parse --auth-timeout %q: %w", authTimeout, err)
		}
		cfg.AuthTimeout = d
	}

	if cfg.StaticOAuthClientMetadataJSON, err = loadJSONFlag(staticMeta, "--static-oauth-client-metadata"); err != nil {
		return nil, err
	}
	if cfg.StaticOAuthClientInfoJSON, err = loadJSONFlag(staticInfo, "--static-oauth-client-info"); err != nil {
		return nil, err
	}

	if host != "" {
		cfg.Host = host
	}

	cfg.ConfigDir, err = resolveConfigDir(configDir)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

// resolveConfigDir выбирает каталог хранения по приоритету
// --config-dir > $MCP_REMOTE_CONFIG_DIR > <UserConfigDir>/mcp-remote > $HOME/.mcp-auth.
func resolveConfigDir(flagVal string) (string, error) {
	if flagVal != "" {
		return flagVal, nil
	}
	if env := os.Getenv("MCP_REMOTE_CONFIG_DIR"); env != "" {
		return env, nil
	}
	if d, err := os.UserConfigDir(); err == nil && d != "" {
		return filepath.Join(d, "mcp-remote"), nil
	}
	if home := os.Getenv("HOME"); home != "" {
		return filepath.Join(home, ".mcp-auth"), nil
	}
	return "", errors.New("resolve config dir: no UserConfigDir and no HOME")
}

// loadJSONFlag разбирает значение --static-oauth-client-{metadata,info}.
// Пустой raw → nil, без ошибки.
func loadJSONFlag(raw, flagName string) ([]byte, error) {
	if raw == "" {
		return nil, nil
	}
	b, err := loadJSONArg(raw)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", flagName, err)
	}
	if !json.Valid(b) {
		return nil, fmt.Errorf("parse %s: invalid JSON", flagName)
	}
	return b, nil
}

// flagValue извлекает значение для флага в форме `--flag value` или `--flag=value`.
// Возвращает значение и новый индекс (последний потреблённый элемент args).
func flagValue(args []string, i int, name string) (string, int, error) {
	a := args[i]
	if eq := strings.IndexByte(a, '='); eq >= 0 {
		// --flag=value
		return a[eq+1:], i, nil
	}
	if i+1 >= len(args) {
		return "", i, fmt.Errorf("flag %s requires a value", name)
	}
	return args[i+1], i + 1, nil
}

// parseHeader разбирает строку "K: V" / "K:V" в Header с валидацией по RFC 7230
// и проверкой reserved-имён.
func parseHeader(raw string) (Header, error) {
	idx := strings.IndexByte(raw, ':')
	if idx < 0 {
		return Header{}, errors.New(`missing ":" separator`)
	}
	name := strings.TrimSpace(raw[:idx])
	value := raw[idx+1:]
	// "K: V" — пробел сразу после ':' считается синтаксическим; убираем ровно один,
	// потом trim left, чтобы выровнять формат, но не трогаем хвост (значение
	// может валидно заканчиваться пробелом, хотя это редкий случай).
	value = strings.TrimLeft(value, " \t")

	if name == "" {
		return Header{}, errors.New("empty header name")
	}
	if !rfc7230Token.MatchString(name) {
		return Header{}, fmt.Errorf("invalid header name %q (must match RFC 7230 token)", name)
	}
	if _, bad := reservedHeaders[strings.ToLower(name)]; bad {
		return Header{}, fmt.Errorf("header %q is reserved and managed by the proxy", name)
	}

	// ${ENV} интерполяция — выполняем после извлечения имени, иначе env с двоеточием
	// мог бы изменить семантику разделителя.
	value = os.ExpandEnv(value)

	if strings.ContainsAny(value, "\r\n\x00") {
		return Header{}, errors.New("header value contains CR, LF or NUL")
	}
	return Header{Name: name, Value: value}, nil
}

// parseAuthTimeout: чистое целое → секунды; иначе пробуем time.ParseDuration.
func parseAuthTimeout(s string) (time.Duration, error) {
	if n, err := strconv.Atoi(s); err == nil {
		if n <= 0 {
			return 0, fmt.Errorf("must be positive: %d", n)
		}
		return time.Duration(n) * time.Second, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	if d <= 0 {
		return 0, fmt.Errorf("must be positive: %s", d)
	}
	return d, nil
}

// loadJSONArg: если аргумент начинается с '@' — читаем файл; иначе возвращаем bytes сами.
// json.Valid проверяется на уровне Parse.
func loadJSONArg(arg string) ([]byte, error) {
	if strings.HasPrefix(arg, "@") {
		path := arg[1:]
		if path == "" {
			return nil, errors.New(`"@" requires a file path`)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		return b, nil
	}
	return []byte(arg), nil
}
