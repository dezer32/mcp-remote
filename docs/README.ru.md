[English](../README.md) | **Русский**

# mcp-remote

Локальный stdio↔Streamable HTTP MCP-прокси на Go для подключения удалённых MCP-серверов к stdio-клиентам (Claude Desktop и др.).

[![Go Version](https://img.shields.io/badge/go-1.26%2B-00ADD8?logo=go)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../LICENSE)
[![Release](https://img.shields.io/github/v/release/dezer32/mcp-remote?include_prereleases)](https://github.com/dezer32/mcp-remote/releases)

## Что это

`mcp-remote` — прокси, позволяющий MCP-клиентам с поддержкой только stdio
(в первую очередь — Claude Desktop) общаться с удалёнными MCP-серверами,
которые работают по транспорту [Streamable HTTP](https://modelcontextprotocol.io/specification/2025-03-26/basic/transports#streamable-http)
(спецификация MCP 2025-03-26). Это Go-порт npm-пакета
[`mcp-remote`](https://github.com/geelen/mcp-remote) с акцентом на одиночный
self-contained бинарь без runtime-зависимостей.

Под капотом mcp-remote запускается как подпроцесс клиента, читает JSON-RPC
сообщения из stdin, пробрасывает их по HTTPS на remote MCP-эндпоинт и
отдаёт ответы (включая SSE-стрим server-initiated сообщений) обратно в
stdout. При получении HTTP 401 он автоматически запускает OAuth 2.1 поток
(PKCE + RFC7591 Dynamic Client Registration + RFC9728/RFC8414 discovery),
открывает браузер, ловит redirect на localhost и сохраняет токены на диск
с правами 0600. Повторные запуски используют сохранённые токены прозрачно
для пользователя.

## Установка

### Через Go toolchain

```bash
go install github.com/dezer32/mcp-remote@latest
```

Бинарь будет установлен в `$(go env GOBIN)` (по умолчанию `$GOPATH/bin`).

### Готовые сборки

Скачайте архив для своей платформы с
[GitHub Releases](https://github.com/dezer32/mcp-remote/releases): доступны
сборки для `darwin`, `linux`, `windows` на `amd64` и `arm64`. Распакуйте и
положите `mcp-remote` в любую директорию из `$PATH`.

```bash
# macOS / Linux пример
tar -xzf mcp-remote_<version>_<os>_<arch>.tar.gz
sudo install mcp-remote /usr/local/bin/
```

### Homebrew (планируется)

```bash
brew install dezer32/tap/mcp-remote
```

## Использование

mcp-remote запускается клиентом — самостоятельно его руками вызывать
обычно не нужно. Достаточно прописать команду и аргументы в конфиге
клиента.

### Claude Desktop

Файл конфигурации:

| ОС | Путь |
|----|------|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

Минимальный пример:

```json
{
  "mcpServers": {
    "my-server": {
      "command": "/usr/local/bin/mcp-remote",
      "args": ["https://your-mcp-server.example.com/mcp"]
    }
  }
}
```

Пример с `Authorization` заголовком и подстановкой переменной окружения:

```json
{
  "mcpServers": {
    "my-server": {
      "command": "/usr/local/bin/mcp-remote",
      "args": [
        "https://api.example.com/mcp",
        "--header",
        "Authorization:Bearer ${TOKEN}"
      ],
      "env": {
        "TOKEN": "sk-..."
      }
    }
  }
}
```

Ещё примеры — в [`examples/claude_desktop_config.json`](../examples/claude_desktop_config.json).

## CLI флаги

```
mcp-remote <server-url> [port] [flags]
```

| Флаг | Аргумент | Описание |
|------|----------|----------|
| `--header` | `"K: V"` | HTTP-заголовок, добавляется ко всем запросам. Можно повторять. Поддерживает `${ENV}` интерполяцию. |
| `--allow-http` | — | Разрешить не-HTTPS `server-url` (по умолчанию запрещён). |
| `--debug` | — | Verbose-логи в stderr (уровень DEBUG). |
| `--silent` | — | Логировать только ошибки (уровень ERROR). |
| `--auth-timeout` | `30s` / `30` | Таймаут ожидания OAuth callback. Принимает Go duration (`30s`, `2m`) или число секунд. По умолчанию `30s`. |
| `--static-oauth-client-metadata` | `<json>` или `@<path>` | Переопределить client_metadata для DCR. JSON inline или `@file.json`. |
| `--static-oauth-client-info` | `<json>` или `@<path>` | Готовый `client_id` (и при необходимости `client_secret`) — DCR пропускается. |
| `--resource` | `<uri>` | Переопределить RFC9728 `resource` URI (по умолчанию автодискавери). |
| `--host` | `127.0.0.1` | Bind host для локального OAuth callback. По умолчанию `127.0.0.1`. |
| `--config-dir` | `<path>` | Корень хранения токенов и OAuth-метаданных. |

Позиционные аргументы: первый — обязательный URL remote MCP-сервера,
второй (опционально) — желаемый порт локального callback-сервера; если
не задан или `0`, порт выбирает ОС.

## Переменные окружения

| Переменная | Назначение |
|------------|------------|
| `MCP_REMOTE_CONFIG_DIR` | Переопределяет корень хранения токенов (эквивалент `--config-dir`, флаг имеет приоритет). |
| `BROWSER` | Путь к executable, который открывает OAuth-URL. Если задан — перебивает `open` / `xdg-open` / `cmd /c start`. |

## OAuth

При получении HTTP `401 Unauthorized` от remote MCP-сервера mcp-remote
автоматически запускает OAuth-флоу:

1. Парсит `WWW-Authenticate` и/или выполняет RFC9728 protected-resource
   discovery, чтобы найти Authorization Server.
2. Делает RFC8414 metadata discovery у Authorization Server.
3. Если нужно — выполняет RFC7591 Dynamic Client Registration (или
   использует данные из `--static-oauth-client-info`).
4. Поднимает локальный HTTP-сервер на `--host:port` для приёма callback.
5. Открывает браузер пользователя на authorization endpoint
   (PKCE S256, state, redirect_uri = `http://<host>:<port>/callback`).
6. После успешного редиректа обменивает `code` на access/refresh токены.
7. Сохраняет токены, client info и server metadata в config-dir.

### Где хранятся токены

Корень: `--config-dir`, либо `MCP_REMOTE_CONFIG_DIR`, либо системная
директория конфига (`~/.config/mcp-remote` на Linux,
`~/Library/Application Support/mcp-remote` на macOS,
`%AppData%\mcp-remote` на Windows).

Внутри — поддиректория на каждый сервер, имя = первые 16 hex-символов
`sha256(server-url)`:

```
<config-dir>/
  <hash16>/
    tokens.json     # access + refresh token, expiry
    client.json     # client_id / client_secret
    metadata.json   # discovered authorization server metadata
```

Все файлы — `0600`, директории — `0700`.

### Сброс токенов

```bash
# macOS
rm -rf "$HOME/Library/Application Support/mcp-remote/<hash16>"
# Linux
rm -rf "$HOME/.config/mcp-remote/<hash16>"
# Windows (PowerShell)
Remove-Item -Recurse -Force "$env:AppData\mcp-remote\<hash16>"
```

Удалить всё сразу — снести корневую директорию полностью.

## Troubleshooting

- **Ничего не видно** — добавьте `--debug`, mcp-remote пишет подробные
  логи в stderr; Claude Desktop сохраняет stderr подпроцессов в свой
  лог-файл.
- **OAuth-окно не открывается** — задайте переменную окружения
  `BROWSER` с путём до исполняемого файла браузера; либо откройте
  напечатанный в stderr URL вручную.
- **Зависает на callback** — увеличьте `--auth-timeout`, проверьте
  что redirect_uri разрешён на стороне Authorization Server.
- **Сервер не поддерживает DCR** — зарегистрируйте клиент вручную и
  передайте `--static-oauth-client-info '{"client_id":"...","client_secret":"..."}'`
  (или `@/path/to/file.json`).
- **Сброс залипшего state** — удалите директорию с токенами для этого
  сервера (см. выше) и перезапустите клиент.
- **HTTP вместо HTTPS** — в dev-окружении добавьте `--allow-http`. В
  production этого делать **не следует**.

## Безопасность

- HTTPS обязателен. Не-HTTPS URL отвергается, пока не передан
  `--allow-http` (только для разработки).
- Cross-origin редиректы при обмене на token endpoint блокируются —
  защита от утечки `code` / `refresh_token` на сторонний хост.
- Reserved headers (`Mcp-Session-Id`, `Accept`, `Content-Type`,
  `Content-Length`, `Host`, `Connection`, `Upgrade` и пр.) нельзя
  переопределить через `--header` — попытка приведёт к ошибке валидации.
- Если через `--header` задан `Authorization`, он перебивает OAuth-флоу:
  mcp-remote не будет инициировать авторизацию и не сохранит токены.
- Файлы токенов сохраняются с правами `0600`, директории — `0700`.
- `${ENV}` в значениях `--header` берётся из окружения процесса
  mcp-remote; в Claude Desktop окружение задаётся через ключ `env` в
  конфиге сервера.

## Структура проекта

| Пакет | Назначение |
|-------|------------|
| `internal/jsonrpc` | JSON-RPC 2.0 типы и encoding |
| `internal/logging` | Структурированное логирование (slog → stderr) |
| `internal/config`  | CLI-флаги, env vars, валидация |
| `internal/stdio`   | Транспорт stdin/stdout |
| `internal/httpmcp` | Streamable HTTP клиент к remote MCP |
| `internal/oauth`   | OAuth 2.1 (PKCE + RFC7591 DCR + RFC9728/RFC8414 discovery) |
| `internal/proxy`   | Маршрутизация JSON-RPC между transport и remote |
| `main.go`          | Wire-up |

Сборка: `make build`. Тесты: `make test`. Интеграционные: `make test-integration`.

## Лицензия

MIT — см. [LICENSE](../LICENSE).
