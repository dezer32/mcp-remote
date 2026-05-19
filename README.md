# mcp-remote (Go)

Локальный stdio↔Streamable HTTP MCP-прокси: позволяет подключать удалённые MCP-серверы
(Streamable HTTP, спецификация 2025-03-26) к клиентам, поддерживающим только stdio
(например, Claude Desktop). Go-аналог npm-пакета [`mcp-remote`](https://github.com/geelen/mcp-remote).

## Статус

**WIP** — проект в активной разработке. Скелет с интерфейсами зафиксирован;
реализация распределена по worker-юнитам.

## Структура

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

Сборка: `make build`. Тесты: `make test`. Интеграция: `make test-integration`.

## Лицензия

MIT.
