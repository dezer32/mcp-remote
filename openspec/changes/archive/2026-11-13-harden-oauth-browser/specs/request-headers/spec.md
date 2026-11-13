# Spec Delta

## Purpose

Пользовательские HTTP-заголовки (`--header`), которые прокси добавляет к запросам к remote MCP-серверу, и защита заголовков, которыми управляет сам прокси или HTTP-транспорт.

## ADDED Requirements

### Requirement: Зарезервированные имена заголовков отклоняются
Прокси MUST отклонять при запуске, с ошибкой и ненулевым кодом выхода, `--header`, чьё имя без учёта регистра совпадает с одним из зарезервированных: `Mcp-Session-Id`, `Mcp-Protocol-Version`, `Accept`, `Content-Type`, `Content-Length`, `Host`, `Connection`, `Upgrade`, `Transfer-Encoding`. Заголовок `Authorization` MUST оставаться разрешённым.

#### Scenario: Upgrade отклоняется
- **WHEN** прокси запущен с `--header "Upgrade: websocket"`
- **THEN** он завершается при старте с ошибкой о зарезервированном заголовке

#### Scenario: Регистр имени не важен
- **WHEN** прокси запущен с `--header "upgrade: h2c"`
- **THEN** он завершается при старте с ошибкой о зарезервированном заголовке

#### Scenario: Authorization разрешён
- **WHEN** прокси запущен с `--header "Authorization: Bearer abc"`
- **THEN** запуск проходит, и заголовок уходит в запросах к remote
