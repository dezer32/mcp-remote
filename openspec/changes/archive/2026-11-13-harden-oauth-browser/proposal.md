# Proposal

## Why

Прокси открывает в браузере URL, собранный из данных удалённого сервера (`authorization_endpoint` из AS metadata), без проверки схемы. На Windows он уходит в `cmd /c start`, где `&` в URL работает как разделитель команд. Это тот же класс уязвимости, что CVE-2025-6514 (CVSS 9.6) в npm-версии `mcp-remote`: подключение к недоверенному MCP-серверу даёт выполнение команд на машине пользователя. Попутно, вероятно, ломается и обычный OAuth на Windows: URL авторизации всегда содержит `&` между параметрами.

Рядом есть смежные пробелы того же класса «доверяем удалённому серверу больше, чем нужно»:
- метаданные discovery принимаются без проверки: `http://`-эндпоинты, `issuer` (RFC 8414 §3.3), `resource` (RFC 9728);
- OAuth HTTP-клиент следует cross-origin редиректам, в том числе на POST с `code_verifier`, `refresh_token` и `client_secret` в теле;
- callback-сервер завершает флоу на первом же запросе к `/callback`, а в ветке `?error=` не проверяет `state`;
- `Upgrade` разрешён в `--header`, хотя README и CLAUDE.md утверждают, что он зарезервирован.

## What Changes

- **Запуск браузера.** `DefaultOpener` открывает только абсолютные `http`/`https` URL с хостом и без userinfo; в браузер уходит перекодированный `url.URL.String()`, а не сырая строка. На Windows вместо `cmd /c start` используется `rundll32 url.dll,FileProtocolHandler`, без участия `cmd.exe`.
- **Транспортная политика эндпоинтов.** **BREAKING:** `resource_metadata` из `WWW-Authenticate`, `authorization_servers[0]`, `authorization_endpoint`, `token_endpoint` и `registration_endpoint` должны быть абсолютными `https` URL. `http` допускается только с `--allow-http`. Иначе авторизация завершается ошибкой.
- **Проверка `issuer`.** **BREAKING:** если AS metadata содержит `issuer`, он должен совпадать с идентификатором AS, по которому строился well-known URL (с точностью до завершающего `/`). Если `issuer` отсутствует, пишется предупреждение и флоу продолжается. На fallback к дефолтным путям (404 на metadata) проверка не применяется.
- **Проверка `resource` из PRM.** **BREAKING:** `resource` должен иметь тот же origin, что `ServerURL`, а путь `ServerURL` должен начинаться с пути `resource` (с точностью до завершающего `/`). При явном `--resource` проверка пропускается.
- **Редиректы OAuth-клиента.** POST на token и registration endpoint не следует редиректам. GET discovery следует не более чем 5 редиректам и не допускает понижения `https` → `http` (кроме `--allow-http`).
- **Callback-сервер.** `state` проверяется (в постоянное время) и для успешного ответа, и для `?error=`. Запрос с неверным или отсутствующим `state` получает 400, но флоу не завершает. Методы, отличные от GET, получают 405.
- **Предупреждение о `--host`.** Если callback-сервер слушает не loopback-адрес, в лог пишется предупреждение.
- **Зарезервированные заголовки.** **BREAKING:** `--header "Upgrade: …"` отклоняется на этапе парсинга, как уже обещает документация.

## Capabilities

### New Capabilities
- `oauth-authorization`: OAuth-авторизация прокси перед remote MCP-сервером: запуск браузера, проверка метаданных discovery, транспортная политика OAuth-запросов, приём callback.
- `request-headers`: пользовательские HTTP-заголовки (`--header`) для запросов к remote и правила зарезервированных имён.

### Modified Capabilities
<!-- Существующих спецификаций в проекте нет. -->

## Impact

- **Код:** `internal/oauth/browser.go`, `internal/oauth/discovery.go`, `internal/oauth/flow.go`, `internal/oauth/callback.go`, `internal/config/config.go`. Сигнатуры `Opener`, `TokenProvider` и `proxy`-контрактов не меняются: assert-блок в `main.go` не затрагивается.
- **Тесты:** unit-тесты `internal/oauth` поднимают `httptest`-серверы на `http://`; их конфиги получат `AllowHTTP: true`. Integration-тесты уже запускают бинарь с `--allow-http`. Добавятся тесты на отклонение небезопасных URL, на `issuer`/`resource`, на редиректы и на callback.
- **Поведение для пользователей:** серверы с `http://`-эндпоинтами без `--allow-http`, с несовпадающим `issuer` или `resource` перестанут авторизоваться. Для `resource` остаётся обход через `--resource`.
- **Документация:** `README.md`, `docs/README.ru.md` (описание `BROWSER`/opener, `--allow-http`, troubleshooting), `CLAUDE.md` (описание `DefaultOpener` и шагов OAuth-флоу).
- **Зависимости:** новых нет, только stdlib (`crypto/subtle`, `net/url`, `net/netip`).
