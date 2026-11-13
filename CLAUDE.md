# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Что это

`mcp-remote` — локальный stdio↔Streamable HTTP MCP-прокси на Go. Запускается MCP-клиентом (Claude Desktop и т.п.) как подпроцесс: читает JSON-RPC из stdin, пробрасывает по HTTPS на remote MCP-эндпоинт (спецификация MCP 2025-03-26), отдаёт ответы и SSE-стрим обратно в stdout. На HTTP 401 автоматически запускает OAuth 2.1 (PKCE + RFC 7591 DCR + RFC 9728/RFC 8414 discovery) и кэширует токены на диск. Это Go-порт npm-пакета [`mcp-remote`](https://github.com/geelen/mcp-remote); цель — одиночный self-contained бинарь без runtime-зависимостей.

## Команды разработки

```bash
make build               # go build -o mcp-remote .
make test                # go test -race -count=1 ./...   (без integration)
make test-integration    # go test -race -tags=integration -count=1 ./test/...
make lint                # go vet + gofmt check
make tidy                # go mod tidy
```

Запуск одного теста:

```bash
go test -race -run TestIntegration_SessionRecovery -tags=integration ./test/...
go test -race -run TestParse ./internal/config/
```

Go 1.26+. CI (`.github/workflows/ci.yml`) гоняет unit-тесты на ubuntu/macos/windows + golangci-lint (только Linux) + integration-тесты (только на push в master/main). Релизы — через GoReleaser, `CGO_ENABLED=0`, ldflags пишут `main.{version,commit,date}`.

## Архитектура (большая картина)

Поток данных: **stdin → `stdio.Transport` → `proxy.Proxy` → `httpmcp.Client` (с `oauth.Provider` для токенов) → HTTPS** и в обратную сторону, включая SSE-стрим server-initiated сообщений.

### Consumer-side контракты — где лежит интерфейс

Интерфейсы определены в *потребляющем* пакете, а не там, где живут реализации:

- `internal/proxy` определяет `Transport`, `Remote`, `MessageOrError`, `ErrSessionLost` — это контракты, к которым прицепляются `stdio.Transport` и `httpmcp.Client`.
- `internal/httpmcp` определяет `TokenProvider` — реализует его `oauth.Provider`.

Compile-time проверки склейки сидят в `main.go` (`var _ proxy.Transport = (*stdio.Transport)(nil)` и т.д.) — если worker сломает сигнатуру в своём пакете, main.go не соберётся. **При изменении интерфейса обновляй обе стороны и assert-блок в main.go.**

### Пакеты

| Пакет | Роль |
|-------|------|
| `internal/jsonrpc` | JSON-RPC 2.0 типы; `Decode`/`Encode`/`BatchDecode`; `Message.IsRequest/IsNotification/IsResponse`. |
| `internal/stdio`   | Реализация `proxy.Transport`. Newline-delimited JSON. Фоновая read-горутина стартует через `sync.Once`; **она НЕ отменяется ctx**, висит до EOF на `in` (намеренно — Claude Desktop закрывает stdin на shutdown). Write атомарен под мьютексом, батч пишется одной записью. |
| `internal/httpmcp` | Реализация `proxy.Remote`. POST для send, GET SSE для listen (reconnect+backoff+Last-Event-ID; 408/429/5xx на GET — reconnect с backoff, прочие статусы — ошибка и стоп; backoff сбрасывается только после стрима, прожившего `listenStableStream`), `MCP-Session-Id`/`MCP-Protocol-Version` headers. Один retry на 401 (через `TokenProvider.HandleUnauthorized`). Поколение сессии: `ResetSession` → `gen++`; `Mcp-Session-Id` из ответа запроса со старым поколением игнорируется; 404 → `proxy.ErrSessionLost`, если запрос *ушёл* с sessionID (снимок на момент отправки, а не текущее состояние). `CheckRedirect` блокирует cross-origin (защита от token leak). `Close` шлёт DELETE если есть sessionID. |
| `internal/oauth`   | `Provider` (TokenProvider), `Storage` (файлы `0600`, директории `0700`), `discover` (PRM/AS), callback HTTP-сервер на `cfg.Host:port`, PKCE S256, `DefaultOpener` через `$BROWSER`/open/xdg-open/`rundll32 url.dll,FileProtocolHandler` (Windows; `cmd.exe` не используется), URL перед запуском проходит санитарию (только абсолютный `http`/`https` с хостом, без userinfo и пробелов; иначе `errUnsafeURL`). Файлы лежат в `<configDir>/<sha256(ServerURL)[:16]>/{tokens,client,metadata}.json`. |
| `internal/proxy`   | Маршрутизация + recovery. Две фоновые горутины — stdin reader и recovery dispatcher. Listener (GET SSE) стартует после доставки `notifications/initialized` (GET без сессии серверы отклоняют); его жизненным циклом владеет recovery. |
| `internal/config`  | Парсинг argv (свой парсер: standard `flag` не даёт смешивать позиционные и флаги в произвольном порядке). Резолв `configDir` по приоритету: `--config-dir` → `$MCP_REMOTE_CONFIG_DIR` → `os.UserConfigDir`/mcp-remote → `$HOME/.mcp-auth`. |
| `internal/logging` | `slog` → stderr; уровни DEBUG/INFO/ERROR через `--debug`/`--silent`. |

### Session recovery — нетривиальная часть

Когда remote возвращает `404` на запрос с `Mcp-Session-Id`, `httpmcp.Client` emit-ит `proxy.ErrSessionLost`. Proxy в ответ:

1. Складывает request в `pendingReplay`, **не** пишет клиенту.
2. Тригерит `recoveryTrigger` (coalescing через buffered channel size 1).
3. `runRecovery` берёт `recoveryMu.Lock()` (stdin-dispatch держит `RLock` → новые in-flight не выпускаются на время recovery).
4. `stopListener()` (cancel + join) → `remote.ResetSession()` → replay сохранённого `initialize` (proxy запоминает первый initialize в `firstInitialize` и `notifications/initialized` в `initializedNotif`) → replay `initialized` (включает listener) → replay pending → после прохода `maybeStartListener` поднимает listener на новой сессии.
5. На успех — `recoveryAttempts` сбрасывается на следующем удачном response, а также если с прошлого успешного recovery прошло больше `recoveryAttemptsWindow` (1 мин). На успешный `doRecovery` сам по себе НЕ сбрасывается — иначе петля «recovery ок → сразу 404» не упрётся в лимит.
6. На >`maxRecoveryAttempts` (3) подряд session-lost — `failAndShutdown`: всем in-flight и pending пишется JSON-RPC error `-32000` (до `close(recoveryFail)` — после него ctx отменён и запись не пройдёт), proxy завершается.

Сигнал recovery: флаги `recoveryPending`/`recoveryRunning` под `p.mu`; `triggerRecoveryLocked` схлопывает повторные сигналы. POST-путь во время идущего прохода ставит следующий (нужен для replay запросов, потерявших сессию после снимка).

Listener: `doRecovery` останавливает его (cancel + join, включая HTTP-продюсер `doListen` — `runListener` дочитывает канал `Listen` до закрытия) **до** `ResetSession` и перезапускает после replay — во время recovery GET-ов нет, старый продюсер не перезапишет сессию. На session-lost listener только сигналит (`requestRecoveryFromListener`, no-op если recovery уже ожидается/идёт) и выходит. Прочие ошибки стрима не терминальны; закрытый канал (405 и т.п.) — listener стоит до следующего успешного recovery.

### OAuth-флоу — порядок шагов

`Provider.HandleUnauthorized` → пробует `refresh_token`; на провал → `authorizeLocked`:
1. Парс `WWW-Authenticate` (`resource_metadata=...` если есть).
2. `discover`: RFC 9728 PRM → `authorization_servers[0]` + RFC 8414 AS metadata; fallback на дефолтные пути `/authorize`, `/token`, `/register` при 404 на AS metadata. Проверки: `resource` из PRM — тот же origin, что `ServerURL`, путь `ServerURL` равен пути `resource` или вложен по границе сегмента (пропускается при `--resource`, пустой — `Warn`); `issuer` из AS metadata равен идентификатору AS с точностью до одного завершающего `/` (пустой — `Warn`, на 404-fallback проверки нет); все URL эндпоинтов проходят `validateEndpointURL`.
3. Generate PKCE verifier+challenge S256, state, поднимаем callback-сервер (`net.Listen` на `cfg.Host:cfg.Port`, по умолчанию `127.0.0.1:0`).
4. DCR (RFC 7591) если нет `cachedClient` и `meta.RegistrationEndpoint != ""`. `--static-oauth-client-metadata` мерджится с гарантией `redirect_uris ⊇ {callbackURL}`.
5. Открыть browser, ждать callback. Callback завершает ожидание только GET-запросом с верным `state` (`subtle.ConstantTimeCompare`, и для `code`, и для `error`); неверный/отсутствующий `state` → 400 без завершения, не-GET → 405. Если `cfg.Host` не loopback — `Warn` после `listenCallback`.
6. `code → token` exchange. Сохранить tokens+client+metadata в Storage.

`Token()` авто-refresh-ит при истечении (`tokenSkew = 30s`). Если refresh упал — токены чистятся, следующий запрос получит 401 и стартует полный flow.

## Соглашения и подводные камни

- **Комментарии в коде — на русском.** Сохраняй стиль (см. README, любой пакет).
- **`Authorization` через `--header` перебивает OAuth.** `setRequestHeaders` ставит user headers ДО системных, потом проверяет `req.Header.Get("Authorization") == ""` перед вызовом `TokenProvider.Token`. Это сознательное поведение — пользователь может зафиксировать внешний Bearer.
- **Reserved headers** (`Mcp-Session-Id`, `Accept`, `Content-Type`, `Content-Length`, `Host`, `Connection`, `Upgrade`, `Transfer-Encoding`, `Mcp-Protocol-Version`) запрещены к override через `--header` — `config.parseHeader` отклоняет (`Authorization` намеренно НЕ в списке).
- **`--allow-http` — только для разработки.** Без него config рубит не-HTTPS URL ещё на парсинге. Флаг распространяется и на OAuth-эндпоинты (`resource_metadata`, `authorization_servers[0]`, `authorization_endpoint`, `token_endpoint`, `registration_endpoint`): `oauth.validateEndpointURL` требует абсолютный `https` (с флагом допускается и `http`, другие схемы — никогда), проверка применяется в discovery и в `postToken`/`registerClient` (покрывает метаданные с диска). POST на token/registration endpoint не следуют редиректам, GET discovery — ≤5 хопов без `https`→`http` (`redirectPolicy` в `flow.go`). В unit-тестах `internal/oauth` с `httptest.NewServer` ставь `AllowHTTP: true`.
- **Cross-origin редиректы** при HTTP-запросах к remote блокируются (`httpmcp/redirects.go`) — защита от утечки токена/кода.
- **Permissions:** все JSON-файлы хранилища — `0600`, директории — `0700`. Не ослаблять.
- **`ServerURL → hash16`**: первые 16 hex-символов `sha256(serverURL)`. Полный URL не персистится в имени папки (приватность).
- **MCP-Protocol-Version** проставляется в OAuth-запросах (`2025-03-26`) и в каждом запросе к remote после успешного `initialize` (proxy парсит `result.protocolVersion` и зовёт `remote.SetProtocolVersion`).

## Тесты

- **Unit-тесты** живут рядом с кодом (`*_test.go`). Race-detector включён по умолчанию.
- **Integration-тесты** в `test/` под build-tag `integration` (`//go:build integration` в первой строке). `buildBinary(t)` собирает `mcp-remote` в `t.TempDir()`. `test/fake_mcp_server.go` — stateful `httptest.Server`, эмулирующий MCP Streamable HTTP + опционально OAuth (PRM/AS/register/authorize/token); умеет помечать сессию `expired` для тестирования recovery. Тесты запускают бинарь с `--allow-http`, т.к. `httptest` отдаёт `http://`.
- **`test/browser_helper/`** — отдельный mini-бинарь, имитирующий браузер: получает auth-URL через stdin, делает GET на authorize endpoint фейкового сервера, ходит по redirect-цепочке до callback-сервера прокси.

## Линтер

`.golangci.yml`: enabled = `govet` (enable-all, кроме `fieldalignment`), `errcheck`, `staticcheck`, `ineffassign`, `unused`, `gofmt`. В `_test.go` отключён `errcheck`.
