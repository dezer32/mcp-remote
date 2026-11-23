# Tasks

## 1. Общий разбор WWW-Authenticate

- [x] 1.1 Создать пакет `internal/wwwauth` с `ParseBearer(string) map[string]string`, перенеся туда `oauth.parseWWWAuthenticate` и её табличные тесты из `internal/oauth/discovery_test.go`. `oauth.authorizeLocked` использует новый пакет. Проверка: `go test -race ./internal/wwwauth/ ./internal/oauth/` зелёный, `grep -rn parseWWWAuthenticate internal` пуст.
- [x] 1.2 Добавить `internal/wwwauth` в таблицу пакетов `CLAUDE.md`. Проверка: строка в таблице описывает назначение пакета, `make lint` зелёный.

## 2. Контракт TokenProvider и решение провайдера

- [x] 2.1 Сменить сигнатуру `httpmcp.TokenProvider.HandleUnauthorized` на `(ctx, wwwAuthenticate, rejectedToken string, allowRefresh bool) (authorized bool, err error)` и обновить doc-комментарий. Обновить `oauth.Provider`, `fakeTP` в `internal/httpmcp/client_test.go` и вызовы в тестах `internal/oauth`. `handle401` временно передаёт `("", true)` и сохраняет прежнюю семантику одного повтора. Проверка: `go build ./... && go vet ./...` и `make test` зелёные, assert в `main.go` компилируется.
- [x] 2.2 Реализовать в `Provider.HandleUnauthorized` решение из design.md (решение 1): «токен уже заменён» → `(false, nil)` без сетевых вызовов; `allowRefresh` и `refresh_token` → refresh; `!allowRefresh` → очистка токенов и полный флоу; полный флоу → `authorized=true`. Логи: debug `token refreshed` и `token already replaced, retrying`, info `token rejected after refresh, starting full authorization`. Проверка: новые тесты в `internal/oauth/flow_test.go` проходят (`go test -race -run TestHandleUnauthorized ./internal/oauth/`):
  - заменённый токен не вызывает ни token endpoint, ни opener;
  - `allowRefresh=false` при наличии `refresh_token` открывает opener ровно один раз и не обращается к refresh;
  - захваченный slog-вывод не содержит значений access/refresh токенов.

## 3. Цепочка 401 в httpmcp

- [x] 3.1 `setRequestHeaders` возвращает токен, поставленный из провайдера (`""`, если `Authorization` пришёл из `--header` или токена нет). Ввести `authChain` с `maxAuthAttempts = 3`, переписать `handle401` и заменить рекурсию `sendOnce` циклом. На каждый 401 — debug-лог `remote 401` с `method`, `attempt`, `token_sent`, `error`, `error_description` (через `wwwauth`). Итоговые ошибки в формате из design.md (решение 4). Проверка: новые тесты в `internal/httpmcp/client_test.go` проходят:
  - 401 → refresh → 401 → второй вызов с `allowRefresh=false` → 200;
  - после `authorized=true` 401 даёт ошибку с `right after authorization` и `invalid_token`;
  - remote всегда отвечает 401 → не больше 4 POST;
  - `rejectedToken` равен отправленному Bearer, при `Authorization` из `--header` он `""`.
- [x] 3.2 `doListen` использует `authChain` вместо `retried401` и сбрасывает её на 200. Проверка: тест GET SSE с цепочкой 401 → refresh → 401 → authorize → 200 проходит, а после 200 следующий 401 снова начинается с `allowRefresh=true`.
- [x] 3.3 Усечение `error_description` до 200 рун в итоговой ошибке. Проверка: тест с описанием из 500 символов, включая многобайтовые, видит в ошибке ровно 200 рун без порванных UTF-8 последовательностей.
- [x] 3.4 Обновить `CLAUDE.md`: строку `internal/httpmcp` («Один retry на 401» → цепочка до 3 обращений, `rejectedToken`/`allowRefresh`) и раздел «OAuth-флоу» (решение refresh или authorize по `allowRefresh` и заменённому токену). Проверка: описание в `CLAUDE.md` совпадает с doc-комментарием `TokenProvider`, `make lint` зелёный.

## 4. Callback-порт и повторная регистрация клиента

- [x] 4.1 Добавить `Provider.clientStatic` (выставляется в `New` при разборе `StaticOAuthClientInfoJSON`) и функцию выбора порта из `redirect_uris` по правилам design.md (решение 3). Проверка: табличный тест покрывает совпадение хоста без учёта регистра, IPv6 `[::1]`, чужой путь, схему `https`, нечисловой порт и несколько URI, где подходит второй.
- [x] 4.2 `listenCallback` получает `preferredPort`: явный `cfg.Port` > предпочтительный с fallback на 0 при ошибке bind > 0. Проверка: тесты в `internal/oauth/callback_test.go` проходят:
  - свободный предпочтительный порт используется;
  - занятый (тест сам держит `net.Listen`) даёт случайный порт;
  - занятый явный порт даёт ошибку, как раньше.
- [x] 4.3 В `authorizeLocked` сравнивать `callbackURL` с `cachedClient.RedirectURIs` точным совпадением. Для DCR-клиента при несовпадении выполнять новый DCR (не больше одного за флоу), сохранять его и писать info `re-registering client` с `reason`. Для статического клиента и при отсутствии `registration_endpoint` писать warn и продолжать. Если ответ DCR без `redirect_uris`, записывать отправленные. Проверка: тесты на `asFixture` в `internal/oauth/flow_test.go` проходят:
  - сохранённый клиент со свободным портом — без обращения к `/register`, `redirect_uri` в URL авторизации совпадает с сохранённым;
  - занятый порт — ровно один `/register` и новый `client_id` в `client.json`;
  - клиент без `redirect_uris` — один `/register`;
  - статический клиент — ни одного `/register`, в логе warn с callback URL;
  - нет `registration_endpoint` — warn, флоу завершается успешно.
- [x] 4.4 Обновить `README.md` и `docs/README.ru.md`:
  - описание позиционного `port`: по умолчанию используется порт сохранённого клиента, при недоступности клиент перерегистрируется;
  - troubleshooting для `redirect_uri is not valid for this client application` и для 401 сразу после refresh (запуск с `--debug`, что искать в логе);
  - в `CLAUDE.md` — шаги 3–4 OAuth-флоу.

  Проверка: оба README описывают одно и то же поведение, а команды из troubleshooting выполняются как написано.

## 5. Интеграционная проверка

- [x] 5.1 Доработать `test/fake_mcp_server.go`:
  - `/register` возвращает отправленные `redirect_uris` и уникальный `client_id`, считает регистрации;
  - опциональный строгий режим `/authorize` отвечает 400 `invalid_request`, если `redirect_uri` не входит в зарегистрированные для `client_id`;
  - опциональный режим, в котором токены, выданные по `refresh_token`, ресурс отвергает с `error="invalid_token"`.

  Проверка: `make test-integration` зелёный для существующих тестов.
- [x] 5.2 Integration-тест «протухший grant». В `--config-dir` заранее лежат `client.json`, `metadata.json` и `tokens.json` с истёкшим access и рабочим `refresh_token`; сервер в режиме отвергаемых refresh-токенов. Бинарь доходит до `browser_helper`, и `initialize` возвращает result. Проверка: `go test -race -tags=integration -run TestIntegration_OAuthStaleGrant ./test/...` зелёный.
- [x] 5.3 Integration-тест «повторная авторизация на зарегистрированном порту». Первый запуск проходит OAuth в строгом режиме `/authorize`. После удаления `tokens.json` второй запуск тоже проходит, а счётчик регистраций остаётся равным 1. Проверка: `go test -race -tags=integration -run TestIntegration_OAuthReusesRegisteredPort ./test/...` зелёный.
- [x] 5.4 Полный прогон. Проверка: `make lint`, `make test`, `make test-integration` и `openspec validate fix-oauth-reauthorization --strict` завершаются успешно, вывод приложен к отчёту.
- [x] 5.5 Ручная проверка на DeepL. Убрать `62505` из `args` в конфиге клиента, отложить `tokens.json` и запустить `mcp-remote https://mcp.deepl.com/v1/mcp --debug` с `initialize` на stdin. Проверка: в логе debug-запись `remote 401` с `token_sent=false`, браузер открывается на `/.idp/auth` с `redirect_uri=http://127.0.0.1:62505/callback`, после логина в stdout приходит result `initialize`.

## Workflow follow-up

- Коммит и push — только по явной просьбе пользователя.
- Архивировать change после ревью (`/opsx:archive`) и проверить, что требования попали в `openspec/specs/oauth-authorization/spec.md`.
