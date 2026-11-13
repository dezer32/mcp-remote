# Tasks

## 1. Безопасный запуск браузера

- [x] 1.1 В `internal/oauth/browser.go` добавить sentinel `errUnsafeURL` и функцию санитарии URL для браузера (схема `http`/`https`, непустой хост, без userinfo, без пробельных символов; возвращает `u.String()`). Покрыть табличным тестом в новом `internal/oauth/browser_test.go`: `file://`, `javascript:`, `smb://`, userinfo, пробел, пустой хост, ведущий `-`, нормальный `https` с `&` в query. Проверка: `go test -race -run TestSanitizeBrowserURL ./internal/oauth/` зелёный
- [x] 1.2 Вынести выбор команды в чистую `browserCommand(goos, url string) (string, []string)`: darwin → `open`, windows → `%SystemRoot%\System32\rundll32.exe url.dll,FileProtocolHandler` (fallback `rundll32.exe` при пустом `SystemRoot`), прочие → `xdg-open`; URL всегда одним последним аргументом, `cmd` нигде не используется. Проверка: табличный тест `TestBrowserCommand` по трём `goos` проходит на любой ОС
- [x] 1.3 Переписать `DefaultOpener.Open`: сначала санитария (на отказ — ошибка, обёрнутая `errUnsafeURL`, без запуска процесса), затем `$BROWSER` или `browserCommand`. Проверка: тест, где `Open` с `file:///...` возвращает `errors.Is(err, errUnsafeURL)`, при этом `BROWSER` указывает на несуществующий бинарь (значит, до exec дело не дошло)
- [x] 1.4 В `Provider.authorizeLocked` при `errors.Is(openErr, errUnsafeURL)` завершать авторизацию ошибкой и не печатать URL в stderr; прочие ошибки opener-а — прежнее поведение. Проверка: тест с fake opener, возвращающим `errUnsafeURL`, — `HandleUnauthorized` возвращает ошибку с `errors.Is(err, errUnsafeURL)`, токен-эндпоинт не вызывается
- [x] 1.5 Обновить документацию opener-а: строка `BROWSER` в `README.md` и `docs/README.ru.md` (вместо `cmd /c start` — `rundll32 url.dll,FileProtocolHandler`, URL проверяется до запуска), описание `DefaultOpener` в таблице пакетов `CLAUDE.md`. Проверка: `grep -n "cmd /c start" README.md docs/README.ru.md CLAUDE.md` ничего не находит

## 2. HTTPS-политика OAuth-эндпоинтов и редиректы

- [x] 2.1 Добавить `validateEndpointURL(raw string, allowHTTP bool) (*url.URL, error)` в `internal/oauth/discovery.go` (абсолютный URL, `https` или `http` при `allowHTTP`, непустой хост, без userinfo). Проверка: табличный тест `TestValidateEndpointURL` (https ок; http без/с allowHTTP; `javascript:` и `file:` отклоняются даже с allowHTTP; относительный URL; userinfo)
- [x] 2.2 Выставить `AllowHTTP: true` в конфигах unit-тестов `internal/oauth`, которые ходят на `httptest.NewServer` (`newTestProvider` в `discovery_test.go`, конфиги в `flow_test.go`), до включения проверок. Проверка: `go test -race ./internal/oauth/` зелёный без изменений в production-коде
- [x] 2.3 Применить `validateEndpointURL` в `discover`/`fetchAS` к `resource_metadata`, `authorization_servers[0]`, `authorization_endpoint`, `token_endpoint` и непустому `registration_endpoint` с `cfg.AllowHTTP`. Проверка: тесты — `http` token endpoint без `AllowHTTP` даёт ошибку discovery; с `AllowHTTP` проходит; `authorization_endpoint: "javascript:alert(1)"` с `AllowHTTP` даёт ошибку и opener не вызывается
- [x] 2.4 Применить ту же проверку в начале `postToken` и `registerClient`. Проверка: тест, где в storage лежит `metadata.json` с `http` token endpoint, прокси без `AllowHTTP`: refresh не отправляет запрос на этот адрес, токены очищаются, `HandleUnauthorized` уходит в полный флоу с новым discovery
- [x] 2.5 Задать `CheckRedirect` у `p.httpClient` в `oauth.New`: POST — ошибка без следования; GET — не более 5 хопов и без понижения `https` → `http` при выключенном `AllowHTTP`. Проверка: тесты — token endpoint отвечает 307 на второй `httptest`-сервер, тот не получает ни одного запроса, обмен кода падает; `httptest.NewTLSServer` с AS metadata редиректит на `http`-сервер — discovery падает (транспорт берётся из `tlsSrv.Client()`, `CheckRedirect` сохраняется); шестой редирект — ошибка
- [x] 2.6 Документация: строка `--allow-http` и раздел Security в `README.md` и `docs/README.ru.md` — флаг распространяется и на OAuth-эндпоинты; соответствующий пункт в «Соглашениях» `CLAUDE.md`. Проверка: в обоих README и в CLAUDE.md описание `--allow-http` упоминает OAuth-эндпоинты

## 3. Проверка issuer и resource

- [x] 3.1 Передать в `fetchAS` исходный идентификатор AS (`authorization_servers[0]` до обрезки или origin `ServerURL`) и сравнивать с `issuer` без учёта одного завершающего `/`; пустой `issuer` — `Warn` и продолжение; на 404 (дефолтные пути) проверки нет. Проверка: тесты — совпадение, различие только в `/`, несовпадение (ошибка содержит оба значения, opener не вызывается), отсутствие `issuer` (предупреждение в логгере, захваченном в буфер)
- [x] 3.2 В `discover` после PRM, если `resourceOverride` пуст, проверять `resource`: схема и хост без учёта регистра, порт с учётом дефолтного для схемы, путь `ServerURL` равен пути `resource` или начинается с `resourcePath + "/"`; пустой `resource` — `Warn` и прежнее поведение. Проверка: тесты — origin-resource для `ServerURL` с `/mcp` проходит; другой хост — ошибка; `/mcp` против `/mcp-admin` — ошибка; `https://h:443` равен `https://h`; с `--resource` проверка пропущена
- [x] 3.3 Привести фикстуры к новым правилам: `resource` в `TestDiscoveryPRMPath` (сейчас `https://api.example.com/mcp` при `ServerURL` `https://ignored.example/mcp`) и `resource` в `asFixture` из `flow_test.go`, если флоу идёт через PRM. Проверка: `go test -race ./internal/oauth/` зелёный
- [x] 3.4 Документация: пункт troubleshooting в `README.md` и `docs/README.ru.md` про ошибки несовпадения `issuer`/`resource` (что означает и что `--resource` обходит проверку resource); шаг 2 OAuth-флоу в `CLAUDE.md` дополнить проверками. Проверка: новые пункты есть в обоих README и в CLAUDE.md

## 4. Callback-сервер

- [x] 4.1 В `callbackServer.handle`: не-GET — 405 с `Allow: GET` без `send`; `state` сравнивается через `subtle.ConstantTimeCompare`, при несовпадении или отсутствии — 400 без `send`; дальше прежняя логика для `error`/`code`. Проверка: тесты в `callback_test.go` — неверный `state`, затем верный callback даёт успех; `?error=access_denied` без `state` — 400, `Wait` завершается только по ctx; `?error=access_denied&state=<верный>` — ошибка с `access_denied`; POST — 405. Существующие `TestCallbackStateMismatch` и `TestCallbackErrorParam` переписать под новое поведение
- [x] 4.2 Добавить проверку loopback-хоста (`localhost` без учёта регистра или IP с `netip.Addr.IsLoopback()`) и `Warn` в `authorizeLocked` после `listenCallback`, если хост не loopback. Проверка: табличный тест `TestIsLoopbackHost` (`localhost`, `LOCALHOST`, `127.0.0.1`, `::1`, `0.0.0.0`, `::`, `example.com`) и тест, что при `Host: "0.0.0.0"` в захваченном логе есть предупреждение
- [x] 4.3 Документация: строка `--host` в `README.md` и `docs/README.ru.md` — предупреждение для не-loopback адреса; шаг 5 OAuth-флоу в `CLAUDE.md` — неверный `state` отвечает 400 и не завершает ожидание. Проверка: правки присутствуют в трёх файлах

## 5. Зарезервированные заголовки

- [x] 5.1 Добавить `"upgrade"` в `reservedHeaders` в `internal/config/config.go` и кейсы `Upgrade: websocket` и `upgrade: h2c` в табличный `TestParse_Errors`. Проверка: `go test -race -run TestParse ./internal/config/` зелёный; документация уже перечисляет `Upgrade`, правок не требует

## 6. Интеграционная проверка

- [x] 6.1 Прогнать `make lint`, `make test` и `make test-integration`, приложить реальный вывод. Проверка: все три команды завершаются с кодом 0
- [ ] 6.2 Вручную на Windows пройти OAuth против сервера с `authorization_endpoint`, содержащим несколько query-параметров: браузер открывается с полным URL, лишних процессов не запускается. Проверка: результат ручного прогона записан в описании PR

## Workflow follow-up

- В release notes перечислить пункты **BREAKING** из proposal.md.
- Архивировать change после ревью и слияния (`/opsx:archive`).
