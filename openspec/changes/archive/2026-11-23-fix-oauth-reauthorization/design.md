# Design

## Context

Мотивация описана в proposal.md (раздел Why), требования — в `specs/oauth-authorization/spec.md`. Здесь только то, что определяет подход.

- `httpmcp.Client` обрабатывает 401 одинаково в POST (`sendOnce`, рекурсия с флагом `retried`) и в GET SSE (`doListen`, флаг `retried401`, сбрасывается на 200). Разрешён ровно один вызов `TokenProvider.HandleUnauthorized` и один повтор. Заголовок `WWW-Authenticate` передаётся провайдеру и больше нигде не используется.
- `oauth.Provider.HandleUnauthorized(ctx, www)` не знает, какой токен отвергнут и что уже делалось в рамках этого запроса. При наличии `refresh_token` он всегда сначала пробует refresh. Поэтому цепочка «refresh → токен отвергнут» упирается в лимит `httpmcp` до полного флоу.
- `Provider.Token` сам обновляет истёкший токен (`tokenSkew`), так что первый же запрос может уйти с только что обновлённым токеном.
- `listenCallback` слушает `cfg.Host:cfg.Port` (по умолчанию порт 0). DCR выполняется, только если `cachedClient == nil`. `ClientInfo.RedirectURIs` сохраняется в `client.json`, но при выборе порта не читается.
- `parseWWWAuthenticate` — неэкспортируемая функция пакета `oauth`.
- Все вызовы `HandleUnauthorized` сериализованы `Provider.mu`. Полный флоу держит мьютекс до callback, по умолчанию до 5 минут.

## Goals / Non-Goals

**Goals:**
- Решение «refresh или браузер» опирается на то, что уже произошло с этим запросом, а не только на наличие `refresh_token`.
- Не больше одного открытия браузера на запрос. При параллельных запросах с одним протухшим токеном авторизация выполняется один раз.
- `redirect_uri` в URL авторизации всегда входит в `redirect_uris` используемого DCR-клиента.

**Non-Goals:**
- Координация нескольких процессов `mcp-remote` с общим каталогом хранилища (lock-файлы). Два процесса могут одновременно перерегистрировать клиента. Последняя запись в `client.json` побеждает, и это лечится следующей повторной авторизацией.
- Особая обработка 401 при `Authorization` из `--header`. OAuth для таких запросов по-прежнему вызывается, и поведение остаётся прежним: ошибка после одной авторизации.
- Выбор `scope` по PRM/`WWW-Authenticate` (сейчас берутся `scopes_supported` из AS metadata). На DeepL это не влияло, вопрос отдельный.
- Гарантия `redirect_uris ⊇ {callbackURL}` для `--static-oauth-client-metadata` с пользовательским списком `redirect_uris`. Это отдельное расхождение кода и `CLAUDE.md`.
- Детерминированный порт от `hash(ServerURL)`, как в npm-версии.

## Decisions

### 1. Контракт `TokenProvider` знает о цепочке запроса

```go
// HandleUnauthorized обрабатывает 401 на запрос, ушедший с rejectedToken
// ("" — токен провайдера не отправлялся). allowRefresh=false запрещает
// refresh: предыдущий шаг этой же цепочки уже дал токен, и его отвергли.
// authorized=true — был пройден полный флоу авторизации в браузере.
HandleUnauthorized(ctx context.Context, wwwAuthenticate, rejectedToken string, allowRefresh bool) (authorized bool, err error)
```

Логика провайдера под `p.mu`:

```
есть текущий токен и он != rejectedToken --> (false, nil)   токен уже заменён: повторить
allowRefresh и есть refresh_token        --> refresh
     ok   --> debug "token refreshed",           (false, nil)
     fail --> info  "refresh failed ...", очистить, к полному флоу
!allowRefresh и есть токены              --> info "token rejected after refresh, starting full authorization", очистить
полный флоу (authorizeLocked)            --> (true, err)
```

Цепочка в `httpmcp`: локальное состояние одного запроса POST или одной серии GET до ответа 200.

```go
type authChain struct {
    attempts   int  // вызовы HandleUnauthorized в этой цепочке
    authorized bool // цепочка уже прошла полный флоу
}
const maxAuthAttempts = 3
```

На каждый 401:
1. Разобрать challenge и записать debug-лог.
2. Если `authorized` — ошибка «отвергнут сразу после авторизации».
3. Если `attempts == maxAuthAttempts` — ошибка «исчерпан лимит».
4. Вызвать `HandleUnauthorized(www, sentToken, allowRefresh: attempts == 0)`, затем `attempts++`; результат `authorized` запомнить.
5. Повторить запрос.

Рекурсия `sendOnce` заменяется циклом. `doListen` хранит `authChain` вместо `retried401` и сбрасывает её на 200, как сейчас сбрасывается флаг. `setRequestHeaders` дополнительно возвращает токен, который он поставил из провайдера. Если `Authorization` пришёл из `--header`, возвращается `""`.

Сценарий DeepL после изменения:

```
Token(): A истёк -> refresh -> B
POST(B) -> 401 -> HU(B, allowRefresh=true)  -> B текущий, refresh -> B'   (false)
POST(B')-> 401 -> HU(B', allowRefresh=false) -> очистить, браузер -> C    (true)
POST(C) -> 200
```

Почему `allowRefresh` выключается после **любого** шага без браузера, включая «токен уже заменён»: заменить токен мог refresh другого запроса, и если его токен тоже отвергнут, второй refresh — тот самый дефект. Если тот, другой, запрос уже пошёл в браузер, наш вызов дождётся `p.mu`, увидит новый токен и вернёт «уже заменён». Второго окна не будет.

Рассмотренные альтернативы:
- **Поднять лимит повторов до двух без смены контракта.** Провайдер сделает refresh дважды: он не отличает первый 401 от второго. Дефект остаётся.
- **Провайдер запоминает происхождение токена** (refresh или authorize) глобально. Токен, полученный refresh-ем и часами работавший, после отзыва сразу вёл бы в браузер, хотя refresh мог бы помочь. Пришлось бы добавить сигнал «токен подтверждён», то есть ещё один метод контракта. Отклонено.
- **Вернуть enum исхода** (`Replaced`/`Refreshed`/`Authorized`). Типу пришлось бы жить в `httpmcp`, и `oauth` начал бы импортировать `httpmcp`. Для решения в `httpmcp` хватает bool.

### 2. Разбор `WWW-Authenticate` — в отдельный пакет `internal/wwwauth`

`httpmcp` нужны `error` и `error_description` для лога и итоговой ошибки, а последний 401 цепочки до провайдера не доходит. Парсер переносится из `oauth` в `internal/wwwauth` (`ParseBearer(string) map[string]string`) вместе с тестами, и им пользуются оба пакета. Альтернатива — копия парсера в `httpmcp`. Это две реализации одного RFC 6750 разбора, которые со временем разойдутся.

### 3. Порт callback: сначала зарегистрированный, при несовпадении — новый DCR

Порядок выбора порта в `listenCallback` (новый аргумент `preferredPort`):
1. `cfg.Port > 0` — как сейчас; ошибка bind фатальна.
2. Иначе `preferredPort > 0`: это порт из `redirect_uris` известного клиента, первый URL со схемой `http`, тем же `Hostname()`, что у callback-хоста (без учёта регистра), путём `/callback` и числовым портом. Если bind не удался — debug-лог и переход к п.3.
3. Порт 0.

После bind в `authorizeLocked` итоговый `callbackURL` сравнивается **точным совпадением строки** с `cachedClient.RedirectURIs`: строгие сервера авторизации сравнивают именно так. При несовпадении:
- клиент из DCR и есть `registration_endpoint` → новый DCR, `SaveClient`, info-лог с причиной (`port_unavailable`, `explicit_port`, `no_redirect_uris`, `mismatch`);
- клиент из DCR без `registration_endpoint` → warn, продолжить;
- статический клиент (`--static-oauth-client-info`) → warn с callback URL и подсказкой про позиционный `port`, продолжить.

Происхождение клиента: в `Provider` добавляется `clientStatic bool`, он выставляется в `New` при разборе `StaticOAuthClientInfoJSON`.

Если ответ DCR не содержит `redirect_uris`, в `ClientInfo` записываются отправленные `redirect_uris`. По RFC 7591 §3.2.1 сервер возвращает зарегистрированные метаданные, и отсутствие поля считаем принятием отправленного. Без этого сервер, не возвращающий поле, вызывал бы новый DCR при каждой авторизации. Новый DCR выполняется не больше одного раза за флоу. Если и после него `callbackURL` не входит в `redirect_uris` (например, пользовательские метаданные со своим списком), пишется warn, и флоу продолжается.

Рассмотренные альтернативы:
- **Новый DCR при каждом полном флоу.** Просто, но каждый раз новый `client_id` и мусорные регистрации на сервере авторизации. Оставлен только как fallback.
- **Порт от `hash(ServerURL)`.** Всё равно нужен fallback на занятый порт, а у существующих клиентов порт другой, то есть ещё одна перерегистрация. Повторное использование зарегистрированного порта решает задачу без этого.

### 4. Формат логов и итоговой ошибки

- `httpmcp`, debug на каждый 401: `remote 401` с атрибутами `method`, `attempt`, `token_sent` (bool), `error`, `error_description`.
- Итоговая ошибка: `http 401: <причина>[: <error>][: <error_description≤200 рун>]`. Причины: `token rejected right after authorization`, `giving up after 3 authorization attempts`. Ошибка провайдера, как и сейчас, приходит как `handle unauthorized: ...`.
- `oauth`: debug `token refreshed`, debug `token already replaced, retrying`, info `token rejected after refresh, starting full authorization`, info `re-registering client` с `reason`, warn для статического клиента и при отсутствии `registration_endpoint`. Значения токенов, `refresh_token`, `client_secret` и `code` не логируются. Уже существующий info-лог с URL авторизации остаётся: в URL нет ни токенов, ни `code`.

## Risks / Trade-offs

- [На один запрос уходит больше HTTP-запросов (до 4 вместо 2)] → Лимит `maxAuthAttempts = 3`. Браузер в цепочке открывается не больше одного раза.
- [Зарегистрированный порт занял посторонний процесс] → Bind не удаётся, берётся случайный порт и выполняется новый DCR. Перехватить `code` посторонний не может: redirect уходит на новый callback URL, а `state` и PKCE защищают флоу.
- [Два процесса `mcp-remote` с одним сервером одновременно проходят авторизацию: второй не может занять порт и перерегистрирует клиента] → Вне scope (см. Non-Goals). Худший исход — лишняя повторная авторизация позже.
- [Запрос с `Authorization` из `--header` при сохранённых OAuth-токенах получает 401] → Провайдер считает токен «уже заменённым» (`rejectedToken == ""`), повторяет запрос до лимита и возвращает ошибку без браузера. Сейчас в этом случае выполняется бесполезный refresh. Исход тот же — ошибка.
- [Параллельные запросы ждут на `p.mu`, пока идёт полный флоу (до `--auth-timeout`)] → Так и сейчас. После флоу они получают «уже заменён» и повторяются без новых окон.
- [`error_description` от недоверенного сервера уходит в JSON-RPC ошибку клиенту] → Обрезается до 200 рун. JSON-кодирование экранирует содержимое, slog экранирует значения атрибутов.

## Migration Plan

Миграция данных не нужна, формат `client.json` и `tokens.json` не меняется.
- Существующие `client.json` с `redirect_uris` начнут использовать свой порт.
- При первой полной авторизации на клиенте без `redirect_uris` выполнится один новый DCR.
- Откат: прежний бинарь читает те же файлы. Порт у него опять будет случайным.
