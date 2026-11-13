# Spec Delta

## Purpose

OAuth-авторизация прокси перед remote MCP-сервером: какие URL от сервера прокси принимает, как открывает браузер, по каким правилам ходит к OAuth-эндпоинтам и как принимает callback. Цель: подключение к недоверенному серверу не должно давать ему выполнения кода на машине пользователя или утечки секретов авторизации.

## ADDED Requirements

### Requirement: Браузер открывается только для веб-URL
Прокси MUST передавать в механизм запуска браузера только абсолютный URL со схемой `http` или `https`, непустым хостом, без userinfo и без пробельных символов. Любой другой URL MUST быть отклонён без запуска какого-либо процесса, а авторизация MUST завершиться ошибкой, в которой названа причина.

#### Scenario: Схема file отклоняется
- **WHEN** URL авторизации имеет вид `file:///Applications/Calculator.app?response_type=code`
- **THEN** никакой процесс не запускается, и авторизация завершается ошибкой, где указана недопустимая схема

#### Scenario: URL с userinfo отклоняется
- **WHEN** URL авторизации имеет вид `https://login.example.com@evil.example/authorize?...`
- **THEN** никакой процесс не запускается, и авторизация завершается ошибкой

#### Scenario: Обычный https URL открывается
- **WHEN** URL авторизации имеет вид `https://auth.example.com/authorize?response_type=code&client_id=abc&state=xyz`
- **THEN** браузер открывается с этим URL

### Requirement: URL передаётся браузеру без интерпретации командной оболочкой
На всех платформах прокси MUST передавать URL механизму запуска браузера одним аргументом, который не разбирает командный интерпретатор. Символы `&`, `|`, `^` и `%` MUST остаться частью URL. Если задана переменная `BROWSER`, указанный в ней исполняемый файл MUST получить URL единственным аргументом.

#### Scenario: Windows и URL с несколькими параметрами
- **WHEN** прокси работает на Windows и открывает `https://auth.example.com/authorize?response_type=code&client_id=abc&state=xyz`
- **THEN** браузер получает URL целиком, со всеми тремя параметрами, и никакая дополнительная команда не выполняется

#### Scenario: Попытка внедрить команду через амперсанд
- **WHEN** сервер прислал `authorization_endpoint` вида `https://evil.example/a&calc`
- **THEN** не запускается никакой процесс, кроме механизма открытия браузера с этим URL как одним аргументом

#### Scenario: Пользовательский BROWSER
- **WHEN** задана переменная окружения `BROWSER=/usr/bin/firefox`
- **THEN** запускается `/usr/bin/firefox` с проверенным URL единственным аргументом

### Requirement: OAuth-эндпоинты требуют HTTPS
Без `--allow-http` прокси MUST требовать абсолютный `https` URL для `resource_metadata` из `WWW-Authenticate`, для идентификатора сервера авторизации из PRM и для `authorization_endpoint`, `token_endpoint`, `registration_endpoint`, включая метаданные, загруженные из хранилища токенов. Нарушение MUST завершать авторизацию ошибкой до запроса к такому URL. С `--allow-http` MUST допускаться и `http`, но не другие схемы.

#### Scenario: token_endpoint по http без --allow-http
- **WHEN** AS metadata содержит `token_endpoint: "http://auth.example.com/token"`, а прокси запущен без `--allow-http`
- **THEN** авторизация завершается ошибкой, и запрос на `http://auth.example.com/token` не отправляется

#### Scenario: http допускается с --allow-http
- **WHEN** прокси запущен с `--allow-http`, и все OAuth-эндпоинты имеют схему `http`
- **THEN** авторизация проходит как раньше

#### Scenario: Недопустимая схема отклоняется и с --allow-http
- **WHEN** прокси запущен с `--allow-http`, а `authorization_endpoint` имеет вид `javascript:alert(1)`
- **THEN** авторизация завершается ошибкой, и браузер не открывается

#### Scenario: Сохранённые метаданные с http token_endpoint
- **WHEN** в хранилище лежат метаданные с `http`-адресом `token_endpoint` (записанные старой версией), а прокси запущен без `--allow-http`
- **THEN** refresh по этому адресу не выполняется, и прокси переходит к полному флоу авторизации с новым discovery

### Requirement: Проверка issuer сервера авторизации
Если AS metadata получены и содержат `issuer`, прокси MUST сравнить его с идентификатором сервера авторизации, по которому строился URL метаданных, без учёта одного завершающего `/`. При несовпадении авторизация MUST завершиться ошибкой с обоими значениями. При отсутствии `issuer` прокси MUST записать предупреждение и продолжить. При переходе на дефолтные пути (404 на метаданные) проверка не выполняется.

#### Scenario: issuer совпадает
- **WHEN** идентификатор сервера авторизации `https://auth.example.com`, а metadata содержат `issuer: "https://auth.example.com"`
- **THEN** авторизация продолжается

#### Scenario: Различие только в завершающем слэше
- **WHEN** идентификатор сервера авторизации `https://auth.example.com/`, а metadata содержат `issuer: "https://auth.example.com"`
- **THEN** авторизация продолжается

#### Scenario: issuer не совпадает
- **WHEN** идентификатор сервера авторизации `https://auth.example.com`, а metadata содержат `issuer: "https://evil.example"`
- **THEN** авторизация завершается ошибкой, где названы оба значения, и браузер не открывается

#### Scenario: issuer отсутствует
- **WHEN** metadata не содержат поле `issuer`
- **THEN** в лог пишется предупреждение, и авторизация продолжается

### Requirement: Проверка resource из метаданных защищённого ресурса
Если используется PRM и `--resource` не задан, прокси MUST проверить, что `resource` имеет те же схему, хост и порт, что `ServerURL`, а путь `ServerURL` равен пути `resource` или вложен в него по границе сегмента, без учёта завершающего `/`. При несовпадении авторизация MUST завершиться ошибкой. При пустом `resource` прокси MUST записать предупреждение и продолжить. С `--resource` проверка MUST пропускаться.

#### Scenario: resource равен origin сервера
- **WHEN** `ServerURL` равен `https://mcp.example.com/mcp`, а PRM содержит `resource: "https://mcp.example.com"`
- **THEN** авторизация продолжается

#### Scenario: resource на другом хосте
- **WHEN** `ServerURL` равен `https://mcp.example.com/mcp`, а PRM содержит `resource: "https://other.example.com/mcp"`
- **THEN** авторизация завершается ошибкой

#### Scenario: Совпадение префикса не по границе сегмента
- **WHEN** `ServerURL` равен `https://mcp.example.com/mcp-admin`, а PRM содержит `resource: "https://mcp.example.com/mcp"`
- **THEN** авторизация завершается ошибкой

#### Scenario: Явный --resource
- **WHEN** прокси запущен с `--resource https://custom.example/api`, а PRM содержит `resource: "https://other.example.com"`
- **THEN** проверка resource не выполняется, и в запросах авторизации используется `https://custom.example/api`

### Requirement: Запросы к token и registration endpoint не следуют редиректам
POST-запросы к `token_endpoint` и `registration_endpoint` MUST NOT следовать HTTP-редиректам. Ответ 3xx MUST завершать запрос ошибкой, и тело запроса MUST NOT отправляться на другой URL.

#### Scenario: 307 на token endpoint
- **WHEN** token endpoint отвечает `307` с `Location` на другой хост
- **THEN** запрос на другой хост не отправляется, и обмен кода (или refresh) завершается ошибкой

### Requirement: Редиректы discovery не понижают схему
GET-запросы discovery (PRM и AS metadata) MUST следовать не более чем 5 редиректам и MUST NOT следовать редиректу с `https` на `http`, если не задан `--allow-http`.

#### Scenario: Понижение до http
- **WHEN** запрос AS metadata по `https` получает редирект на `http`-адрес, а прокси запущен без `--allow-http`
- **THEN** редирект не выполняется, и discovery завершается ошибкой

#### Scenario: Цепочка длиннее пяти
- **WHEN** запрос PRM получает шестой подряд редирект
- **THEN** discovery завершается ошибкой

### Requirement: Callback завершает флоу только при совпадающем state
Callback-эндпоинт MUST завершать авторизацию (успехом или ошибкой от сервера авторизации) только по GET-запросу, чей `state` совпадает с ожидаемым. Запрос с отсутствующим или другим `state` MUST получить ответ 400 и MUST NOT завершать ожидание. Запрос с методом, отличным от GET, MUST получить ответ 405.

#### Scenario: Чужой state не срывает флоу
- **WHEN** на callback приходит запрос `?code=x&state=wrong`, а затем запрос с верными `code` и `state`
- **THEN** первый запрос получает 400, а авторизация успешно завершается по второму

#### Scenario: error без state
- **WHEN** на callback приходит `?error=access_denied` без `state`
- **THEN** запрос получает 400, и авторизация продолжает ждать callback до истечения `--auth-timeout`

#### Scenario: error с верным state
- **WHEN** на callback приходит `?error=access_denied&state=<ожидаемый>`
- **THEN** авторизация завершается ошибкой, содержащей `access_denied`

#### Scenario: POST на callback
- **WHEN** на callback приходит POST-запрос
- **THEN** он получает 405, и авторизация продолжает ждать

### Requirement: Предупреждение о callback на не-loopback адресе
Если callback-сервер слушает адрес, который не является loopback-адресом и не равен `localhost`, прокси MUST записать в лог предупреждение о том, что callback доступен из сети.

#### Scenario: --host 0.0.0.0
- **WHEN** прокси запущен с `--host 0.0.0.0` и начинает авторизацию
- **THEN** в лог пишется предупреждение о доступности callback из сети

#### Scenario: Адрес по умолчанию
- **WHEN** прокси запущен без `--host`
- **THEN** предупреждение о callback не пишется
