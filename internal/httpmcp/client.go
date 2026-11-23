// Package httpmcp реализует Remote (см. internal/proxy) поверх MCP
// Streamable HTTP transport (спецификация 2025-03-26).
//
// Сюда же вынесен consumer-side контракт TokenProvider — абстракция получения
// токена и обработки 401, которую реализует пакет oauth.
package httpmcp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/dezer32/mcp-remote/internal/config"
	"github.com/dezer32/mcp-remote/internal/jsonrpc"
	"github.com/dezer32/mcp-remote/internal/proxy"
	"github.com/dezer32/mcp-remote/internal/wwwauth"
)

// TokenProvider абстрагирует получение Authorization для каждого запроса.
// Если конфиг содержит явный заголовок Authorization от пользователя —
// провайдер может возвращать "" (заголовок поставит сам httpmcp.Client из cfg).
type TokenProvider interface {
	// Token возвращает текущий access-токен. "" → заголовок не ставится.
	Token(ctx context.Context) (string, error)
	// HandleUnauthorized обрабатывает 401 на запрос, ушедший с rejectedToken
	// ("" — токен провайдера не отправлялся). wwwAuthenticate — точное
	// значение заголовка WWW-Authenticate из ответа (может быть пустым).
	// allowRefresh=false запрещает refresh: предыдущий шаг этой же цепочки
	// уже дал токен, и его отвергли. authorized=true — был пройден полный
	// флоу авторизации в браузере. На успех httpmcp повторяет запрос.
	HandleUnauthorized(ctx context.Context, wwwAuthenticate, rejectedToken string, allowRefresh bool) (authorized bool, err error)
}

// Internal constants.
const (
	headerSessionID       = "Mcp-Session-Id"
	headerProtocolVersion = "MCP-Protocol-Version"
	headerLastEventID     = "Last-Event-ID"

	contentTypeJSON = "application/json"
	contentTypeSSE  = "text/event-stream"

	maxErrorBody        = 1024
	responseHeaderTout  = 30 * time.Second
	listenBackoffMin    = 1 * time.Second
	listenBackoffMax    = 30 * time.Second
	closeRequestTimeout = 2 * time.Second
	// listenStableStream — сколько должен прожить GET SSE стрим, чтобы
	// считаться стабильным и сбросить backoff перед reconnect-ом.
	listenStableStream = 30 * time.Second

	// maxAuthAttempts — сколько раз одна цепочка 401 (один POST или серия
	// GET SSE до ответа 200) обращается к TokenProvider.HandleUnauthorized.
	// Запрос уходит не больше maxAuthAttempts+1 раз.
	maxAuthAttempts = 3
	// maxErrorDescriptionRunes — предел error_description из WWW-Authenticate
	// в итоговой ошибке: значение приходит от недоверенного сервера.
	maxErrorDescriptionRunes = 200
)

// authChain — состояние обработки 401 в рамках одного запроса.
type authChain struct {
	attempts   int  // вызовы HandleUnauthorized в этой цепочке
	authorized bool // цепочка уже прошла полный флоу авторизации
}

// Client — Streamable HTTP клиент. Реализует proxy.Remote.
type Client struct {
	cfg *config.Config
	tp  TokenProvider
	log *slog.Logger

	httpOnce sync.Once
	httpC    *http.Client

	session sessionState

	// Параметры reconnect-а GET SSE (из const в New; поля — чтобы тесты
	// могли их уменьшить).
	backoffMin   time.Duration
	backoffMax   time.Duration
	stableStream time.Duration
}

// New создаёт клиент. Возвращает ошибку если cfg не валиден на этом уровне
// (например, ServerURL пустой).
func New(cfg *config.Config, tp TokenProvider, log *slog.Logger) (*Client, error) {
	if cfg == nil {
		return nil, errors.New("httpmcp: nil config")
	}
	if log == nil {
		log = slog.Default()
	}
	return &Client{
		cfg:          cfg,
		tp:           tp,
		log:          log,
		backoffMin:   listenBackoffMin,
		backoffMax:   listenBackoffMax,
		stableStream: listenStableStream,
	}, nil
}

// httpClient lazy-init под sync.Once. Один shared экземпляр на Client.
func (c *Client) httpClient() *http.Client {
	c.httpOnce.Do(func() {
		c.httpC = &http.Client{
			Transport: &http.Transport{
				ResponseHeaderTimeout: responseHeaderTout,
			},
			CheckRedirect: checkRedirect,
		}
	})
	return c.httpC
}

// setRequestHeaders проставляет user-defined cfg.Headers, Accept, MCP-Session-Id,
// MCP-Protocol-Version и Authorization из tp.Token если user не задал свой.
// Заголовки из cfg.Headers ставятся ДО системных — поэтому пользовательский
// Authorization перебьёт OAuth, а Accept останется системным.
//
// Возвращает снимок сессии, с которым уходит запрос: по нему ответ решает,
// применять ли пришедший Mcp-Session-Id (extractSessionID) и считать ли 404
// потерей сессии (emit404). Второе значение — токен, поставленный из
// TokenProvider ("" если Authorization пришёл из --header или токена нет):
// его handle401 передаёт провайдеру как отвергнутый.
func (c *Client) setRequestHeaders(ctx context.Context, req *http.Request, withContentType bool) (sessionSnap, string, error) {
	for _, h := range c.cfg.Headers {
		req.Header.Set(h.Name, h.Value)
	}

	req.Header.Set("Accept", contentTypeJSON+", "+contentTypeSSE)
	if withContentType {
		req.Header.Set("Content-Type", contentTypeJSON)
	}

	snap := c.session.snapshot()
	if snap.id != "" {
		req.Header.Set(headerSessionID, snap.id)
	}
	if pv := c.session.getProtocolVersion(); pv != "" {
		req.Header.Set(headerProtocolVersion, pv)
	}

	var token string
	if req.Header.Get("Authorization") == "" && c.tp != nil {
		t, err := c.tp.Token(ctx)
		if err != nil {
			return snap, "", fmt.Errorf("token provider: %w", err)
		}
		if t != "" {
			req.Header.Set("Authorization", "Bearer "+t)
			token = t
		}
	}
	return snap, token, nil
}

// extractSessionID читает Mcp-Session-Id из ответа и сохраняет, если валиден и
// запрос ушёл в текущем поколении сессии. Ответ запроса, отправленного до
// ResetSession, сессию не меняет.
func (c *Client) extractSessionID(resp *http.Response, snap sessionSnap) {
	id := resp.Header.Get(headerSessionID)
	if id == "" {
		return
	}
	if !isASCIIPrintable(id) {
		c.log.Warn("ignored non-ASCII-printable Mcp-Session-Id", slog.String("value", id))
		return
	}
	if !c.session.setSessionIDIfCurrent(id, snap.gen) {
		c.log.Debug("ignored Mcp-Session-Id from response to request of previous session",
			slog.String("value", id))
	}
}

// Send — POST одного JSON-RPC сообщения. См. интерфейс proxy.Remote.
func (c *Client) Send(ctx context.Context, msg jsonrpc.Message) (<-chan proxy.MessageOrError, error) {
	body, err := jsonrpc.Encode(msg)
	if err != nil {
		return nil, fmt.Errorf("encode: %w", err)
	}
	out := make(chan proxy.MessageOrError, 4)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				c.emitErr(ctx, out, fmt.Errorf("httpmcp.Send panic: %v", r))
			}
			close(out)
		}()
		c.doSend(ctx, body, out)
	}()
	return out, nil
}

// doSend выполняет POST и обрабатывает ответ. На 401 запрос повторяется,
// пока handle401 разрешает (цепочка authChain ограничена maxAuthAttempts).
// НЕ закрывает out — caller отвечает за close.
func (c *Client) doSend(ctx context.Context, body []byte, out chan<- proxy.MessageOrError) {
	var chain authChain
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.ServerURL, bytes.NewReader(body))
		if err != nil {
			c.emitErr(ctx, out, fmt.Errorf("new request: %w", err))
			return
		}
		snap, sentToken, err := c.setRequestHeaders(ctx, req, true)
		if err != nil {
			c.emitErr(ctx, out, err)
			return
		}

		resp, err := c.httpClient().Do(req)
		if err != nil {
			c.emitErr(ctx, out, fmt.Errorf("http do: %w", err))
			return
		}

		switch resp.StatusCode {
		case http.StatusAccepted:
			c.extractSessionID(resp, snap)
			drainAndClose(resp.Body)
			return

		case http.StatusOK:
			c.extractSessionID(resp, snap)
			c.handleOK(ctx, resp, out)
			return

		case http.StatusUnauthorized:
			if !c.handle401(ctx, req, resp, &chain, sentToken, out) {
				return
			}
			continue

		case http.StatusNotFound:
			c.emit404(ctx, resp, out, snap)
			return

		default:
			excerpt := readBodyExcerpt(resp.Body)
			resp.Body.Close()
			c.emitErr(ctx, out, fmt.Errorf("http %d: %s", resp.StatusCode, excerpt))
			return
		}
	}
}

// handleOK разбирает тело 200 OK по Content-Type и emit-ит сообщения.
// Body закрывается внутри.
func (c *Client) handleOK(ctx context.Context, resp *http.Response, out chan<- proxy.MessageOrError) {
	ct := resp.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		drainAndClose(resp.Body)
		c.emitErr(ctx, out, fmt.Errorf("parse content-type %q: %w", ct, err))
		return
	}
	defer resp.Body.Close()
	switch mediaType {
	case contentTypeJSON:
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			c.emitErr(ctx, out, fmt.Errorf("read body: %w", err))
			return
		}
		trimmed := bytes.TrimSpace(data)
		if len(trimmed) == 0 {
			return
		}
		msgs, err := jsonrpc.BatchDecode(trimmed)
		if err != nil {
			c.emitErr(ctx, out, fmt.Errorf("decode: %w", err))
			return
		}
		for _, m := range msgs {
			if !c.emit(ctx, out, proxy.MessageOrError{Msg: m}) {
				return
			}
		}
	case contentTypeSSE:
		if err := parseSSE(ctx, resp.Body, out, nil); err != nil && !errors.Is(err, context.Canceled) {
			c.emitErr(ctx, out, fmt.Errorf("sse: %w", err))
		}
	default:
		c.emitErr(ctx, out, fmt.Errorf("unexpected content-type: %s", ct))
	}
}

// Listen — GET SSE для server-initiated сообщений. См. proxy.Remote.
func (c *Client) Listen(ctx context.Context) (<-chan proxy.MessageOrError, error) {
	out := make(chan proxy.MessageOrError, 4)
	go c.doListen(ctx, out)
	return out, nil
}

// doListen — цикл reconnect для GET SSE.
//
// close(out) — последнее действие горутины (после всех extractSessionID и
// setLastID), а все ожидания внутри прерываются по ctx. Поэтому consumer,
// отменивший ctx и дочитавший канал до закрытия, знает: продюсер завершён и
// сессию больше не тронет.
//
// Backoff между reconnect-ами: первый reconnect — сразу, далее backoffMin,
// 2·backoffMin… до backoffMax (с jitter ±25%, т.е. фактическая пауза до
// 1.25·backoffMax). Сбрасывается только после стрима, прожившего stableStream:
// сервер, сразу закрывающий GET, не загонит клиент в цикл без пауз.
func (c *Client) doListen(ctx context.Context, out chan<- proxy.MessageOrError) {
	defer close(out)

	var (
		lastEventID string
		backoff     time.Duration // 0 → первый retry без задержки
		chain       authChain     // цепочка 401, сбрасывается на 200
	)

	setLastID := func(id string) {
		lastEventID = id
	}

	for {
		if ctx.Err() != nil {
			return
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.ServerURL, nil)
		if err != nil {
			c.emitErr(ctx, out, fmt.Errorf("new request: %w", err))
			return
		}
		snap, sentToken, err := c.setRequestHeaders(ctx, req, false)
		if err != nil {
			c.emitErr(ctx, out, err)
			return
		}
		if lastEventID != "" {
			req.Header.Set(headerLastEventID, lastEventID)
		}

		resp, err := c.httpClient().Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			c.log.Debug("listen: request error, will reconnect", slog.String("err", err.Error()))
			if !c.sleepBackoff(ctx, &backoff) {
				return
			}
			continue
		}

		switch resp.StatusCode {
		case http.StatusMethodNotAllowed:
			// Сервер не поддерживает GET SSE — clean exit.
			drainAndClose(resp.Body)
			return

		case http.StatusUnauthorized:
			if !c.handle401(ctx, req, resp, &chain, sentToken, out) {
				return
			}
			continue

		case http.StatusNotFound:
			c.emit404(ctx, resp, out, snap)
			return

		case http.StatusOK:
			c.extractSessionID(resp, snap)
			chain = authChain{}
			ct := resp.Header.Get("Content-Type")
			mediaType, _, mtErr := mime.ParseMediaType(ct)
			if mtErr != nil || mediaType != contentTypeSSE {
				drainAndClose(resp.Body)
				c.emitErr(ctx, out, fmt.Errorf("listen: unexpected content-type %q", ct))
				return
			}
			connectedAt := time.Now()
			err := parseSSE(ctx, resp.Body, out, setLastID)
			resp.Body.Close()
			if ctx.Err() != nil {
				return
			}
			if err != nil && !errors.Is(err, io.EOF) {
				c.log.Debug("listen: sse error, will reconnect", slog.String("err", err.Error()))
			}
			// Сбрасываем backoff только после стабильного стрима: сразу
			// закрывающийся стрим продолжает наращивать паузу.
			if time.Since(connectedAt) >= c.stableStream {
				backoff = 0
			}
			if !c.sleepBackoff(ctx, &backoff) {
				return
			}
			continue

		default:
			if isRetryableListenStatus(resp.StatusCode) {
				// Тело закрываем до паузы — не держим соединение во время backoff.
				drainAndClose(resp.Body)
				c.log.Debug("listen: retryable status, will reconnect",
					slog.Int("status", resp.StatusCode))
				if !c.sleepBackoff(ctx, &backoff) {
					return
				}
				continue
			}
			excerpt := readBodyExcerpt(resp.Body)
			resp.Body.Close()
			c.emitErr(ctx, out, fmt.Errorf("listen: http %d: %s", resp.StatusCode, excerpt))
			return
		}
	}
}

// isRetryableListenStatus — статусы GET SSE, после которых имеет смысл
// переподключиться с backoff (временная недоступность), а не останавливать
// listener: 408, 429 и 5xx.
func isRetryableListenStatus(code int) bool {
	switch {
	case code == http.StatusRequestTimeout, code == http.StatusTooManyRequests:
		return true
	case code >= 500 && code <= 599:
		return true
	}
	return false
}

// sleepBackoff ждёт текущий backoff и увеличивает его (capped c.backoffMax,
// с jitter ±25%). Если backoff == 0 — ничего не ждёт и сразу выставляет минимум.
// Возвращает false если ctx отменён.
func (c *Client) sleepBackoff(ctx context.Context, backoff *time.Duration) bool {
	if *backoff == 0 {
		*backoff = c.backoffMin
		return ctx.Err() == nil
	}
	// jitter ±25%
	jitter := time.Duration(rand.Int63n(int64(*backoff / 2)))
	wait := *backoff - (*backoff / 4) + jitter
	select {
	case <-ctx.Done():
		return false
	case <-time.After(wait):
	}
	*backoff *= 2
	if *backoff > c.backoffMax {
		*backoff = c.backoffMax
	}
	return true
}

// SetProtocolVersion вызывается proxy после успешного initialize.
func (c *Client) SetProtocolVersion(version string) {
	c.session.setProtocolVersion(version)
}

// ResetSession обнуляет Mcp-Session-Id (использует proxy перед recovery).
func (c *Client) ResetSession() {
	c.session.clearSessionID()
}

// Close посылает DELETE на endpoint если у нас есть sessionID и завершает работу.
func (c *Client) Close(ctx context.Context) error {
	sid := c.session.getSessionID()
	if sid == "" {
		return nil
	}
	delCtx, cancel := context.WithTimeout(ctx, closeRequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(delCtx, http.MethodDelete, c.cfg.ServerURL, nil)
	if err != nil {
		c.log.Warn("close: new request", slog.String("err", err.Error()))
		return nil
	}
	// Снимок сессии DELETE-у не нужен: ответ сессию не меняет.
	if _, _, err = c.setRequestHeaders(delCtx, req, false); err != nil {
		c.log.Warn("close: set headers", slog.String("err", err.Error()))
		return nil
	}

	resp, err := c.httpClient().Do(req)
	if err != nil {
		c.log.Warn("close: do", slog.String("err", err.Error()))
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusMethodNotAllowed {
		// Сервер не поддерживает DELETE — ignore.
		return nil
	}
	if resp.StatusCode >= 400 {
		c.log.Warn("close: non-2xx", slog.Int("status", resp.StatusCode))
	}
	return nil
}

// handle401 — общая обработка 401 для POST и GET SSE. Закрывает resp.Body.
// Пишет debug-лог с причиной отказа из WWW-Authenticate и решает, можно ли
// повторить запрос:
//   - цепочка уже прошла полный флоу авторизации — ошибка без нового флоу;
//   - исчерпан лимит maxAuthAttempts — ошибка;
//   - иначе HandleUnauthorized с отвергнутым токеном; refresh разрешён только
//     на первом шаге цепочки (дальше отвергнут токен, выданный этой цепочкой).
//
// Возвращает true, если caller-у можно повторить запрос, иначе false (ошибка
// уже emit-нута). sentToken — токен провайдера, с которым ушёл req.
func (c *Client) handle401(ctx context.Context, req *http.Request, resp *http.Response, chain *authChain, sentToken string, out chan<- proxy.MessageOrError) bool {
	www := resp.Header.Get("WWW-Authenticate")
	drainAndClose(resp.Body)

	params := wwwauth.ParseBearer(www)
	errCode := params["error"]
	errDesc := truncateRunes(params["error_description"], maxErrorDescriptionRunes)
	c.log.Debug("remote 401",
		slog.String("method", req.Method),
		slog.Int("attempt", chain.attempts+1),
		slog.Bool("token_sent", req.Header.Get("Authorization") != ""),
		slog.String("error", errCode),
		slog.String("error_description", errDesc))

	if chain.authorized {
		c.emitErr(ctx, out, unauthorizedError("token rejected right after authorization", errCode, errDesc))
		return false
	}
	if chain.attempts >= maxAuthAttempts {
		c.emitErr(ctx, out, unauthorizedError(fmt.Sprintf("giving up after %d authorization attempts", maxAuthAttempts), errCode, errDesc))
		return false
	}
	if c.tp == nil {
		c.emitErr(ctx, out, unauthorizedError("no token provider", errCode, errDesc))
		return false
	}
	authorized, err := c.tp.HandleUnauthorized(ctx, www, sentToken, chain.attempts == 0)
	chain.attempts++
	if err != nil {
		c.emitErr(ctx, out, fmt.Errorf("handle unauthorized: %w", err))
		return false
	}
	chain.authorized = authorized
	return true
}

// unauthorizedError — итоговая ошибка 401:
// "http 401: <причина>[: <error>][: <error_description>]".
func unauthorizedError(reason, errCode, errDesc string) error {
	msg := "http 401: " + reason
	if errCode != "" {
		msg += ": " + errCode
	}
	if errDesc != "" {
		msg += ": " + errDesc
	}
	return errors.New(msg)
}

// truncateRunes обрезает s до n рун, не разрывая UTF-8 последовательности.
func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// emit404 — общая обработка 404. ErrSessionLost, если запрос ушёл с session id
// (snap — снимок на момент отправки, а не текущее состояние: за время запроса
// сессию мог сбросить recovery или установить другой запрос), иначе обычный
// http-error. Закрывает resp.Body (симметрично handle401).
func (c *Client) emit404(ctx context.Context, resp *http.Response, out chan<- proxy.MessageOrError, snap sessionSnap) {
	drainAndClose(resp.Body)
	if snap.id != "" {
		c.emitErr(ctx, out, proxy.ErrSessionLost)
		return
	}
	c.emitErr(ctx, out, fmt.Errorf("http 404"))
}

// emit неблокирующе отправляет moe в out, либо завершается на ctx cancel.
// Возвращает false если ctx отменён.
func (c *Client) emit(ctx context.Context, out chan<- proxy.MessageOrError, moe proxy.MessageOrError) bool {
	select {
	case <-ctx.Done():
		return false
	case out <- moe:
		return true
	}
}

// emitErr вспомогательно отправляет ошибку.
func (c *Client) emitErr(ctx context.Context, out chan<- proxy.MessageOrError, err error) {
	c.emit(ctx, out, proxy.MessageOrError{Err: err})
}

// drainAndClose закрывает body, читая остаток (для keep-alive).
func drainAndClose(body io.ReadCloser) {
	_, _ = io.Copy(io.Discard, io.LimitReader(body, 1<<20))
	body.Close()
}

// readBodyExcerpt читает до maxErrorBody байт для error-сообщения.
func readBodyExcerpt(body io.Reader) string {
	buf, _ := io.ReadAll(io.LimitReader(body, maxErrorBody))
	s := strings.TrimSpace(string(buf))
	if s == "" {
		return "<empty body>"
	}
	return s
}
