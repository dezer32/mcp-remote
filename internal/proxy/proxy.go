// Package proxy маршрутизирует JSON-RPC сообщения между локальным транспортом
// (stdio) и удалённым MCP-сервером (Streamable HTTP).
//
// Интерфейсы Transport и Remote, а также тип MessageOrError и sentinel
// ErrSessionLost определены здесь — это consumer-side контракты, к которым
// прицепляются реализации в пакетах stdio и httpmcp.
package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/dezer32/mcp-remote/internal/jsonrpc"
)

// ErrSessionLost — sentinel, сигнализирующий что remote вернул 404 на запрос
// с Mcp-Session-Id (сессия истекла). НЕ должен попадать в исходящие JSON-RPC
// сообщения клиенту — proxy перехватывает его и запускает recovery.
var ErrSessionLost = errors.New("mcp session lost (404 Mcp-Session-Id)")

// MessageOrError — единица канала из Remote.Send/Listen. Если Err == nil,
// валиден Msg; иначе валидна Err (включая ErrSessionLost).
type MessageOrError struct {
	Msg jsonrpc.Message
	Err error
}

// Transport — локальный stdio-канал к MCP-клиенту (Claude Desktop и т.п.).
type Transport interface {
	// Read блокируется до прихода сообщения. На EOF → io.EOF.
	// На отмену ctx → ctx.Err() (фоновая read-горутина может остаться висеть до закрытия stdin).
	Read(ctx context.Context) (jsonrpc.Message, error)
	// Write атомарно записывает все msgs в порядке аргументов под единым мьютексом.
	Write(ctx context.Context, msgs ...jsonrpc.Message) error
	Close() error
}

// Remote — удалённый MCP-сервер по Streamable HTTP transport.
type Remote interface {
	// Send: для notification/response → закрытый канал сразу после 202.
	// Для request → канал получает финальный response и server-initiated
	// request/notification, привязанные к этому request-у; закрывается после
	// окончания SSE-стрима. На session loss → MessageOrError{Err: ErrSessionLost}
	// и закрытие канала.
	Send(ctx context.Context, msg jsonrpc.Message) (<-chan MessageOrError, error)
	// Listen — GET SSE для server-initiated вне client-request. Контракт ошибок
	// тот же, что у Send.
	Listen(ctx context.Context) (<-chan MessageOrError, error)
	// SetProtocolVersion вызывается proxy один раз после успешного initialize.
	SetProtocolVersion(version string)
	// ResetSession очищает кэшированный Mcp-Session-Id (используется recovery).
	ResetSession()
	// Close посылает DELETE на endpoint и освобождает ресурсы.
	Close(ctx context.Context) error
}

// Proxy — точка соединения Transport ↔ Remote. Конструируется в main.go.
type Proxy struct {
	transport Transport
	remote    Remote
	log       *slog.Logger

	// mu защищает initialize-state и pendingReplay/inFlight.
	mu               sync.Mutex
	firstInitialize  *jsonrpc.Message
	initializedNotif *jsonrpc.Message
	pendingReplay    []jsonrpc.Message
	// inFlight — client-request id → исходное сообщение. Используется только
	// для error-blanket в recovery-fail (id уже есть, но храним req на случай
	// будущей необходимости).
	inFlight map[string]jsonrpc.Message

	// recoveryMu блокирует нормальный поток на время recovery (RLock в normal flow,
	// Lock в recovery). Stdin-dispatch держит RLock, что заставляет recovery
	// дождаться завершения in-flight перед началом replay.
	recoveryMu sync.RWMutex
	// recoveryTrigger — сигнал к recovery. Buffered 1 чтобы coalescing нескольких
	// одновременных session-lost в один проход.
	recoveryTrigger chan struct{}
	// recoveryFail закрывается при невосстановимой recovery — основной loop по нему завершается.
	recoveryFail chan struct{}
	// recoveryFailErr — почему упало recovery (под mu).
	recoveryFailErr error
	// recoveryAttempts — счётчик подряд идущих recovery-проходов. Сбрасывается на успех
	// последующего request-а. Защита от петли: если N подряд приводят к session-lost — fail.
	recoveryAttempts int
}

// maxRecoveryAttempts — максимум попыток восстановления подряд без успешного
// "обычного" request. Защита от бесконечной петли при постоянно сбрасываемой сессии.
const maxRecoveryAttempts = 3

// MCP-specific JSON-RPC method names, перехватываемые proxy для recovery-replay.
const (
	methodInitialize       = "initialize"
	methodNotifInitialized = "notifications/initialized"
)

// New собирает proxy. Логика — в Run.
func New(t Transport, r Remote, log *slog.Logger) *Proxy {
	if log == nil {
		log = slog.Default()
	}
	return &Proxy{
		transport:       t,
		remote:          r,
		log:             log,
		inFlight:        make(map[string]jsonrpc.Message),
		recoveryTrigger: make(chan struct{}, 1),
		recoveryFail:    make(chan struct{}),
	}
}

// Run — главный цикл. Запускает три фоновые горутины (stdin reader, remote
// listener, recovery dispatcher) и ждёт завершения по EOF/ctx/recovery-fail.
func (p *Proxy) Run(ctx context.Context) error {
	loopCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup

	// readerErr — ошибка завершения stdin-reader (EOF, ctx, ...).
	var (
		readerErrMu sync.Mutex
		readerErr   error
	)
	setReaderErr := func(err error) {
		readerErrMu.Lock()
		if readerErr == nil {
			readerErr = err
		}
		readerErrMu.Unlock()
	}
	getReaderErr := func() error {
		readerErrMu.Lock()
		defer readerErrMu.Unlock()
		return readerErr
	}

	// Listener: server-initiated сообщения вне client-request.
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.runListener(loopCtx, &wg)
	}()

	// Recovery dispatcher.
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.runRecovery(loopCtx, &wg)
	}()

	// Stdin reader.
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := p.runStdinReader(loopCtx, &wg)
		setReaderErr(err)
		cancel() // EOF/Read error → инициируем shutdown.
	}()

	// Ждём либо завершения reader-а, либо ctx, либо recovery-fail.
	select {
	case <-loopCtx.Done():
	case <-p.recoveryFail:
		cancel()
	}

	// Дожидаемся всех горутин (в т.ч. per-request).
	wg.Wait()

	// Транспорты закрываем — пусть отпустят ресурсы.
	closeCtx, closeCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer closeCancel()
	_ = p.remote.Close(closeCtx)
	_ = p.transport.Close()

	// Сначала проверяем recovery-fail (более информативно).
	p.mu.Lock()
	rFail := p.recoveryFailErr
	p.mu.Unlock()
	if rFail != nil {
		return rFail
	}

	if rerr := getReaderErr(); rerr != nil {
		if errors.Is(rerr, io.EOF) || errors.Is(rerr, context.Canceled) {
			return nil
		}
		return rerr
	}

	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}

	return nil
}

// runStdinReader — главный цикл чтения из transport. На каждое сообщение
// диспатчит в правильную ветку обработки.
func (p *Proxy) runStdinReader(ctx context.Context, wg *sync.WaitGroup) error {
	for {
		msg, err := p.transport.Read(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				p.log.Debug("stdin EOF, shutting down")
				return io.EOF
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			p.log.Error("transport read", slog.String("err", err.Error()))
			return err
		}

		// Перед dispatch — ждём пока recovery не идёт.
		// RLock блокируется на время recovery (которая держит Lock).
		p.recoveryMu.RLock()

		switch {
		case msg.IsRequest():
			p.handleClientRequest(ctx, wg, msg)
		case msg.IsNotification():
			p.handleClientNotification(ctx, wg, msg)
		case msg.IsResponse():
			p.handleClientResponse(ctx, wg, msg)
		default:
			p.log.Warn("unknown JSON-RPC message from client",
				slog.String("method", msg.Method),
				slog.Bool("has_id", msg.HasID()))
		}

		p.recoveryMu.RUnlock()

		// recovery-fail во время dispatch — выходим.
		select {
		case <-p.recoveryFail:
			return errors.New("recovery failed")
		default:
		}
	}
}

// handleClientRequest диспатчит request от клиента в remote и проксирует обратно
// все ответы. Перехватывает initialize и ErrSessionLost.
func (p *Proxy) handleClientRequest(ctx context.Context, wg *sync.WaitGroup, req jsonrpc.Message) {
	idKey := string(req.ID)
	isInitialize := req.Method == methodInitialize

	if isInitialize {
		// Делаем глубокую копию (json.RawMessage — share underlying bytes, но
		// jsonrpc.Decode уже скопировал из приёмного буфера).
		cp := req
		p.mu.Lock()
		p.firstInitialize = &cp
		p.mu.Unlock()
	}

	p.mu.Lock()
	p.inFlight[idKey] = req
	p.mu.Unlock()

	wg.Add(1)
	go func() {
		defer wg.Done()
		p.dispatchRequest(ctx, req, isInitialize)
	}()
}

// dispatchRequest — общая логика для оригинальной отправки и для replay.
// Читает респонсы и пишет клиенту. На ErrSessionLost — кладёт req в pendingReplay
// и тригерит recovery.
func (p *Proxy) dispatchRequest(ctx context.Context, req jsonrpc.Message, isInitialize bool) {
	idKey := string(req.ID)

	respCh, err := p.remote.Send(ctx, req)
	if err != nil {
		p.writeErrorResponse(ctx, req.ID, fmt.Sprintf("remote send: %v", err))
		p.removeInFlight(idKey)
		return
	}

	for {
		select {
		case <-ctx.Done():
			p.removeInFlight(idKey)
			return
		case me, ok := <-respCh:
			if !ok {
				p.removeInFlight(idKey)
				return
			}
			if me.Err != nil {
				if errors.Is(me.Err, ErrSessionLost) {
					p.log.Warn("session lost during request, queuing for replay",
						slog.String("method", req.Method),
						slog.String("id", idKey))
					// НЕ пишем клиенту. Складываем в pendingReplay.
					p.mu.Lock()
					p.pendingReplay = append(p.pendingReplay, req)
					p.mu.Unlock()
					p.removeInFlight(idKey)
					p.triggerRecovery()
					return
				}
				p.log.Error("remote response error",
					slog.String("method", req.Method),
					slog.String("err", me.Err.Error()))
				p.writeErrorResponse(ctx, req.ID, me.Err.Error())
				p.removeInFlight(idKey)
				return
			}

			// Это либо финальный response (HasID && method=="" && (Result|Error)),
			// либо server-initiated request/notification внутри SSE.
			if isInitialize && me.Msg.IsResponse() && len(me.Msg.Result) > 0 {
				p.captureProtocolVersion(me.Msg.Result)
			}

			if werr := p.transport.Write(ctx, me.Msg); werr != nil {
				p.log.Error("transport write",
					slog.String("err", werr.Error()))
				// Не отменяем — клиент скорее всего закрыл stdout.
			}

			// Если это финальный response на наш request — снимаем in-flight
			// и сбрасываем recovery-attempt счётчик: значит сессия в норме.
			if me.Msg.IsResponse() && bytes.Equal(me.Msg.ID, req.ID) {
				p.removeInFlight(idKey)
				p.mu.Lock()
				p.recoveryAttempts = 0
				p.mu.Unlock()
			}
		}
	}
}

func (p *Proxy) removeInFlight(idKey string) {
	p.mu.Lock()
	delete(p.inFlight, idKey)
	p.mu.Unlock()
}

// captureProtocolVersion парсит result.protocolVersion и зовёт remote.SetProtocolVersion.
func (p *Proxy) captureProtocolVersion(result json.RawMessage) {
	var v struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if err := json.Unmarshal(result, &v); err != nil {
		p.log.Debug("could not parse initialize response", slog.String("err", err.Error()))
		return
	}
	if v.ProtocolVersion == "" {
		return
	}
	p.log.Debug("got protocol version", slog.String("version", v.ProtocolVersion))
	p.remote.SetProtocolVersion(v.ProtocolVersion)
}

// handleClientNotification — fire-and-forget remote.Send. Перехватывает
// notifications/initialized для последующего replay.
func (p *Proxy) handleClientNotification(ctx context.Context, wg *sync.WaitGroup, notif jsonrpc.Message) {
	if notif.Method == methodNotifInitialized {
		cp := notif
		p.mu.Lock()
		p.initializedNotif = &cp
		p.mu.Unlock()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		ch, err := p.remote.Send(ctx, notif)
		if err != nil {
			p.log.Error("notification send",
				slog.String("method", notif.Method),
				slog.String("err", err.Error()))
			return
		}
		// Дренаж канала (для notification обычно закрыт сразу).
		for me := range ch {
			if me.Err != nil {
				if errors.Is(me.Err, ErrSessionLost) {
					p.log.Warn("session lost during notification",
						slog.String("method", notif.Method))
					p.triggerRecovery()
					return
				}
				p.log.Error("remote notification error",
					slog.String("method", notif.Method),
					slog.String("err", me.Err.Error()))
				return
			}
			// Если remote всё-таки прислал msg на notification — отдаём клиенту.
			if werr := p.transport.Write(ctx, me.Msg); werr != nil {
				p.log.Error("transport write", slog.String("err", werr.Error()))
			}
		}
	}()
}

// handleClientResponse — клиент отвечает на server-initiated request.
// Fire-and-forget в remote.
func (p *Proxy) handleClientResponse(ctx context.Context, wg *sync.WaitGroup, resp jsonrpc.Message) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		ch, err := p.remote.Send(ctx, resp)
		if err != nil {
			p.log.Error("client response send", slog.String("err", err.Error()))
			return
		}
		for me := range ch {
			if me.Err != nil {
				if errors.Is(me.Err, ErrSessionLost) {
					p.triggerRecovery()
					return
				}
				p.log.Error("remote response-forward error",
					slog.String("err", me.Err.Error()))
				return
			}
			if werr := p.transport.Write(ctx, me.Msg); werr != nil {
				p.log.Error("transport write", slog.String("err", werr.Error()))
			}
		}
	}()
}

// runListener — GET SSE стрим для server-initiated сообщений вне request.
// На ErrSessionLost — тригерит recovery и перезапускается.
func (p *Proxy) runListener(ctx context.Context, _ *sync.WaitGroup) {
	for {
		if ctx.Err() != nil {
			return
		}

		lch, err := p.remote.Listen(ctx)
		if err != nil {
			// Listen может вернуть 405 (transport не поддерживает GET) — это ok, выходим тихо.
			p.log.Debug("remote listen returned err, stopping",
				slog.String("err", err.Error()))
			return
		}

		sessionLost := false
		for me := range lch {
			if me.Err != nil {
				if errors.Is(me.Err, ErrSessionLost) {
					p.log.Warn("session lost on Listen stream")
					p.triggerRecovery()
					sessionLost = true
					break
				}
				p.log.Error("listen stream error",
					slog.String("err", me.Err.Error()))
				// Нефатальная ошибка — выходим из текущего стрима, попробуем поднять заново.
				break
			}
			if werr := p.transport.Write(ctx, me.Msg); werr != nil {
				p.log.Error("transport write from listener",
					slog.String("err", werr.Error()))
			}
		}

		if !sessionLost {
			// Stream нормально закрылся — выходим.
			return
		}

		// При session-lost ждём пока recovery завершится прежде чем reopen.
		// Берём RLock — он не выдадут пока recovery держит Lock.
		p.recoveryMu.RLock()
		p.recoveryMu.RUnlock()
		// recovery-fail могла произойти — проверим.
		select {
		case <-p.recoveryFail:
			return
		case <-ctx.Done():
			return
		default:
		}
		// Пробуем заново.
	}
}

// triggerRecovery — неблокирующий сигнал. Множественные одновременные вызовы
// схлопываются в один проход recovery.
func (p *Proxy) triggerRecovery() {
	select {
	case p.recoveryTrigger <- struct{}{}:
	default:
	}
}

// runRecovery читает сигналы и выполняет восстановление сессии.
func (p *Proxy) runRecovery(ctx context.Context, wg *sync.WaitGroup) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.recoveryTrigger:
			p.mu.Lock()
			p.recoveryAttempts++
			attempts := p.recoveryAttempts
			p.mu.Unlock()

			if attempts > maxRecoveryAttempts {
				err := fmt.Errorf("recovery: exceeded %d attempts", maxRecoveryAttempts)
				p.log.Error("recovery aborted", slog.String("err", err.Error()))
				p.failAndShutdown(ctx, err)
				return
			}

			if err := p.doRecovery(ctx, wg); err != nil {
				p.log.Error("recovery failed", slog.String("err", err.Error()))
				p.failAndShutdown(ctx, err)
				return
			}
			p.log.Info("session recovered", slog.Int("attempt", attempts))
		}
	}
}

// failAndShutdown — атомарно записывает причину и закрывает recoveryFail.
func (p *Proxy) failAndShutdown(ctx context.Context, err error) {
	p.mu.Lock()
	inFlightSnap := make(map[string]jsonrpc.Message, len(p.inFlight))
	for k, v := range p.inFlight {
		inFlightSnap[k] = v
	}
	pending := p.pendingReplay
	p.pendingReplay = nil
	if p.recoveryFailErr == nil {
		p.recoveryFailErr = err
		close(p.recoveryFail)
	}
	p.mu.Unlock()

	p.failAllPending(ctx, inFlightSnap, pending, err)
}

// doRecovery делает один проход восстановления: reset → initialize → initialized → replay.
// Под Lock recoveryMu, чтобы stdin-dispatch не выпускал новых in-flight в это время.
func (p *Proxy) doRecovery(ctx context.Context, wg *sync.WaitGroup) error {
	p.recoveryMu.Lock()
	defer p.recoveryMu.Unlock()

	// Сначала забираем сохранённые initialize/initialized + pending.
	p.mu.Lock()
	savedInit := p.firstInitialize
	savedInitNotif := p.initializedNotif
	pending := p.pendingReplay
	p.pendingReplay = nil
	inFlightSnap := make(map[string]jsonrpc.Message, len(p.inFlight))
	for k, v := range p.inFlight {
		inFlightSnap[k] = v
	}
	p.mu.Unlock()

	if savedInit == nil {
		return errors.New("recovery: no captured initialize request")
	}

	// Step 1: reset session.
	p.remote.ResetSession()
	p.log.Debug("recovery: session reset")

	// Step 2: replay initialize, ждём response, забираем protocolVersion.
	if err := p.replayInitialize(ctx, *savedInit); err != nil {
		// Recovery не получилась — отдаём ошибки всем in-flight и pending.
		p.failAllPending(ctx, inFlightSnap, pending, err)
		return fmt.Errorf("replay initialize: %w", err)
	}
	p.log.Debug("recovery: initialize replayed")

	// Step 3: replay initialized notification (если был).
	if savedInitNotif != nil {
		if err := p.replayInitializedNotif(ctx, *savedInitNotif); err != nil {
			p.failAllPending(ctx, inFlightSnap, pending, err)
			return fmt.Errorf("replay initialized notif: %w", err)
		}
		p.log.Debug("recovery: initialized notif replayed")
	}

	// Step 4: replay все pending requests в отдельных горутинах.
	// dispatchRequest сам не берёт recoveryMu, так что они стартуют сразу;
	// recoveryMu.Lock мы отпустим в defer этой функции.
	for _, req := range pending {
		req := req
		p.mu.Lock()
		p.inFlight[string(req.ID)] = req
		p.mu.Unlock()

		wg.Add(1)
		go func() {
			defer wg.Done()
			p.dispatchRequest(ctx, req, req.Method == methodInitialize)
		}()
	}

	return nil
}

// replayInitialize отправляет initialize и забирает response (с protocolVersion).
func (p *Proxy) replayInitialize(ctx context.Context, init jsonrpc.Message) error {
	respCh, err := p.remote.Send(ctx, init)
	if err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case me, ok := <-respCh:
			if !ok {
				return errors.New("initialize channel closed without response")
			}
			if me.Err != nil {
				return me.Err
			}
			if me.Msg.IsResponse() && bytes.Equal(me.Msg.ID, init.ID) {
				if len(me.Msg.Result) > 0 {
					p.captureProtocolVersion(me.Msg.Result)
				}
				if me.Msg.Error != nil {
					return fmt.Errorf("initialize replay returned error: %s", me.Msg.Error.Message)
				}
				return nil
			}
			// Прочее (например, server-initiated request внутри initialize SSE) игнорируем —
			// recovery не должен прокидывать ничего лишнего клиенту, мы заменяем сессию.
		}
	}
}

// replayInitializedNotif отправляет initialized notification.
func (p *Proxy) replayInitializedNotif(ctx context.Context, notif jsonrpc.Message) error {
	ch, err := p.remote.Send(ctx, notif)
	if err != nil {
		return err
	}
	// Дренаж канала (обычно закрыт сразу).
	for me := range ch {
		if me.Err != nil {
			return me.Err
		}
	}
	return nil
}

// failAllPending пишет error response клиенту для каждого in-flight и pending
// request — используется при recovery-fail.
func (p *Proxy) failAllPending(ctx context.Context, inFlight map[string]jsonrpc.Message, pending []jsonrpc.Message, cause error) {
	seen := make(map[string]struct{}, len(inFlight)+len(pending))

	emit := func(id json.RawMessage) {
		if len(id) == 0 {
			return
		}
		key := string(id)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		p.writeErrorResponse(ctx, id, fmt.Sprintf("session lost, recovery failed: %v", cause))
	}

	for _, req := range inFlight {
		emit(req.ID)
	}
	for _, m := range pending {
		emit(m.ID)
	}

	p.mu.Lock()
	p.inFlight = make(map[string]jsonrpc.Message)
	p.mu.Unlock()
}

// writeErrorResponse пишет клиенту JSON-RPC error response с кодом -32000.
func (p *Proxy) writeErrorResponse(ctx context.Context, id json.RawMessage, message string) {
	if len(id) == 0 {
		// notification — клиенту ничего не возвращаем.
		return
	}
	errMsg := jsonrpc.Message{
		JSONRPC: jsonrpc.Version,
		ID:      id,
		Error: &jsonrpc.Error{
			Code:    -32000,
			Message: message,
		},
	}
	if werr := p.transport.Write(ctx, errMsg); werr != nil {
		p.log.Error("transport write error response",
			slog.String("err", werr.Error()))
	}
}
