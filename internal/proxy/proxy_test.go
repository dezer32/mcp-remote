package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dezer32/mcp-remote/internal/jsonrpc"
	"github.com/dezer32/mcp-remote/internal/logging"
)

// ---------- fakeTransport ----------

type fakeTransport struct {
	mu       sync.Mutex
	inMsgs   chan jsonrpc.Message
	outMsgs  chan jsonrpc.Message
	closed   bool
	writeErr error
}

func newFakeTransport() *fakeTransport {
	return &fakeTransport{
		inMsgs:  make(chan jsonrpc.Message, 64),
		outMsgs: make(chan jsonrpc.Message, 64),
	}
}

func (t *fakeTransport) Read(ctx context.Context) (jsonrpc.Message, error) {
	select {
	case m, ok := <-t.inMsgs:
		if !ok {
			return jsonrpc.Message{}, io.EOF
		}
		return m, nil
	case <-ctx.Done():
		return jsonrpc.Message{}, ctx.Err()
	}
}

func (t *fakeTransport) Write(ctx context.Context, msgs ...jsonrpc.Message) error {
	t.mu.Lock()
	werr := t.writeErr
	t.mu.Unlock()
	if werr != nil {
		return werr
	}
	for _, m := range msgs {
		select {
		case t.outMsgs <- m:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (t *fakeTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.closed {
		t.closed = true
		close(t.inMsgs)
	}
	return nil
}

func (t *fakeTransport) PushIn(m jsonrpc.Message) {
	t.inMsgs <- m
}

func (t *fakeTransport) ExpectOut(timeout time.Duration) (jsonrpc.Message, bool) {
	select {
	case m := <-t.outMsgs:
		return m, true
	case <-time.After(timeout):
		return jsonrpc.Message{}, false
	}
}

// ---------- fakeRemote ----------

// fakeRemote — настраивается через handlerFunc, который для каждого incoming msg
// возвращает срез событий (MessageOrError) и флаг closeChan.
type fakeRemote struct {
	mu sync.Mutex
	// handler — функция, принимающая отправляемое сообщение и возвращающая канал ответа.
	handler func(ctx context.Context, msg jsonrpc.Message) (<-chan MessageOrError, error)
	// listenHandler — функция для GET SSE; n — порядковый номер вызова Listen (с 1).
	listenHandler func(ctx context.Context, n int) (<-chan MessageOrError, error)

	// Tracking.
	sent             []jsonrpc.Message
	resetCount       int
	listenCount      int
	protocolVersions []string
	closed           bool
	// events — журнал в порядке наступления: send:<method>, reset,
	// listen-start/N и события, которые пишут сами handler-ы (logEvent).
	events []string
}

func newFakeRemote() *fakeRemote {
	return &fakeRemote{}
}

func (r *fakeRemote) Send(ctx context.Context, msg jsonrpc.Message) (<-chan MessageOrError, error) {
	r.mu.Lock()
	r.sent = append(r.sent, msg)
	method := msg.Method
	if method == "" {
		method = "response"
	}
	r.events = append(r.events, "send:"+method)
	h := r.handler
	r.mu.Unlock()
	if h == nil {
		ch := make(chan MessageOrError)
		close(ch)
		return ch, nil
	}
	return h(ctx, msg)
}

func (r *fakeRemote) Listen(ctx context.Context) (<-chan MessageOrError, error) {
	r.mu.Lock()
	r.listenCount++
	n := r.listenCount
	r.events = append(r.events, fmt.Sprintf("listen-start/%d", n))
	h := r.listenHandler
	r.mu.Unlock()
	if h == nil {
		// По умолчанию — пустой закрытый канал.
		ch := make(chan MessageOrError)
		close(ch)
		return ch, nil
	}
	return h(ctx, n)
}

func (r *fakeRemote) SetProtocolVersion(v string) {
	r.mu.Lock()
	r.protocolVersions = append(r.protocolVersions, v)
	r.mu.Unlock()
}

func (r *fakeRemote) ResetSession() {
	r.mu.Lock()
	r.resetCount++
	r.events = append(r.events, "reset")
	r.mu.Unlock()
}

func (r *fakeRemote) Close(ctx context.Context) error {
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	return nil
}

func (r *fakeRemote) Sent() []jsonrpc.Message {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]jsonrpc.Message, len(r.sent))
	copy(out, r.sent)
	return out
}

func (r *fakeRemote) ResetCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.resetCount
}

func (r *fakeRemote) ProtocolVersions() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.protocolVersions))
	copy(out, r.protocolVersions)
	return out
}

func (r *fakeRemote) ListenCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.listenCount
}

// logEvent дописывает событие в журнал (для handler-ов теста).
func (r *fakeRemote) logEvent(e string) {
	r.mu.Lock()
	r.events = append(r.events, e)
	r.mu.Unlock()
}

func (r *fakeRemote) Events() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.events))
	copy(out, r.events)
	return out
}

// blockingListen — стрим без сообщений, живущий до отмены ctx; при отмене пишет
// listen-cancel/N и закрывает канал.
func (r *fakeRemote) blockingListen(ctx context.Context, n int) (<-chan MessageOrError, error) {
	ch := make(chan MessageOrError)
	go func() {
		<-ctx.Done()
		r.logEvent(fmt.Sprintf("listen-cancel/%d", n))
		close(ch)
	}()
	return ch, nil
}

// ---------- helpers ----------

func rawID(i int) json.RawMessage {
	return json.RawMessage(strconv.Itoa(i))
}

func makeRequest(id int, method string) jsonrpc.Message {
	return jsonrpc.Message{
		JSONRPC: jsonrpc.Version,
		ID:      rawID(id),
		Method:  method,
		Params:  json.RawMessage(`{}`),
	}
}

func makeNotification(method string) jsonrpc.Message {
	return jsonrpc.Message{
		JSONRPC: jsonrpc.Version,
		Method:  method,
	}
}

func makeResponse(id int, result string) jsonrpc.Message {
	return jsonrpc.Message{
		JSONRPC: jsonrpc.Version,
		ID:      rawID(id),
		Result:  json.RawMessage(result),
	}
}

// runProxy запускает proxy в горутине, возвращает функцию ожидания и итоговую ошибку.
func runProxy(t *testing.T, p *Proxy, ctx context.Context) (waitFn func() error) {
	t.Helper()
	errCh := make(chan error, 1)
	go func() {
		errCh <- p.Run(ctx)
	}()
	return func() error {
		select {
		case e := <-errCh:
			return e
		case <-time.After(5 * time.Second):
			t.Fatal("proxy.Run did not return in time")
			return errors.New("timeout")
		}
	}
}

// ---------- tests ----------

// 1. Round-trip request.
func TestRoundTripRequest(t *testing.T) {
	tr := newFakeTransport()
	rm := newFakeRemote()

	rm.handler = func(ctx context.Context, msg jsonrpc.Message) (<-chan MessageOrError, error) {
		ch := make(chan MessageOrError, 1)
		if msg.IsRequest() {
			ch <- MessageOrError{Msg: makeResponse(idFromRaw(msg.ID), `{"items":[]}`)}
		}
		close(ch)
		return ch, nil
	}

	p := New(tr, rm, logging.Discard())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wait := runProxy(t, p, ctx)

	tr.PushIn(makeRequest(1, "tools/list"))

	got, ok := tr.ExpectOut(2 * time.Second)
	if !ok {
		t.Fatal("expected response on stdout")
	}
	if !got.IsResponse() {
		t.Fatalf("expected response, got %+v", got)
	}
	if idFromRaw(got.ID) != 1 {
		t.Fatalf("expected id=1, got %s", string(got.ID))
	}

	tr.Close()
	if err := wait(); err != nil {
		t.Fatalf("Run returned err: %v", err)
	}
}

// 2. Notification — fire-and-forget remote.Send получает.
func TestNotification(t *testing.T) {
	tr := newFakeTransport()
	rm := newFakeRemote()

	rm.handler = func(ctx context.Context, msg jsonrpc.Message) (<-chan MessageOrError, error) {
		ch := make(chan MessageOrError)
		close(ch)
		return ch, nil
	}

	p := New(tr, rm, logging.Discard())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wait := runProxy(t, p, ctx)

	tr.PushIn(makeNotification("notifications/initialized"))

	// Wait for remote to receive it.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(rm.Sent()) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	sent := rm.Sent()
	if len(sent) != 1 {
		t.Fatalf("expected 1 sent, got %d", len(sent))
	}
	if sent[0].Method != "notifications/initialized" {
		t.Fatalf("unexpected method: %s", sent[0].Method)
	}

	tr.Close()
	if err := wait(); err != nil {
		t.Fatalf("Run returned err: %v", err)
	}
}

// 3. Server-initiated через Listen.
func TestServerInitiatedListen(t *testing.T) {
	tr := newFakeTransport()
	rm := newFakeRemote()

	listenCh := make(chan MessageOrError, 1)
	listenCh <- MessageOrError{Msg: jsonrpc.Message{
		JSONRPC: jsonrpc.Version,
		Method:  "notifications/ping",
	}}

	rm.handler = handshakeHandler(nil)
	rm.listenHandler = func(ctx context.Context, n int) (<-chan MessageOrError, error) {
		return listenCh, nil
	}

	p := New(tr, rm, logging.Discard())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wait := runProxy(t, p, ctx)

	// Listener стартует только после initialize + initialized.
	handshake(t, tr)

	got, ok := tr.ExpectOut(2 * time.Second)
	if !ok {
		t.Fatal("expected listen msg on stdout")
	}
	if got.Method != "notifications/ping" {
		t.Fatalf("expected ping, got %+v", got)
	}

	close(listenCh)
	tr.Close()
	if err := wait(); err != nil {
		t.Fatalf("Run returned err: %v", err)
	}
}

// 5. protocolVersion из initialize response.
func TestProtocolVersionCapture(t *testing.T) {
	tr := newFakeTransport()
	rm := newFakeRemote()

	rm.handler = func(ctx context.Context, msg jsonrpc.Message) (<-chan MessageOrError, error) {
		ch := make(chan MessageOrError, 1)
		if msg.Method == "initialize" {
			ch <- MessageOrError{Msg: jsonrpc.Message{
				JSONRPC: jsonrpc.Version,
				ID:      msg.ID,
				Result:  json.RawMessage(`{"protocolVersion":"2025-03-26","serverInfo":{}}`),
			}}
		}
		close(ch)
		return ch, nil
	}

	p := New(tr, rm, logging.Discard())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wait := runProxy(t, p, ctx)

	tr.PushIn(makeRequest(1, "initialize"))

	_, ok := tr.ExpectOut(2 * time.Second)
	if !ok {
		t.Fatal("expected response")
	}

	// Wait a tad for SetProtocolVersion bookkeeping.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if len(rm.ProtocolVersions()) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	versions := rm.ProtocolVersions()
	if len(versions) == 0 || versions[0] != "2025-03-26" {
		t.Fatalf("expected protocolVersion captured, got %v", versions)
	}

	tr.Close()
	if err := wait(); err != nil {
		t.Fatalf("Run returned err: %v", err)
	}
}

// 6. Initialize + initialized notif сохраняются в Proxy.
func TestInitializeStateCaptured(t *testing.T) {
	tr := newFakeTransport()
	rm := newFakeRemote()

	rm.handler = func(ctx context.Context, msg jsonrpc.Message) (<-chan MessageOrError, error) {
		ch := make(chan MessageOrError, 1)
		if msg.Method == "initialize" {
			ch <- MessageOrError{Msg: jsonrpc.Message{
				JSONRPC: jsonrpc.Version,
				ID:      msg.ID,
				Result:  json.RawMessage(`{"protocolVersion":"2025-03-26"}`),
			}}
		}
		close(ch)
		return ch, nil
	}

	p := New(tr, rm, logging.Discard())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wait := runProxy(t, p, ctx)

	tr.PushIn(makeRequest(1, "initialize"))
	_, ok := tr.ExpectOut(2 * time.Second)
	if !ok {
		t.Fatal("expected init response")
	}
	tr.PushIn(makeNotification("notifications/initialized"))

	// Дожидаемся пока remote получит notification.
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		hasNotif := false
		for _, m := range rm.Sent() {
			if m.Method == "notifications/initialized" {
				hasNotif = true
				break
			}
		}
		if hasNotif {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Внутреннее состояние.
	p.mu.Lock()
	gotInit := p.firstInitialize
	gotNotif := p.initializedNotif
	p.mu.Unlock()

	if gotInit == nil {
		t.Fatal("firstInitialize not captured")
	}
	if gotInit.Method != "initialize" {
		t.Fatalf("unexpected init method: %s", gotInit.Method)
	}
	if gotNotif == nil {
		t.Fatal("initializedNotif not captured")
	}
	if gotNotif.Method != "notifications/initialized" {
		t.Fatalf("unexpected notif method: %s", gotNotif.Method)
	}

	tr.Close()
	if err := wait(); err != nil {
		t.Fatalf("Run returned err: %v", err)
	}
}

// 7. Recovery happy path.
func TestRecoveryHappyPath(t *testing.T) {
	tr := newFakeTransport()
	rm := newFakeRemote()

	var sessionLostFired atomic.Bool

	rm.handler = func(ctx context.Context, msg jsonrpc.Message) (<-chan MessageOrError, error) {
		ch := make(chan MessageOrError, 2)
		switch msg.Method {
		case "initialize":
			ch <- MessageOrError{Msg: jsonrpc.Message{
				JSONRPC: jsonrpc.Version,
				ID:      msg.ID,
				Result:  json.RawMessage(`{"protocolVersion":"2025-03-26"}`),
			}}
		case "notifications/initialized":
			// noop close
		case "tools/list":
			// Первый вызов — session lost. Последующие — успех.
			if !sessionLostFired.Load() {
				sessionLostFired.Store(true)
				ch <- MessageOrError{Err: ErrSessionLost}
			} else {
				ch <- MessageOrError{Msg: makeResponse(idFromRaw(msg.ID), `{"items":["recovered"]}`)}
			}
		}
		close(ch)
		return ch, nil
	}

	p := New(tr, rm, logging.Discard())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wait := runProxy(t, p, ctx)

	// Step 1-3: initialize + notif + first tools/list.
	tr.PushIn(makeRequest(1, "initialize"))
	if _, ok := tr.ExpectOut(2 * time.Second); !ok {
		t.Fatal("init response missing")
	}
	tr.PushIn(makeNotification("notifications/initialized"))

	// дать notif прокинуться
	time.Sleep(50 * time.Millisecond)

	tr.PushIn(makeRequest(2, "tools/list"))

	// Ожидаем что после recovery клиент получит успешный response с id=2.
	got, ok := tr.ExpectOut(3 * time.Second)
	if !ok {
		t.Fatal("expected post-recovery tools/list response")
	}
	if idFromRaw(got.ID) != 2 {
		t.Fatalf("expected id=2, got %s", string(got.ID))
	}
	if got.Error != nil {
		t.Fatalf("expected success, got error: %v", got.Error)
	}

	if rm.ResetCount() < 1 {
		t.Fatal("expected ResetSession to be called at least once")
	}

	tr.Close()
	if err := wait(); err != nil {
		t.Fatalf("Run returned err: %v", err)
	}
}

// 8. Recovery fail.
func TestRecoveryFail(t *testing.T) {
	tr := newFakeTransport()
	rm := newFakeRemote()

	var (
		initCount   atomic.Int32
		initialDone atomic.Bool
	)

	rm.handler = func(ctx context.Context, msg jsonrpc.Message) (<-chan MessageOrError, error) {
		ch := make(chan MessageOrError, 2)
		switch msg.Method {
		case "initialize":
			c := initCount.Add(1)
			if c == 1 {
				// Первый initialize (от клиента) — ок.
				ch <- MessageOrError{Msg: jsonrpc.Message{
					JSONRPC: jsonrpc.Version,
					ID:      msg.ID,
					Result:  json.RawMessage(`{"protocolVersion":"2025-03-26"}`),
				}}
				initialDone.Store(true)
			} else {
				// Replay initialize — снова session lost.
				ch <- MessageOrError{Err: ErrSessionLost}
			}
		case "notifications/initialized":
			// noop
		case "tools/list":
			ch <- MessageOrError{Err: ErrSessionLost}
		}
		close(ch)
		return ch, nil
	}

	p := New(tr, rm, logging.Discard())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wait := runProxy(t, p, ctx)

	tr.PushIn(makeRequest(1, "initialize"))
	if _, ok := tr.ExpectOut(2 * time.Second); !ok {
		t.Fatal("init response missing")
	}
	tr.PushIn(makeNotification("notifications/initialized"))
	time.Sleep(50 * time.Millisecond)

	tr.PushIn(makeRequest(2, "tools/list"))

	// Клиент должен получить error response.
	got, ok := tr.ExpectOut(3 * time.Second)
	if !ok {
		t.Fatal("expected error response after recovery fail")
	}
	if got.Error == nil {
		t.Fatalf("expected error, got %+v", got)
	}
	if got.Error.Code != -32000 {
		t.Fatalf("expected code -32000, got %d", got.Error.Code)
	}
	if idFromRaw(got.ID) != 2 {
		t.Fatalf("expected error id=2, got %s", string(got.ID))
	}

	// Run должен вернуть не-nil.
	err := wait()
	if err == nil {
		t.Fatal("expected Run error on recovery fail")
	}
}

// 9. ErrSessionLost не появляется в stdout.
func TestSessionLostNotLeaked(t *testing.T) {
	tr := newFakeTransport()
	rm := newFakeRemote()

	rm.handler = func(ctx context.Context, msg jsonrpc.Message) (<-chan MessageOrError, error) {
		ch := make(chan MessageOrError, 2)
		switch msg.Method {
		case "initialize":
			ch <- MessageOrError{Msg: jsonrpc.Message{
				JSONRPC: jsonrpc.Version,
				ID:      msg.ID,
				Result:  json.RawMessage(`{"protocolVersion":"2025-03-26"}`),
			}}
		case "tools/list":
			// session lost — НЕ должно появиться в stdout
			ch <- MessageOrError{Err: ErrSessionLost}
		default:
			// noop
		}
		close(ch)
		return ch, nil
	}

	p := New(tr, rm, logging.Discard())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wait := runProxy(t, p, ctx)

	tr.PushIn(makeRequest(1, "initialize"))
	if _, ok := tr.ExpectOut(2 * time.Second); !ok {
		t.Fatal("init response missing")
	}
	tr.PushIn(makeNotification("notifications/initialized"))
	time.Sleep(50 * time.Millisecond)
	tr.PushIn(makeRequest(2, "tools/list"))

	// Дать recovery попытаться и вернуть error response (поскольку replay тоже лопнет).
	// Идея теста: ни одно сообщение, отправленное в stdout, не должно содержать пустого Msg.
	// Recovery всё равно упадёт (replay-initialize ничего не отвечает), и клиенту прилетит error response.
	got, ok := tr.ExpectOut(3 * time.Second)
	if !ok {
		t.Fatal("expected some response")
	}
	// Сообщение должно быть валидным jsonrpc.
	if got.JSONRPC != jsonrpc.Version {
		t.Fatalf("invalid msg on stdout (raw zero-Message?): %+v", got)
	}
	// И это не должно быть "raw" session-lost — это будет error response.
	if got.Error == nil {
		// Это может быть успешный replay — тоже нормально.
		if got.Result == nil {
			t.Fatalf("unexpected msg on stdout: %+v", got)
		}
	}

	tr.Close()
	_ = wait() // не важна ошибка
}

// 10. Concurrent: 50 параллельных request — все ответы доходят.
func TestConcurrentRequests(t *testing.T) {
	tr := newFakeTransport()
	rm := newFakeRemote()

	rm.handler = func(ctx context.Context, msg jsonrpc.Message) (<-chan MessageOrError, error) {
		ch := make(chan MessageOrError, 1)
		if msg.IsRequest() {
			ch <- MessageOrError{Msg: makeResponse(idFromRaw(msg.ID), `{}`)}
		}
		close(ch)
		return ch, nil
	}

	p := New(tr, rm, logging.Discard())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wait := runProxy(t, p, ctx)

	const N = 50
	go func() {
		for i := 1; i <= N; i++ {
			tr.PushIn(makeRequest(i, "tools/list"))
		}
	}()

	seen := make(map[int]bool)
	deadline := time.Now().Add(5 * time.Second)
	for len(seen) < N && time.Now().Before(deadline) {
		got, ok := tr.ExpectOut(2 * time.Second)
		if !ok {
			break
		}
		seen[idFromRaw(got.ID)] = true
	}
	if len(seen) != N {
		t.Fatalf("expected %d responses, got %d", N, len(seen))
	}

	tr.Close()
	if err := wait(); err != nil {
		t.Fatalf("Run returned err: %v", err)
	}
}

// 11. Shutdown by stdin EOF.
func TestShutdownByEOF(t *testing.T) {
	tr := newFakeTransport()
	rm := newFakeRemote()

	p := New(tr, rm, logging.Discard())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wait := runProxy(t, p, ctx)

	tr.Close()
	if err := wait(); err != nil {
		t.Fatalf("expected nil on EOF shutdown, got %v", err)
	}
}

// 12. Shutdown by ctx.
func TestShutdownByCtx(t *testing.T) {
	tr := newFakeTransport()
	rm := newFakeRemote()

	p := New(tr, rm, logging.Discard())
	ctx, cancel := context.WithCancel(context.Background())
	wait := runProxy(t, p, ctx)

	cancel()

	if err := wait(); err != nil {
		t.Fatalf("expected nil on ctx cancel, got %v", err)
	}
}

// 4. (skipped — batch not supported by Transport contract.)

// idFromRaw парсит "1" → 1.
func idFromRaw(r json.RawMessage) int {
	n, _ := strconv.Atoi(string(r))
	return n
}

// TestClientResponseForwarded — клиент отвечает на server-initiated request.
func TestClientResponseForwarded(t *testing.T) {
	tr := newFakeTransport()
	rm := newFakeRemote()

	received := make(chan jsonrpc.Message, 1)

	rm.handler = func(ctx context.Context, msg jsonrpc.Message) (<-chan MessageOrError, error) {
		ch := make(chan MessageOrError)
		close(ch)
		if msg.IsResponse() {
			received <- msg
		}
		return ch, nil
	}

	p := New(tr, rm, logging.Discard())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wait := runProxy(t, p, ctx)

	// Push response (имеется id, нет method, есть result).
	tr.PushIn(jsonrpc.Message{
		JSONRPC: jsonrpc.Version,
		ID:      rawID(42),
		Result:  json.RawMessage(`{"ok":true}`),
	})

	select {
	case got := <-received:
		if idFromRaw(got.ID) != 42 {
			t.Fatalf("expected id=42, got %s", string(got.ID))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("client response not forwarded to remote")
	}

	tr.Close()
	if err := wait(); err != nil {
		t.Fatalf("Run returned err: %v", err)
	}
}

// ---------- listener / recovery: хелперы ----------

type remoteHandler = func(ctx context.Context, msg jsonrpc.Message) (<-chan MessageOrError, error)

// chanOf — закрытый канал с заданными элементами.
func chanOf(items ...MessageOrError) <-chan MessageOrError {
	ch := make(chan MessageOrError, len(items))
	for _, it := range items {
		ch <- it
	}
	close(ch)
	return ch
}

func initResponse(id json.RawMessage) jsonrpc.Message {
	return jsonrpc.Message{
		JSONRPC: jsonrpc.Version,
		ID:      id,
		Result:  json.RawMessage(`{"protocolVersion":"2025-03-26"}`),
	}
}

// handshakeHandler: initialize → response, notification → закрытый канал (202),
// прочие запросы — extra (nil → успешный response).
func handshakeHandler(extra remoteHandler) remoteHandler {
	return func(ctx context.Context, msg jsonrpc.Message) (<-chan MessageOrError, error) {
		switch {
		case msg.Method == methodInitialize:
			return chanOf(MessageOrError{Msg: initResponse(msg.ID)}), nil
		case msg.IsNotification():
			return chanOf(), nil
		case extra != nil:
			return extra(ctx, msg)
		}
		return chanOf(MessageOrError{Msg: makeResponse(idFromRaw(msg.ID), `{}`)}), nil
	}
}

// handshake — initialize (id=1) с ожиданием ответа + notifications/initialized.
func handshake(t *testing.T, tr *fakeTransport) {
	t.Helper()
	tr.PushIn(makeRequest(1, methodInitialize))
	got, ok := tr.ExpectOut(2 * time.Second)
	if !ok || idFromRaw(got.ID) != 1 {
		t.Fatalf("initialize response missing: %+v", got)
	}
	tr.PushIn(makeNotification(methodNotifInitialized))
}

// expectSuccess ждёт успешный response с заданным id.
func expectSuccess(t *testing.T, tr *fakeTransport, id int) {
	t.Helper()
	got, ok := tr.ExpectOut(3 * time.Second)
	if !ok {
		t.Fatalf("response id=%d missing", id)
	}
	if idFromRaw(got.ID) != id || got.Error != nil {
		t.Fatalf("expected success id=%d, got %+v (err=%v)", id, got, got.Error)
	}
}

// waitFor поллит cond до 3 с.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func indexOf(events []string, e string) int {
	for i, v := range events {
		if v == e {
			return i
		}
	}
	return -1
}

func lastIndexOf(events []string, e string) int {
	for i := len(events) - 1; i >= 0; i-- {
		if events[i] == e {
			return i
		}
	}
	return -1
}

// ---------- listener / recovery: тесты ----------

// До initialized Listen не вызывается, после — ровно один раз.
func TestListenerStartsAfterInitialized(t *testing.T) {
	tr := newFakeTransport()
	rm := newFakeRemote()
	rm.handler = handshakeHandler(nil)
	rm.listenHandler = rm.blockingListen

	p := New(tr, rm, logging.Discard())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wait := runProxy(t, p, ctx)

	tr.PushIn(makeRequest(1, methodInitialize))
	expectSuccess(t, tr, 1)
	tr.PushIn(makeRequest(2, "tools/list"))
	expectSuccess(t, tr, 2)
	if n := rm.ListenCount(); n != 0 {
		t.Fatalf("Listen called %d times before initialized, want 0", n)
	}

	tr.PushIn(makeNotification(methodNotifInitialized))
	waitFor(t, "listener start", func() bool { return rm.ListenCount() == 1 })

	tr.PushIn(makeRequest(3, "tools/list"))
	expectSuccess(t, tr, 3)
	if n := rm.ListenCount(); n != 1 {
		t.Fatalf("Listen called %d times, want 1", n)
	}

	tr.Close()
	if err := wait(); err != nil {
		t.Fatalf("Run returned err: %v", err)
	}
	if indexOf(rm.Events(), "listen-cancel/1") < 0 {
		t.Fatalf("listener not cancelled on shutdown: %v", rm.Events())
	}
}

// Исходный initialized получил ErrSessionLost → listener стартует ровно один раз,
// после replay initialized.
func TestListenerStartsAfterInitializedReplay(t *testing.T) {
	tr := newFakeTransport()
	rm := newFakeRemote()
	var notifN atomic.Int32
	rm.handler = func(ctx context.Context, msg jsonrpc.Message) (<-chan MessageOrError, error) {
		if msg.Method == methodNotifInitialized && notifN.Add(1) == 1 {
			return chanOf(MessageOrError{Err: ErrSessionLost}), nil
		}
		return handshakeHandler(nil)(ctx, msg)
	}
	rm.listenHandler = rm.blockingListen

	p := New(tr, rm, logging.Discard())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wait := runProxy(t, p, ctx)

	handshake(t, tr)
	waitFor(t, "listener start after replay", func() bool { return rm.ListenCount() == 1 })
	if n := rm.ResetCount(); n != 1 {
		t.Fatalf("ResetCount=%d, want 1", n)
	}

	tr.PushIn(makeRequest(2, "tools/list"))
	expectSuccess(t, tr, 2)

	tr.Close()
	if err := wait(); err != nil {
		t.Fatalf("Run returned err: %v", err)
	}
	ev := rm.Events()
	if n := rm.ListenCount(); n != 1 {
		t.Fatalf("Listen called %d times, want 1: %v", n, ev)
	}
	if indexOf(ev, "listen-start/1") < lastIndexOf(ev, "send:"+methodNotifInitialized) {
		t.Fatalf("listener started before replayed initialized: %v", ev)
	}
}

// Recovery останавливает listener до ResetSession и перезапускает после replay.
func TestRecoveryStopsAndRestartsListener(t *testing.T) {
	tr := newFakeTransport()
	rm := newFakeRemote()
	var initN, listN atomic.Int32
	replayArrived := make(chan struct{})
	releaseReplay := make(chan struct{})
	rm.handler = func(ctx context.Context, msg jsonrpc.Message) (<-chan MessageOrError, error) {
		switch msg.Method {
		case methodInitialize:
			k := initN.Add(1)
			ch := make(chan MessageOrError, 1)
			go func() {
				defer close(ch)
				if k == 2 {
					close(replayArrived)
					select {
					case <-releaseReplay:
					case <-ctx.Done():
						return
					}
				}
				rm.logEvent(fmt.Sprintf("respond:initialize/%d", k))
				ch <- MessageOrError{Msg: initResponse(msg.ID)}
			}()
			return ch, nil
		case "tools/list":
			if listN.Add(1) == 1 {
				return chanOf(MessageOrError{Err: ErrSessionLost}), nil
			}
		}
		return handshakeHandler(nil)(ctx, msg)
	}
	rm.listenHandler = rm.blockingListen

	p := New(tr, rm, logging.Discard())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wait := runProxy(t, p, ctx)

	handshake(t, tr)
	waitFor(t, "first listener", func() bool { return rm.ListenCount() == 1 })

	tr.PushIn(makeRequest(2, "tools/list"))
	select {
	case <-replayArrived:
	case <-time.After(3 * time.Second):
		t.Fatal("replay initialize not sent")
	}
	ev := rm.Events()
	if c, r := indexOf(ev, "listen-cancel/1"), indexOf(ev, "reset"); c < 0 || r < 0 || c > r {
		t.Fatalf("listener must be cancelled before reset: %v", ev)
	}
	if indexOf(ev, "listen-start/2") >= 0 {
		t.Fatalf("listener restarted during recovery: %v", ev)
	}

	close(releaseReplay)
	expectSuccess(t, tr, 2)
	waitFor(t, "listener restart", func() bool { return rm.ListenCount() == 2 })

	ev = rm.Events()
	start2 := indexOf(ev, "listen-start/2")
	if start2 < indexOf(ev, "respond:initialize/2") || start2 < lastIndexOf(ev, "send:"+methodNotifInitialized) {
		t.Fatalf("listener restarted before replay finished: %v", ev)
	}

	tr.Close()
	if err := wait(); err != nil {
		t.Fatalf("Run returned err: %v", err)
	}
	if n := rm.ListenCount(); n != 2 {
		t.Fatalf("Listen called %d times, want 2: %v", n, rm.Events())
	}
}

// 404 на listener-е → ровно один recovery и один перезапуск listener-а.
func TestListenerSessionLostOneRecovery(t *testing.T) {
	tr := newFakeTransport()
	rm := newFakeRemote()
	rm.handler = handshakeHandler(nil)
	rm.listenHandler = func(ctx context.Context, n int) (<-chan MessageOrError, error) {
		if n == 1 {
			return chanOf(MessageOrError{Err: ErrSessionLost}), nil
		}
		return rm.blockingListen(ctx, n)
	}

	p := New(tr, rm, logging.Discard())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wait := runProxy(t, p, ctx)

	handshake(t, tr)
	waitFor(t, "listener restart", func() bool { return rm.ListenCount() == 2 })
	tr.PushIn(makeRequest(2, "tools/list"))
	expectSuccess(t, tr, 2)

	tr.Close()
	if err := wait(); err != nil {
		t.Fatalf("Run returned err: %v", err)
	}
	if n := rm.ResetCount(); n != 1 {
		t.Fatalf("ResetCount=%d, want 1", n)
	}
	if n := rm.ListenCount(); n != 2 {
		t.Fatalf("ListenCount=%d, want 2", n)
	}
}

// Повторные сигналы до начала прохода схлопываются в один.
func TestTriggerRecoveryCoalesces(t *testing.T) {
	p := New(newFakeTransport(), newFakeRemote(), logging.Discard())
	for i := 0; i < 3; i++ {
		p.triggerRecovery()
	}
	if n := len(p.recoveryTrigger); n != 1 {
		t.Fatalf("signals in channel=%d, want 1", n)
	}
	p.mu.Lock()
	pending := p.recoveryPending
	p.mu.Unlock()
	if !pending {
		t.Fatal("recoveryPending=false, want true")
	}
}

// Запрос listener-а при простое: возвращается (без самоблокировки на mu) и
// ставит ровно один сигнал.
func TestListenerRequestEnqueuesOnce(t *testing.T) {
	p := New(newFakeTransport(), newFakeRemote(), logging.Discard())
	done := make(chan struct{})
	go func() {
		p.requestRecoveryFromListener()
		p.requestRecoveryFromListener()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("requestRecoveryFromListener deadlocked")
	}
	if n := len(p.recoveryTrigger); n != 1 {
		t.Fatalf("signals in channel=%d, want 1", n)
	}
}

// Сигнал вычитан, но проход ещё не начался (pending=true), либо проход идёт —
// запрос listener-а сигнал не добавляет.
func TestListenerRequestSkippedInDequeueGap(t *testing.T) {
	p := New(newFakeTransport(), newFakeRemote(), logging.Discard())

	p.triggerRecovery()
	<-p.recoveryTrigger // имитация runRecovery до захвата mu: pending ещё true
	p.requestRecoveryFromListener()
	if n := len(p.recoveryTrigger); n != 0 {
		t.Fatalf("dequeue gap: signals=%d, want 0", n)
	}

	p.mu.Lock()
	p.recoveryPending = false
	p.recoveryRunning = true
	p.mu.Unlock()
	p.requestRecoveryFromListener()
	if n := len(p.recoveryTrigger); n != 0 {
		t.Fatalf("running: signals=%d, want 0", n)
	}
}

// POST получает 404 после снимка идущего recovery → второй проход реплеит его.
func TestPostSignalAfterSnapshotRunsSecondPass(t *testing.T) {
	tr := newFakeTransport()
	rm := newFakeRemote()
	var initN, calls2, calls3 atomic.Int32
	replayArrived := make(chan struct{})
	releaseReplay := make(chan struct{})
	req3Arrived := make(chan struct{})
	release3 := make(chan struct{})
	rm.handler = func(ctx context.Context, msg jsonrpc.Message) (<-chan MessageOrError, error) {
		switch msg.Method {
		case methodInitialize:
			k := initN.Add(1)
			ch := make(chan MessageOrError, 1)
			go func() {
				defer close(ch)
				if k == 2 {
					close(replayArrived)
					select {
					case <-releaseReplay:
					case <-ctx.Done():
						return
					}
				}
				ch <- MessageOrError{Msg: initResponse(msg.ID)}
			}()
			return ch, nil
		case "tools/list":
			switch idFromRaw(msg.ID) {
			case 2:
				if calls2.Add(1) == 1 {
					return chanOf(MessageOrError{Err: ErrSessionLost}), nil
				}
			case 3:
				if calls3.Add(1) == 1 {
					ch := make(chan MessageOrError, 1)
					go func() {
						defer close(ch)
						close(req3Arrived)
						<-release3
						ch <- MessageOrError{Err: ErrSessionLost}
					}()
					return ch, nil
				}
			}
		}
		return handshakeHandler(nil)(ctx, msg)
	}

	p := New(tr, rm, logging.Discard())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wait := runProxy(t, p, ctx)

	handshake(t, tr)

	// id=3 в полёте до начала recovery.
	tr.PushIn(makeRequest(3, "tools/list"))
	<-req3Arrived
	// id=2 запускает первый проход; снимок берётся до replay initialize.
	tr.PushIn(makeRequest(2, "tools/list"))
	select {
	case <-replayArrived:
	case <-time.After(3 * time.Second):
		t.Fatal("replay initialize not sent")
	}
	// id=3 теряет сессию уже после снимка.
	close(release3)
	waitFor(t, "id=3 queued for second pass", func() bool {
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.recoveryPending && len(p.pendingReplay) == 1
	})
	close(releaseReplay)

	seen := map[int]bool{}
	for i := 0; i < 2; i++ {
		got, ok := tr.ExpectOut(3 * time.Second)
		if !ok {
			t.Fatalf("missing responses, got %v", seen)
		}
		if got.Error != nil {
			t.Fatalf("unexpected error response: %+v", got.Error)
		}
		seen[idFromRaw(got.ID)] = true
	}
	if !seen[2] || !seen[3] {
		t.Fatalf("expected responses for 2 and 3, got %v", seen)
	}
	if n := rm.ResetCount(); n != 2 {
		t.Fatalf("ResetCount=%d, want 2 (second pass)", n)
	}

	tr.Close()
	if err := wait(); err != nil {
		t.Fatalf("Run returned err: %v", err)
	}
}

// Recovery ждёт закрытия канала Listen (HTTP-продюсер завершён) до ResetSession.
// post404 — listener останавливает recovery (stopListener, join через основной
// цикл чтения); listener404 — listener сам получил session-lost и вышел раньше
// закрытия канала (join через дренаж в defer runListener).
func TestStopListenerJoinsProducer(t *testing.T) {
	for _, tc := range []struct {
		name        string
		listenerErr bool
	}{
		{name: "post404"},
		{name: "listener404", listenerErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := newFakeTransport()
			rm := newFakeRemote()
			var listN atomic.Int32
			rm.handler = handshakeHandler(func(ctx context.Context, msg jsonrpc.Message) (<-chan MessageOrError, error) {
				if !tc.listenerErr && listN.Add(1) == 1 {
					return chanOf(MessageOrError{Err: ErrSessionLost}), nil
				}
				return chanOf(MessageOrError{Msg: makeResponse(idFromRaw(msg.ID), `{}`)}), nil
			})
			producerCancelled := make(chan struct{})
			release := make(chan struct{})
			rm.listenHandler = func(ctx context.Context, n int) (<-chan MessageOrError, error) {
				if n > 1 {
					return rm.blockingListen(ctx, n)
				}
				ch := make(chan MessageOrError, 1)
				if tc.listenerErr {
					ch <- MessageOrError{Err: ErrSessionLost}
				}
				go func() {
					// Продюсер закрывает канал не сразу после отмены ctx.
					<-ctx.Done()
					close(producerCancelled)
					<-release
					rm.logEvent("producer-done")
					close(ch)
				}()
				return ch, nil
			}

			p := New(tr, rm, logging.Discard())
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			wait := runProxy(t, p, ctx)

			handshake(t, tr)
			waitFor(t, "listener start", func() bool { return rm.ListenCount() >= 1 })
			if !tc.listenerErr {
				tr.PushIn(makeRequest(2, "tools/list"))
			}

			select {
			case <-producerCancelled:
			case <-time.After(3 * time.Second):
				t.Fatal("listener producer not cancelled by recovery")
			}
			// Продюсер ещё не закрыл канал → recovery обязан ждать.
			if n := rm.ResetCount(); n != 0 {
				t.Fatalf("ResetSession called before producer finished (ResetCount=%d)", n)
			}
			close(release)
			if tc.listenerErr {
				waitFor(t, "listener restart", func() bool { return rm.ListenCount() == 2 })
			} else {
				expectSuccess(t, tr, 2)
			}

			ev := rm.Events()
			if d, r := indexOf(ev, "producer-done"), indexOf(ev, "reset"); d < 0 || r < 0 || d > r {
				t.Fatalf("producer must finish before reset: %v", ev)
			}

			tr.Close()
			if err := wait(); err != nil {
				t.Fatalf("Run returned err: %v", err)
			}
		})
	}
}

// После возврата replayInitialize его SSE-продюсер получает отмену ctx.
func TestReplayInitializeCancelsProducer(t *testing.T) {
	rm := newFakeRemote()
	producerDone := make(chan struct{})
	rm.handler = func(ctx context.Context, msg jsonrpc.Message) (<-chan MessageOrError, error) {
		ch := make(chan MessageOrError, 1)
		go func() {
			defer close(ch)
			ch <- MessageOrError{Msg: initResponse(msg.ID)}
			// Стрим держится открытым до отмены ctx.
			<-ctx.Done()
			close(producerDone)
		}()
		return ch, nil
	}
	p := New(newFakeTransport(), rm, logging.Discard())

	if err := p.replayInitialize(context.Background(), makeRequest(1, methodInitialize)); err != nil {
		t.Fatalf("replayInitialize: %v", err)
	}
	select {
	case <-producerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("replay initialize producer still running after return")
	}
}

// Нетерминальная ошибка в стриме (битое SSE-событие) не останавливает listener.
func TestListenerKeepsReadingAfterDecodeError(t *testing.T) {
	tr := newFakeTransport()
	rm := newFakeRemote()
	rm.handler = handshakeHandler(nil)
	rm.listenHandler = func(ctx context.Context, n int) (<-chan MessageOrError, error) {
		ch := make(chan MessageOrError, 2)
		ch <- MessageOrError{Err: errors.New("decode: invalid character")}
		ch <- MessageOrError{Msg: makeNotification("notifications/ping")}
		go func() {
			<-ctx.Done()
			close(ch)
		}()
		return ch, nil
	}

	p := New(tr, rm, logging.Discard())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wait := runProxy(t, p, ctx)

	handshake(t, tr)
	got, ok := tr.ExpectOut(2 * time.Second)
	if !ok || got.Method != "notifications/ping" {
		t.Fatalf("expected ping after decode error, got %+v (ok=%v)", got, ok)
	}

	tr.Close()
	if err := wait(); err != nil {
		t.Fatalf("Run returned err: %v", err)
	}
}

// Сбой recovery при активном listener-е → Run возвращает ошибку, не зависает.
func TestRunExitsWhenRecoveryFailsWithListener(t *testing.T) {
	tr := newFakeTransport()
	rm := newFakeRemote()
	var initN atomic.Int32
	rm.handler = func(ctx context.Context, msg jsonrpc.Message) (<-chan MessageOrError, error) {
		switch msg.Method {
		case methodInitialize:
			if initN.Add(1) > 1 {
				return chanOf(MessageOrError{Err: errors.New("boom")}), nil
			}
		case "tools/list":
			return chanOf(MessageOrError{Err: ErrSessionLost}), nil
		}
		return handshakeHandler(nil)(ctx, msg)
	}
	rm.listenHandler = rm.blockingListen

	p := New(tr, rm, logging.Discard())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wait := runProxy(t, p, ctx)

	handshake(t, tr)
	waitFor(t, "listener start", func() bool { return rm.ListenCount() == 1 })

	tr.PushIn(makeRequest(2, "tools/list"))
	got, ok := tr.ExpectOut(3 * time.Second)
	if !ok || got.Error == nil || idFromRaw(got.ID) != 2 {
		t.Fatalf("expected error response for id=2, got %+v", got)
	}
	if err := wait(); err == nil {
		t.Fatal("expected Run error on recovery fail")
	}
	if indexOf(rm.Events(), "listen-cancel/1") < 0 {
		t.Fatalf("listener not cancelled: %v", rm.Events())
	}
}

// Отмена ctx при активном listener-е → Run возвращается.
func TestRunExitsOnCancelWithListener(t *testing.T) {
	tr := newFakeTransport()
	rm := newFakeRemote()
	rm.handler = handshakeHandler(nil)
	rm.listenHandler = rm.blockingListen

	p := New(tr, rm, logging.Discard())
	ctx, cancel := context.WithCancel(context.Background())
	wait := runProxy(t, p, ctx)

	handshake(t, tr)
	waitFor(t, "listener start", func() bool { return rm.ListenCount() == 1 })

	cancel()
	if err := wait(); err != nil {
		t.Fatalf("expected nil on ctx cancel, got %v", err)
	}
	if indexOf(rm.Events(), "listen-cancel/1") < 0 {
		t.Fatalf("listener not cancelled: %v", rm.Events())
	}
}

// Session-lost реже окна счётчика не копятся до лимита.
func TestRecoveryAttemptsWindow(t *testing.T) {
	tr := newFakeTransport()
	rm := newFakeRemote()
	rm.handler = handshakeHandler(nil)
	const losses = 5
	rm.listenHandler = func(ctx context.Context, n int) (<-chan MessageOrError, error) {
		if n > losses {
			return rm.blockingListen(ctx, n)
		}
		ch := make(chan MessageOrError, 1)
		go func() {
			defer close(ch)
			select {
			case <-time.After(40 * time.Millisecond): // > recoveryWindow
				ch <- MessageOrError{Err: ErrSessionLost}
			case <-ctx.Done():
			}
		}()
		return ch, nil
	}

	p := New(tr, rm, logging.Discard())
	p.recoveryWindow = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wait := runProxy(t, p, ctx)

	handshake(t, tr)
	waitFor(t, "all recoveries", func() bool { return rm.ListenCount() == losses+1 })
	select {
	case <-p.recoveryFail:
		t.Fatal("recovery failed: attempts must reset after window")
	default:
	}
	if n := rm.ResetCount(); n != losses {
		t.Fatalf("ResetCount=%d, want %d", n, losses)
	}

	tr.Close()
	if err := wait(); err != nil {
		t.Fatalf("Run returned err: %v", err)
	}
}

// 404 на каждый GET без пауз → выход по лимиту попыток.
func TestRecoveryAttemptsExceeded(t *testing.T) {
	tr := newFakeTransport()
	rm := newFakeRemote()
	rm.handler = handshakeHandler(nil)
	rm.listenHandler = func(ctx context.Context, n int) (<-chan MessageOrError, error) {
		return chanOf(MessageOrError{Err: ErrSessionLost}), nil
	}

	p := New(tr, rm, logging.Discard())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wait := runProxy(t, p, ctx)

	handshake(t, tr)
	err := wait()
	if err == nil {
		t.Fatal("expected Run error after exceeding recovery attempts")
	}
	if !strings.Contains(err.Error(), "exceeded") {
		t.Fatalf("unexpected err: %v", err)
	}
	if n := rm.ResetCount(); n != maxRecoveryAttempts {
		t.Fatalf("ResetCount=%d, want %d", n, maxRecoveryAttempts)
	}
}
