package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"
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
	// listenHandler — функция для GET SSE.
	listenHandler func(ctx context.Context) (<-chan MessageOrError, error)

	// Tracking.
	sent             []jsonrpc.Message
	resetCount       int
	protocolVersions []string
	closed           bool
}

func newFakeRemote() *fakeRemote {
	return &fakeRemote{}
}

func (r *fakeRemote) Send(ctx context.Context, msg jsonrpc.Message) (<-chan MessageOrError, error) {
	r.mu.Lock()
	r.sent = append(r.sent, msg)
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
	h := r.listenHandler
	r.mu.Unlock()
	if h == nil {
		// По умолчанию — пустой закрытый канал.
		ch := make(chan MessageOrError)
		close(ch)
		return ch, nil
	}
	return h(ctx)
}

func (r *fakeRemote) SetProtocolVersion(v string) {
	r.mu.Lock()
	r.protocolVersions = append(r.protocolVersions, v)
	r.mu.Unlock()
}

func (r *fakeRemote) ResetSession() {
	r.mu.Lock()
	r.resetCount++
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

	rm.listenHandler = func(ctx context.Context) (<-chan MessageOrError, error) {
		return listenCh, nil
	}

	p := New(tr, rm, logging.Discard())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wait := runProxy(t, p, ctx)

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
