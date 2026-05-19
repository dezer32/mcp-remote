package stdio

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dezer32/mcp-remote/internal/jsonrpc"
	"github.com/dezer32/mcp-remote/internal/logging"
)

// lockedBuf — потокобезопасный io.Writer для конкурентных Write-тестов.
// Сам bytes.Buffer не safe для concurrent writers, race-detector это ловит.
type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) Bytes() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]byte(nil), l.b.Bytes()...)
}

// makeRequest формирует Message-request с числовым id.
func makeRequest(t *testing.T, id int, method string) jsonrpc.Message {
	t.Helper()
	raw, err := json.Marshal(id)
	if err != nil {
		t.Fatalf("marshal id: %v", err)
	}
	return jsonrpc.Message{
		JSONRPC: jsonrpc.Version,
		ID:      raw,
		Method:  method,
	}
}

func idAsInt(t *testing.T, m jsonrpc.Message) int {
	t.Helper()
	var id int
	if err := json.Unmarshal(m.ID, &id); err != nil {
		t.Fatalf("unmarshal id %q: %v", string(m.ID), err)
	}
	return id
}

// 1. Round-trip: Write один msg в out-buffer → распарсь обратно через jsonrpc.Decode.
func TestTransport_WriteRoundTrip(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	tr := New(strings.NewReader(""), &out, logging.Discard())
	defer tr.Close()

	in := makeRequest(t, 42, "ping")
	in.Params = json.RawMessage(`{"hello":"world"}`)

	if err := tr.Write(context.Background(), in); err != nil {
		t.Fatalf("Write: %v", err)
	}

	data := out.Bytes()
	if len(data) == 0 || data[len(data)-1] != '\n' {
		t.Fatalf("expected trailing newline, got %q", string(data))
	}

	got, err := jsonrpc.Decode(bytes.TrimRight(data, "\n"))
	if err != nil {
		t.Fatalf("Decode round-trip: %v", err)
	}
	if got.JSONRPC != in.JSONRPC {
		t.Errorf("jsonrpc mismatch: got %q want %q", got.JSONRPC, in.JSONRPC)
	}
	if got.Method != in.Method {
		t.Errorf("method mismatch: got %q want %q", got.Method, in.Method)
	}
	if idAsInt(t, got) != 42 {
		t.Errorf("id mismatch: got %d want 42", idAsInt(t, got))
	}
	if string(got.Params) != string(in.Params) {
		t.Errorf("params mismatch: got %s want %s", string(got.Params), string(in.Params))
	}
}

// 2. Read parses one message.
func TestTransport_ReadOneMessage(t *testing.T) {
	t.Parallel()

	pr, pw := io.Pipe()
	tr := New(pr, io.Discard, logging.Discard())
	defer tr.Close()

	go func() {
		defer pw.Close()
		_, _ = pw.Write([]byte(`{"jsonrpc":"2.0","id":7,"method":"hello"}` + "\n"))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	msg, err := tr.Read(ctx)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if msg.Method != "hello" {
		t.Errorf("method: got %q want %q", msg.Method, "hello")
	}
	if idAsInt(t, msg) != 7 {
		t.Errorf("id: got %d want 7", idAsInt(t, msg))
	}
}

// 3. Read returns io.EOF on stream close.
func TestTransport_ReadEOF(t *testing.T) {
	t.Parallel()

	pr, pw := io.Pipe()
	tr := New(pr, io.Discard, logging.Discard())
	defer tr.Close()

	// Закрываем pw сразу, без записи.
	if err := pw.Close(); err != nil {
		t.Fatalf("pw.Close: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := tr.Read(ctx)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("Read: got err=%v, want io.EOF", err)
	}

	// Повторный Read тоже должен возвращать io.EOF (msgCh/errCh закрыты).
	_, err = tr.Read(ctx)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("second Read: got err=%v, want io.EOF", err)
	}
}

// 4. Read returns ctx.Err on cancel.
func TestTransport_ReadContextCanceled(t *testing.T) {
	t.Parallel()

	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })
	tr := New(pr, io.Discard, logging.Discard())
	defer tr.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := tr.Read(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Read: got err=%v, want context.Canceled", err)
	}
}

// 5. Read returns decode error on malformed JSON.
func TestTransport_ReadDecodeError(t *testing.T) {
	t.Parallel()

	pr, pw := io.Pipe()
	tr := New(pr, io.Discard, logging.Discard())
	defer tr.Close()

	go func() {
		defer pw.Close()
		_, _ = pw.Write([]byte("not json\n"))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := tr.Read(ctx)
	if err == nil {
		t.Fatalf("Read: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "jsonrpc decode") {
		t.Errorf("Read: error %q does not contain %q", err.Error(), "jsonrpc decode")
	}
}

// 6. Write atomic batch: 10 горутин пишут по 3 msg, в out строки идут группами по 3
// в правильном порядке IDs.
func TestTransport_WriteAtomicBatch(t *testing.T) {
	t.Parallel()

	out := &lockedBuf{}
	tr := New(strings.NewReader(""), out, logging.Discard())
	defer tr.Close()

	const workers = 10
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		base := i * 10
		go func() {
			defer wg.Done()
			a := makeRequest(t, base+1, "a")
			b := makeRequest(t, base+2, "b")
			c := makeRequest(t, base+3, "c")
			if err := tr.Write(context.Background(), a, b, c); err != nil {
				t.Errorf("Write: %v", err)
			}
		}()
	}
	wg.Wait()

	lines := bytes.Split(bytes.TrimRight(out.Bytes(), "\n"), []byte("\n"))
	if len(lines) != workers*3 {
		t.Fatalf("expected %d lines, got %d", workers*3, len(lines))
	}

	for i := 0; i < workers; i++ {
		group := lines[i*3 : i*3+3]
		ids := make([]int, 3)
		for j, ln := range group {
			m, err := jsonrpc.Decode(ln)
			if err != nil {
				t.Fatalf("Decode line %d: %v (%q)", i*3+j, err, string(ln))
			}
			ids[j] = idAsInt(t, m)
		}
		// id1, id2, id3 одной группы должны быть последовательными (b = a+1, c = a+2).
		if ids[1] != ids[0]+1 || ids[2] != ids[0]+2 {
			t.Errorf("group %d not atomic: ids=%v", i, ids)
		}
	}
}

// 7. Concurrent writes serialized: 100 параллельных одиночных Write; гоняется
// race-detector, никаких race-flags быть не должно. Также сверяем, что все 100
// строк дошли до буфера и каждая декодируется.
func TestTransport_ConcurrentWritesSerialized(t *testing.T) {
	t.Parallel()

	out := &lockedBuf{}
	tr := New(strings.NewReader(""), out, logging.Discard())
	defer tr.Close()

	const n = 100
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		id := i
		go func() {
			defer wg.Done()
			if err := tr.Write(context.Background(), makeRequest(t, id, "x")); err != nil {
				t.Errorf("Write: %v", err)
			}
		}()
	}
	wg.Wait()

	lines := bytes.Split(bytes.TrimRight(out.Bytes(), "\n"), []byte("\n"))
	if len(lines) != n {
		t.Fatalf("expected %d lines, got %d", n, len(lines))
	}
	seen := make(map[int]bool, n)
	for _, ln := range lines {
		m, err := jsonrpc.Decode(ln)
		if err != nil {
			t.Fatalf("Decode: %v line=%q", err, string(ln))
		}
		seen[idAsInt(t, m)] = true
	}
	for i := 0; i < n; i++ {
		if !seen[i] {
			t.Errorf("missing id %d in output", i)
		}
	}
}

// 8. Write returns ctx.Err if ctx already cancelled (до Lock-а).
func TestTransport_WriteCanceledContext(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	tr := New(strings.NewReader(""), &out, logging.Discard())
	defer tr.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := tr.Write(ctx, makeRequest(t, 1, "noop"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Write: got %v, want context.Canceled", err)
	}
	if out.Len() != 0 {
		t.Errorf("nothing should have been written, got %q", out.String())
	}
}

// 9. Close idempotent.
func TestTransport_CloseIdempotent(t *testing.T) {
	t.Parallel()

	tr := New(strings.NewReader(""), io.Discard, logging.Discard())
	if err := tr.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := tr.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

// Дополнительно: Write через bufio.Writer вызывает Flush — проверим, что данные
// действительно попадают в нижележащий буфер, а не остаются в bufio-буфере.
func TestTransport_WriteBufioFlush(t *testing.T) {
	t.Parallel()

	var sink bytes.Buffer
	bw := bufio.NewWriterSize(&sink, 4096)
	tr := New(strings.NewReader(""), bw, logging.Discard())
	defer tr.Close()

	if err := tr.Write(context.Background(), makeRequest(t, 99, "p")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Без Flush bytes.Buffer был бы пуст. С Flush — содержит строку.
	if sink.Len() == 0 {
		t.Fatalf("expected Flush to push bytes to underlying buffer")
	}
	if !bytes.HasSuffix(sink.Bytes(), []byte("\n")) {
		t.Errorf("expected trailing newline, got %q", sink.String())
	}
}

// Дополнительно: пустые строки в input пропускаются.
func TestTransport_ReadSkipsBlankLines(t *testing.T) {
	t.Parallel()

	pr, pw := io.Pipe()
	tr := New(pr, io.Discard, logging.Discard())
	defer tr.Close()

	go func() {
		defer pw.Close()
		_, _ = pw.Write([]byte("\n\n" + `{"jsonrpc":"2.0","id":5,"method":"m"}` + "\n"))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	msg, err := tr.Read(ctx)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if idAsInt(t, msg) != 5 {
		t.Errorf("id: got %d want 5", idAsInt(t, msg))
	}
}

// Дополнительно: Write после Close возвращает ошибку.
func TestTransport_WriteAfterClose(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	tr := New(strings.NewReader(""), &out, logging.Discard())
	if err := tr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	err := tr.Write(context.Background(), makeRequest(t, 1, "x"))
	if err == nil {
		t.Fatalf("Write after Close: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "stdio write") {
		t.Errorf("error should be wrapped with 'stdio write', got: %v", err)
	}
}

// Дополнительно (sanity): убеждаемся, что после получения EOF из закрытого pipe
// фоновая горутина действительно закрыла оба канала. Это нужно, чтобы
// последующие Read возвращали io.EOF, а не блокировались.
func TestTransport_ReadAfterEOFConsistent(t *testing.T) {
	t.Parallel()

	pr, pw := io.Pipe()
	tr := New(pr, io.Discard, logging.Discard())
	defer tr.Close()

	_ = pw.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	for i := 0; i < 3; i++ {
		_, err := tr.Read(ctx)
		if !errors.Is(err, io.EOF) {
			t.Fatalf("Read #%d: got %v, want io.EOF", i, err)
		}
	}
}

// Дополнительно: маленький smoke-тест — большое сообщение (но в пределах 16 MB).
// Не гоняем полные 16 MB чтобы не тратить впустую CPU; берём 1 MB.
func TestTransport_ReadLargeMessage(t *testing.T) {
	t.Parallel()

	const payloadSize = 1 << 20 // 1 MB
	big := strings.Repeat("a", payloadSize)
	line := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"big","params":{"data":%q}}`+"\n", big)

	pr, pw := io.Pipe()
	tr := New(pr, io.Discard, logging.Discard())
	defer tr.Close()

	go func() {
		defer pw.Close()
		_, _ = io.Copy(pw, strings.NewReader(line))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	msg, err := tr.Read(ctx)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if msg.Method != "big" {
		t.Errorf("method: got %q want %q", msg.Method, "big")
	}
}
