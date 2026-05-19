// Package stdio реализует Transport (см. internal/proxy) поверх stdin/stdout.
// JSON-RPC сообщения сериализуются как одна строка на сообщение (newline-delimited).
package stdio

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"

	"github.com/dezer32/mcp-remote/internal/jsonrpc"
)

// maxLineSize — верхняя граница на длину JSON-RPC строки в input-потоке.
// 16 MB — щедро для практических MCP-сообщений и совпадает с буфером npm-версии.
const maxLineSize = 16 * 1024 * 1024

// Transport — newline-delimited JSON-RPC поверх io.Reader/io.Writer.
//
// Read запускает фоновую горутину при первом вызове (через sync.Once);
// горутина читает t.in построчно и кладёт результат в msgCh/errCh. Эта
// горутина блокируется на scanner.Scan() и НЕ отменяется через ctx —
// принимается, что она остаётся висеть до закрытия t.in родительским
// процессом (например, EOF на os.Stdin). Это намеренный compromise:
// MCP-клиенты (Claude Desktop и т.п.) закрывают stdin при выходе.
//
// Write сериализует одну или несколько Message под единым мьютексом и
// пишет их подряд в t.out — гарантирует, что batch попадает в выход
// атомарно относительно других конкурирующих Write-вызовов.
type Transport struct {
	in  io.Reader
	out io.Writer
	log *slog.Logger

	// writeMu сериализует запись в out.
	writeMu sync.Mutex
	// closed — флаг под writeMu; идемпотентный Close.
	closed bool

	// readOnce гарантирует, что фоновая read-горутина запускается единожды.
	readOnce sync.Once
	// msgCh / errCh — каналы, в которые фоновая горутина кладёт результаты.
	// msgCh закрывается фоновой горутиной после первой и единственной ошибки.
	msgCh chan jsonrpc.Message
	errCh chan error
}

// New создаёт Transport. in/out обычно — os.Stdin / os.Stdout.
func New(in io.Reader, out io.Writer, log *slog.Logger) *Transport {
	if log == nil {
		log = slog.Default()
	}
	return &Transport{
		in:    in,
		out:   out,
		log:   log,
		msgCh: make(chan jsonrpc.Message),
		errCh: make(chan error, 1),
	}
}

// Read блокируется до прихода сообщения, EOF или отмены ctx.
//
// Внимание: фоновая read-горутина запускается при первом вызове и не
// прерывается отменой ctx — она блокируется на scanner.Scan(). Если ctx
// отменён, Read возвращает ctx.Err(), но горутина остаётся жить до тех
// пор, пока t.in не вернёт EOF или ошибку.
func (t *Transport) Read(ctx context.Context) (jsonrpc.Message, error) {
	t.readOnce.Do(t.startReader)

	select {
	case msg, ok := <-t.msgCh:
		if !ok {
			// msgCh закрыт — дренируем errCh; если там осталась ошибка, вернём её.
			select {
			case err, ok := <-t.errCh:
				if ok && err != nil {
					return jsonrpc.Message{}, err
				}
			default:
			}
			return jsonrpc.Message{}, io.EOF
		}
		return msg, nil
	case err, ok := <-t.errCh:
		if !ok || err == nil {
			return jsonrpc.Message{}, io.EOF
		}
		return jsonrpc.Message{}, err
	case <-ctx.Done():
		return jsonrpc.Message{}, ctx.Err()
	}
}

// startReader — тело фоновой read-горутины. Запускается ровно один раз
// через sync.Once. Закрывает msgCh и errCh при выходе.
func (t *Transport) startReader() {
	go func() {
		defer close(t.msgCh)
		defer close(t.errCh)

		scanner := bufio.NewScanner(t.in)
		scanner.Buffer(make([]byte, 0, 64*1024), maxLineSize)

		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}
			msg, err := jsonrpc.Decode(line)
			if err != nil {
				t.errCh <- err
				return
			}
			// Копию line брать не надо: Decode уже распарсил данные в msg.
			t.msgCh <- msg
		}

		if err := scanner.Err(); err != nil {
			t.errCh <- err
			return
		}
		// scanner.Scan() == false без ошибки означает EOF.
		t.errCh <- io.EOF
	}()
}

// Write последовательно сериализует msgs под единым мьютексом.
//
// Если ctx уже отменён на момент входа, возвращает ctx.Err() ДО взятия
// мьютекса. После взятия мьютекса запись идёт без cancel-проверок —
// критический секшн короткий и должен быть атомарным относительно других
// Write-вызовов.
func (t *Transport) Write(ctx context.Context, msgs ...jsonrpc.Message) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(msgs) == 0 {
		return nil
	}

	// Сериализуем всё в один буфер ДО взятия мьютекса — короче критический
	// секшн, плюс атомарность: при ошибке Encode ни байта не утекает в out.
	var buf []byte
	for _, msg := range msgs {
		data, err := jsonrpc.Encode(msg)
		if err != nil {
			return fmt.Errorf("stdio write: %w", err)
		}
		buf = append(buf, data...)
		buf = append(buf, '\n')
	}

	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	if t.closed {
		return fmt.Errorf("stdio write: %w", io.ErrClosedPipe)
	}

	if _, err := t.out.Write(buf); err != nil {
		return fmt.Errorf("stdio write: %w", err)
	}

	if bw, ok := t.out.(*bufio.Writer); ok {
		if err := bw.Flush(); err != nil {
			return fmt.Errorf("stdio write: %w", err)
		}
	}
	return nil
}

// Close идемпотентен. Не закрывает t.in / t.out — это не наши ресурсы.
//
// Фоновая read-горутина остаётся висеть до тех пор, пока t.in не вернёт
// EOF — см. комментарий к типу Transport.
func (t *Transport) Close() error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	t.closed = true
	return nil
}
