// Package stdio реализует Transport (см. internal/proxy) поверх stdin/stdout.
// JSON-RPC сообщения сериализуются как одна строка на сообщение (newline-delimited).
package stdio

import (
	"context"
	"errors"
	"io"
	"log/slog"

	"github.com/dezer32/mcp-remote/internal/jsonrpc"
)

// Transport — newline-delimited JSON-RPC поверх io.Reader/io.Writer.
// Реализация — unit 2.
type Transport struct {
	in  io.Reader
	out io.Writer
	log *slog.Logger
}

// New создаёт Transport. in/out обычно — os.Stdin / os.Stdout.
func New(in io.Reader, out io.Writer, log *slog.Logger) *Transport {
	return &Transport{in: in, out: out, log: log}
}

// Read блокируется до прихода сообщения, EOF или отмены ctx.
func (t *Transport) Read(ctx context.Context) (jsonrpc.Message, error) {
	return jsonrpc.Message{}, errors.New("stdio.Transport.Read: not implemented")
}

// Write последовательно сериализует msgs под единым мьютексом.
func (t *Transport) Write(ctx context.Context, msgs ...jsonrpc.Message) error {
	return errors.New("stdio.Transport.Write: not implemented")
}

// Close освобождает буферы / останавливает фоновую reader-горутину (если возможно).
func (t *Transport) Close() error {
	return nil
}
