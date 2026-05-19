package httpmcp

import (
	"bufio"
	"context"
	"errors"
	"io"
	"strings"

	"github.com/dezer32/mcp-remote/internal/jsonrpc"
	"github.com/dezer32/mcp-remote/internal/proxy"
)

// sseMaxLine — верхняя граница длины одной строки SSE.
const sseMaxLine = 8 * 1024 * 1024 // 8MB

// parseSSE читает SSE-поток из body и emit парсит каждый event в out как
// jsonrpc.Message (через BatchDecode — поддерживает single & array).
//
// setLastID вызывается после dispatch события, у которого был id (W3C: id
// сохраняется только на пустой строке-разделителе, не при появлении поля id).
//
// Возвращает nil на EOF, либо ошибку чтения. Ошибки декодирования отдельных
// событий emit-ятся в канал но НЕ прерывают стрим.
func parseSSE(ctx context.Context, body io.Reader, out chan<- proxy.MessageOrError, setLastID func(string)) error {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 4096), sseMaxLine)
	scanner.Split(splitSSELine)

	var (
		dataLines   []string
		idCandidate string
		hasIDField  bool
	)

	dispatch := func() {
		if len(dataLines) == 0 {
			return
		}
		data := strings.Join(dataLines, "\n")
		msgs, err := jsonrpc.BatchDecode([]byte(data))
		if err != nil {
			select {
			case <-ctx.Done():
			case out <- proxy.MessageOrError{Err: err}:
			}
		} else {
			for _, m := range msgs {
				select {
				case <-ctx.Done():
					return
				case out <- proxy.MessageOrError{Msg: m}:
				}
			}
		}
		if hasIDField && setLastID != nil {
			setLastID(idCandidate)
		}
		dataLines = nil
		idCandidate = ""
		hasIDField = false
	}

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line := scanner.Text()
		if line == "" {
			dispatch()
			continue
		}
		if strings.HasPrefix(line, ":") {
			// comment — skip
			continue
		}

		var field, value string
		if idx := strings.IndexByte(line, ':'); idx >= 0 {
			field = line[:idx]
			value = line[idx+1:]
			if strings.HasPrefix(value, " ") {
				value = value[1:]
			}
		} else {
			field = line
			value = ""
		}

		switch field {
		case "event":
			// event-name не используется (jsonrpc по умолчанию)
		case "data":
			dataLines = append(dataLines, value)
		case "id":
			idCandidate = value
			hasIDField = true
		case "retry":
			// ignore
		default:
			// ignore
		}
	}

	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		return err
	}

	// EOF — финальный flush для pending данных (если стрим оборван без \n\n).
	dispatch()
	return nil
}

// splitSSELine — bufio.SplitFunc, режет строки по \n, \r\n или \r как
// требует W3C EventSource. Возвращает строку без терминатора.
func splitSSELine(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	for i := 0; i < len(data); i++ {
		c := data[i]
		switch c {
		case '\n':
			return i + 1, data[:i], nil
		case '\r':
			// CRLF: проглотить следующий \n если он есть
			if i+1 < len(data) {
				if data[i+1] == '\n' {
					return i + 2, data[:i], nil
				}
				return i + 1, data[:i], nil
			}
			if atEOF {
				return i + 1, data[:i], nil
			}
			// Нужен ещё байт чтобы понять CRLF или одиночный CR.
			return 0, nil, nil
		}
	}
	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil
}
