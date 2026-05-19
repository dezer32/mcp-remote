// Package jsonrpc реализует типы и (де)сериализацию JSON-RPC 2.0 сообщений,
// используемых обоими транспортами (stdio и Streamable HTTP).
package jsonrpc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// Version — JSON-RPC 2.0.
const Version = "2.0"

// Message — единое представление request/response/notification/error.
// Конкретный вариант различается по наличию полей (см. helpers ниже).
type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Error — стандартная ошибка JSON-RPC.
type Error struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("jsonrpc error %d: %s", e.Code, e.Message)
}

// HasID true если id != null и не пустой.
func (m Message) HasID() bool {
	if len(m.ID) == 0 {
		return false
	}
	return !bytes.Equal(bytes.TrimSpace(m.ID), []byte("null"))
}

// IsRequest — method + id.
func (m Message) IsRequest() bool { return m.Method != "" && m.HasID() }

// IsNotification — method без id.
func (m Message) IsNotification() bool { return m.Method != "" && !m.HasID() }

// IsResponse — id есть, method пуст (есть result или error).
func (m Message) IsResponse() bool {
	return m.Method == "" && m.HasID() && (len(m.Result) > 0 || m.Error != nil)
}

// Decode декодирует одно JSON-RPC сообщение.
func Decode(data []byte) (Message, error) {
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return Message{}, fmt.Errorf("jsonrpc decode: %w", err)
	}
	if msg.JSONRPC != Version {
		return Message{}, fmt.Errorf("jsonrpc decode: expected version %q, got %q", Version, msg.JSONRPC)
	}
	return msg, nil
}

// BatchDecode декодирует одно сообщение или массив (JSON-RPC batch).
// Для одиночного объекта возвращает срез длины 1.
func BatchDecode(data []byte) ([]Message, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, errors.New("jsonrpc batch decode: empty input")
	}
	if trimmed[0] == '[' {
		var raws []json.RawMessage
		if err := json.Unmarshal(trimmed, &raws); err != nil {
			return nil, fmt.Errorf("jsonrpc batch decode: %w", err)
		}
		if len(raws) == 0 {
			return nil, errors.New("jsonrpc batch decode: empty array")
		}
		msgs := make([]Message, 0, len(raws))
		for i, raw := range raws {
			m, err := Decode(raw)
			if err != nil {
				return nil, fmt.Errorf("batch[%d]: %w", i, err)
			}
			msgs = append(msgs, m)
		}
		return msgs, nil
	}
	m, err := Decode(trimmed)
	if err != nil {
		return nil, err
	}
	return []Message{m}, nil
}

// Encode сериализует Message в JSON. Гарантирует jsonrpc=2.0 в выходе.
func Encode(m Message) ([]byte, error) {
	if m.JSONRPC == "" {
		m.JSONRPC = Version
	}
	return json.Marshal(m)
}

// IsBatch true если bytes начинаются с '[' (после whitespace).
func IsBatch(data []byte) bool {
	trimmed := bytes.TrimSpace(data)
	return len(trimmed) > 0 && trimmed[0] == '['
}
