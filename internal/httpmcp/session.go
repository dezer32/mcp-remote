package httpmcp

import (
	"sync"
)

// sessionState инкапсулирует Mcp-Session-Id и MCP-Protocol-Version под общим
// RWMutex. Используется из Client.
type sessionState struct {
	mu              sync.RWMutex
	sessionID       string
	protocolVersion string
}

// setSessionID сохраняет id (валидация ASCII-printable выполняется callerом).
func (s *sessionState) setSessionID(id string) {
	s.mu.Lock()
	s.sessionID = id
	s.mu.Unlock()
}

// getSessionID возвращает текущий id.
func (s *sessionState) getSessionID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessionID
}

// clearSessionID обнуляет id (для ResetSession).
func (s *sessionState) clearSessionID() {
	s.mu.Lock()
	s.sessionID = ""
	s.mu.Unlock()
}

// setProtocolVersion сохраняет согласованную версию протокола.
func (s *sessionState) setProtocolVersion(v string) {
	s.mu.Lock()
	s.protocolVersion = v
	s.mu.Unlock()
}

// getProtocolVersion возвращает текущую версию протокола.
func (s *sessionState) getProtocolVersion() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.protocolVersion
}

// isASCIIPrintable — для валидации значения Mcp-Session-Id (см. спеку).
// Допускаются байты 0x21..0x7E (без управляющих и без пробела/таб).
func isASCIIPrintable(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x21 || c > 0x7E {
			return false
		}
	}
	return true
}
