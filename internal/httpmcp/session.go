package httpmcp

import (
	"sync"
)

// sessionState инкапсулирует Mcp-Session-Id и MCP-Protocol-Version под общим
// RWMutex. Используется из Client.
//
// gen — поколение сессии: увеличивается на каждый clearSessionID (ResetSession).
// Запрос запоминает поколение, с которым ушёл (sessionSnap), и Mcp-Session-Id из
// его ответа применяется, только если поколение не сменилось. Так ответ запроса,
// отправленного ещё со старой сессией, не перезапишет сессию, полученную после
// recovery.
type sessionState struct {
	mu              sync.RWMutex
	sessionID       string
	gen             uint64
	protocolVersion string
}

// sessionSnap — атомарный снимок сессии на момент отправки запроса.
type sessionSnap struct {
	// id — Mcp-Session-Id, с которым запрос ушёл ("" — без сессии).
	id string
	// gen — поколение сессии на момент отправки.
	gen uint64
}

// snapshot возвращает текущие id и поколение под одним захватом мьютекса.
func (s *sessionState) snapshot() sessionSnap {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return sessionSnap{id: s.sessionID, gen: s.gen}
}

// setSessionIDIfCurrent сохраняет id (валидация ASCII-printable — на caller-е),
// только если поколение не изменилось с момента снимка gen. Возвращает false,
// если снимок устарел и id проигнорирован.
func (s *sessionState) setSessionIDIfCurrent(id string, gen uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gen != gen {
		return false
	}
	s.sessionID = id
	return true
}

// getSessionID возвращает текущий id.
func (s *sessionState) getSessionID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessionID
}

// clearSessionID обнуляет id и начинает новое поколение (для ResetSession).
func (s *sessionState) clearSessionID() {
	s.mu.Lock()
	s.sessionID = ""
	s.gen++
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
