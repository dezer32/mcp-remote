package httpmcp

// TODO(unit-3): SSE-парсер.
// Контракт по спецификации W3C EventSource:
//   - line с префиксом ":" — комментарий, skip
//   - "field: value" — accumulate (multi-line data склеивается через "\n")
//   - пустая строка → emit event и reset
//   - EOF → flush pending event (если был) и close
//   - тракать lastEventID per-stream для Last-Event-ID при reconnect
//   - retry — игнорируем
