package oauth

// Локальный OAuth callback listener.
//   net.Listen("tcp", host:0) → http.Server на /callback.
//   host из cfg.Host (default 127.0.0.1).
//   Принимает ?code=...&state=... либо ?error=...&error_description=...
//   state валидируется; mismatch → ошибка, токен не запрашивается.
//   Отвечает простой HTML "Authorization complete, you can close this tab".
//   Graceful shutdown через ctx.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dezer32/mcp-remote/internal/config"
)

const (
	callbackPath    = "/callback"
	defaultHost     = "127.0.0.1"
	shutdownTimeout = 2 * time.Second
)

// callbackResult — результат, полученный браузером на /callback.
type callbackResult struct {
	code  string
	state string
	err   error
}

// callbackServer — локальный HTTP сервер, ждущий ровно одного запроса
// /callback и затем gracefully завершающийся.
type callbackServer struct {
	listener net.Listener
	server   *http.Server
	result   chan callbackResult
	state    string

	once sync.Once // защищает result от двойной отправки
}

// listenCallback стартует HTTP сервер на cfg.Host (default 127.0.0.1) на
// случайном порту. expectedState — для валидации state в callback.
// Возвращает абсолютный callback URL и сам сервер.
func listenCallback(cfg *config.Config, expectedState string) (string, *callbackServer, error) {
	host := defaultHost
	if cfg != nil && cfg.Host != "" {
		host = cfg.Host
	}
	port := 0
	if cfg != nil && cfg.Port > 0 {
		port = cfg.Port
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", nil, fmt.Errorf("oauth: listen %s: %w", addr, err)
	}

	cs := &callbackServer{
		listener: ln,
		result:   make(chan callbackResult, 1),
		state:    expectedState,
	}

	mux := http.NewServeMux()
	mux.HandleFunc(callbackPath, cs.handle)

	cs.server = &http.Server{
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		_ = cs.server.Serve(ln)
	}()

	// Сборка callback URL из фактически занятого порта.
	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		return "", nil, fmt.Errorf("oauth: unexpected listener addr type %T", ln.Addr())
	}
	hostPart := host
	if strings.Contains(hostPart, ":") {
		// IPv6 — оборачиваем в квадратные скобки.
		hostPart = "[" + hostPart + "]"
	}
	url := fmt.Sprintf("http://%s:%d%s", hostPart, tcpAddr.Port, callbackPath)
	return url, cs, nil
}

// handle обрабатывает запрос /callback.
func (s *callbackServer) handle(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var res callbackResult
	switch {
	case q.Get("error") != "":
		e := q.Get("error")
		desc := q.Get("error_description")
		if desc != "" {
			res = callbackResult{err: fmt.Errorf("%s: %s", e, desc)}
		} else {
			res = callbackResult{err: errors.New(e)}
		}
	default:
		code := q.Get("code")
		state := q.Get("state")
		if state != s.state {
			res = callbackResult{err: errors.New("state mismatch")}
		} else if code == "" {
			res = callbackResult{err: errors.New("authorization code missing")}
		} else {
			res = callbackResult{code: code, state: state}
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if res.err != nil {
		_, _ = fmt.Fprintf(w, `<!doctype html><html><body><p>Authorization error: %s</p></body></html>`, htmlEscape(res.err.Error()))
	} else {
		_, _ = fmt.Fprintln(w, `<!doctype html><html><body><p>Authorization complete, you can close this tab.</p></body></html>`)
	}

	s.send(res)
}

// send отправляет ровно один результат в канал; повторные вызовы no-op.
func (s *callbackServer) send(r callbackResult) {
	s.once.Do(func() {
		s.result <- r
	})
}

// Wait блокирует до получения callback-результата или отмены ctx.
// На ctx.Done возвращает {err: ctx.Err()} и асинхронно вызывает Shutdown.
func (s *callbackServer) Wait(ctx context.Context) callbackResult {
	select {
	case r := <-s.result:
		return r
	case <-ctx.Done():
		go func() {
			shCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
			defer cancel()
			_ = s.Shutdown(shCtx)
		}()
		return callbackResult{err: ctx.Err()}
	}
}

// Shutdown gracefully останавливает сервер. Идемпотентен.
func (s *callbackServer) Shutdown(ctx context.Context) error {
	if s.server == nil {
		return nil
	}
	err := s.server.Shutdown(ctx)
	// Закрываем listener на всякий случай — server.Shutdown это уже делает.
	if s.listener != nil {
		_ = s.listener.Close()
	}
	return err
}

// htmlEscape — минимальный escape для текста в HTML body.
func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")
	return r.Replace(s)
}
