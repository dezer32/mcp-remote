package oauth

// Локальный OAuth callback listener.
//   net.Listen("tcp", host:port) → http.Server на /callback.
//   host из cfg.Host (default 127.0.0.1). port: явный cfg.Port, иначе порт
//   из redirect_uris известного клиента (с fallback на случайный), иначе 0.
//   Принимает ?code=...&state=... либо ?error=...&error_description=...
//   state валидируется (в постоянное время) для code и для error; запрос с
//   неверным/отсутствующим state получает 400 и ожидание не завершает.
//   Методы кроме GET получают 405.
//   Отвечает простой HTML "Authorization complete, you can close this tab".
//   Graceful shutdown через ctx.

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
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

// listenCallback стартует HTTP сервер на cfg.Host (default 127.0.0.1).
// Порт выбирается так:
//  1. cfg.Port > 0 — явный порт; ошибка bind фатальна;
//  2. preferredPort > 0 — порт из redirect_uris известного клиента; если
//     bind не удался, пишется debug-лог и берётся случайный порт;
//  3. иначе случайный порт (0).
//
// expectedState — для валидации state в callback. log может быть nil.
// Возвращает абсолютный callback URL и сам сервер.
func listenCallback(cfg *config.Config, expectedState string, preferredPort int, log *slog.Logger) (string, *callbackServer, error) {
	host := defaultHost
	if cfg != nil && cfg.Host != "" {
		host = cfg.Host
	}
	// IPv6 в cfg.Host допустим и в скобках, и без: JoinHostPort ставит их сам.
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	explicit := cfg != nil && cfg.Port > 0

	var ln net.Listener
	var err error
	switch {
	case explicit:
		addr := net.JoinHostPort(host, strconv.Itoa(cfg.Port))
		if ln, err = net.Listen("tcp", addr); err != nil {
			return "", nil, fmt.Errorf("oauth: listen %s: %w", addr, err)
		}
	case preferredPort > 0:
		addr := net.JoinHostPort(host, strconv.Itoa(preferredPort))
		ln, err = net.Listen("tcp", addr)
		if err != nil {
			if log != nil {
				log.Debug("oauth: registered callback port unavailable, using a random port",
					slog.Int("port", preferredPort), slog.String("error", err.Error()))
			}
			ln = nil
		}
	}
	if ln == nil {
		addr := net.JoinHostPort(host, "0")
		if ln, err = net.Listen("tcp", addr); err != nil {
			return "", nil, fmt.Errorf("oauth: listen %s: %w", addr, err)
		}
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
	callbackURL := fmt.Sprintf("http://%s:%d%s", hostPart, tcpAddr.Port, callbackPath)
	return callbackURL, cs, nil
}

// registeredCallbackPort возвращает порт первого URL из redirectURIs, на
// котором может подняться callback-сервер на host: схема http, тот же хост
// (без учёта регистра, IPv6 без скобок), путь /callback и числовой порт.
// 0 — подходящего URL нет. Пустой host — defaultHost. "localhost" и
// "127.0.0.1" — разные хосты: строгий AS сравнивает redirect_uri как строку.
func registeredCallbackPort(host string, redirectURIs []string) int {
	if host == "" {
		host = defaultHost
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	for _, raw := range redirectURIs {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "http" || u.Path != callbackPath {
			continue
		}
		if !strings.EqualFold(u.Hostname(), host) {
			continue
		}
		port, err := strconv.Atoi(u.Port())
		if err != nil || port <= 0 || port > 65535 {
			continue
		}
		return port
	}
	return 0
}

// isLoopbackHost сообщает, слушает ли callback-сервер только loopback:
// "localhost" (без учёта регистра) или IP, для которого IsLoopback. Пустой
// host — это defaultHost (127.0.0.1). 0.0.0.0, "::" и произвольные имена
// хостов не считаются loopback.
func isLoopbackHost(host string) bool {
	if host == "" {
		return true
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return addr.IsLoopback()
}

// handle обрабатывает запрос /callback. Флоу завершается только GET-запросом
// с верным state: на callback может постучаться любой локальный процесс или
// страница в браузере, а легитимный редирект AS всегда несёт state.
func (s *callbackServer) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	state := q.Get("state")
	// Пустой state считаем отсутствующим, даже если ожидаемый почему-то пуст.
	if state == "" || subtle.ConstantTimeCompare([]byte(state), []byte(s.state)) != 1 {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintln(w, `<!doctype html><html><body><p>Authorization error: invalid or missing state.</p></body></html>`)
		return
	}

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
	case q.Get("code") == "":
		res = callbackResult{err: errors.New("authorization code missing")}
	default:
		res = callbackResult{code: q.Get("code"), state: state}
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
