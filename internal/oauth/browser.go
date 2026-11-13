package oauth

// DefaultOpener — реальная реализация Opener, открывающая URL в дефолтном
// браузере хоста. Уважает переменную окружения $BROWSER; иначе использует
// платформенный механизм (open / xdg-open / rundll32 url.dll,FileProtocolHandler).
//
// URL приходит из данных удалённого сервера (authorization_endpoint), поэтому
// перед запуском процесса он проходит санитарию, а на Windows командный
// интерпретатор (cmd.exe) не используется вовсе: для него `&` в URL —
// разделитель команд (класс уязвимости CVE-2025-6514).

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"unicode"
)

// errUnsafeURL — URL не прошёл санитарию и в браузер не передаётся.
var errUnsafeURL = errors.New("oauth: unsafe URL for browser")

// sanitizeBrowserURL проверяет, что raw — абсолютный http/https URL с хостом,
// без userinfo и без пробельных символов, и возвращает перекодированный
// url.URL.String(), а не исходную строку.
func sanitizeBrowserURL(raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("%w: empty URL", errUnsafeURL)
	}
	// Без пробельных символов Go передаёт аргумент дочернему процессу без
	// кавычек и изменений на любой платформе.
	if strings.IndexFunc(raw, unicode.IsSpace) >= 0 {
		return "", fmt.Errorf("%w: whitespace in URL", errUnsafeURL)
	}
	u, err := url.Parse(raw)
	if err != nil {
		// url.Error содержит исходный URL — в сообщение берём только причину.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return "", fmt.Errorf("%w: malformed URL: %v", errUnsafeURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("%w: scheme %q is not allowed (want http or https)", errUnsafeURL, u.Scheme)
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("%w: empty host", errUnsafeURL)
	}
	if u.User != nil {
		return "", fmt.Errorf("%w: userinfo in URL", errUnsafeURL)
	}
	return u.String(), nil
}

// browserCommand возвращает команду запуска браузера для платформы goos.
// URL всегда единственный последний аргумент; командная оболочка не участвует.
func browserCommand(goos, rawURL string) (string, []string) {
	switch goos {
	case "darwin":
		return "open", []string{rawURL}
	case "windows":
		// rundll32 — не интерпретатор: `&`, `|`, `^`, `%` для него обычные
		// символы. Путь абсолютный, чтобы не зависеть от PATH.
		name := "rundll32.exe"
		if root := os.Getenv("SystemRoot"); root != "" {
			name = strings.TrimRight(root, `\/`) + `\System32\rundll32.exe`
		}
		return name, []string{"url.dll,FileProtocolHandler", rawURL}
	default:
		// linux, *bsd, etc.
		return "xdg-open", []string{rawURL}
	}
}

// DefaultOpener — стандартный открыватель браузера.
type DefaultOpener struct{}

// Open запускает дефолтный браузер для rawURL. Сначала URL проходит санитарию
// (на отказ — ошибка, обёрнутая errUnsafeURL, процесс не запускается).
// Команда стартует в фоне (cmd.Start, не Run) — мы не дожидаемся завершения
// процесса браузера.
func (DefaultOpener) Open(ctx context.Context, rawURL string) error {
	safe, err := sanitizeBrowserURL(rawURL)
	if err != nil {
		return err
	}

	if browser := strings.TrimSpace(os.Getenv("BROWSER")); browser != "" {
		cmd := exec.CommandContext(ctx, browser, safe) //nolint:gosec // user-provided $BROWSER, URL проверен
		return startDetached(cmd)
	}

	name, args := browserCommand(runtime.GOOS, safe)
	return startDetached(exec.CommandContext(ctx, name, args...)) //nolint:gosec // команда выбирается из фиксированного набора, URL проверен
}

// startDetached запускает процесс не дожидаясь его завершения.
func startDetached(cmd *exec.Cmd) error {
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("oauth: open browser: %w", err)
	}
	// Освобождаем ресурсы дочернего процесса в фоне, чтобы он не стал зомби.
	go func() { _ = cmd.Wait() }()
	return nil
}
