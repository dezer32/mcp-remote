package oauth

// DefaultOpener — реальная реализация Opener, открывающая URL в дефолтном
// браузере хоста. Уважает переменную окружения $BROWSER; иначе использует
// платформенный механизм (open / xdg-open / cmd start).

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// DefaultOpener — стандартный открыватель браузера.
type DefaultOpener struct{}

// Open запускает дефолтный браузер для url. Команда стартует в фоне
// (cmd.Start, не Run) — мы не дожидаемся завершения процесса браузера.
func (DefaultOpener) Open(ctx context.Context, url string) error {
	if url == "" {
		return fmt.Errorf("oauth: empty URL")
	}

	if browser := strings.TrimSpace(os.Getenv("BROWSER")); browser != "" {
		cmd := exec.CommandContext(ctx, browser, url) //nolint:gosec // user-provided $BROWSER
		return startDetached(cmd)
	}

	switch runtime.GOOS {
	case "darwin":
		return startDetached(exec.CommandContext(ctx, "open", url))
	case "windows":
		// cmd /c start "" "<url>" — пустой "" нужен как title для start.
		return startDetached(exec.CommandContext(ctx, "cmd", "/c", "start", "", url))
	default:
		// linux, *bsd, etc.
		return startDetached(exec.CommandContext(ctx, "xdg-open", url))
	}
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
