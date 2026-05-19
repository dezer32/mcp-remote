package oauth

import "context"

// DefaultOpener — стандартный открыватель браузера.
// Реализация — unit 4 (BROWSER env / open / xdg-open / cmd /c start).
type DefaultOpener struct{}

// Open запускает дефолтный браузер для url.
func (DefaultOpener) Open(ctx context.Context, url string) error {
	return nil
}
