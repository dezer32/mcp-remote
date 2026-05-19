package httpmcp

import (
	"fmt"
	"net/http"
	"net/url"
)

// maxRedirects — лимит цепочки редиректов внутри same-origin.
const maxRedirects = 5

// checkRedirect — CheckRedirect policy для http.Client. Блокирует cross-origin
// редиректы (защита от token leak через open redirect) и ограничивает глубину
// до maxRedirects хопов внутри same-origin.
func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("stopped after %d redirects", maxRedirects)
	}
	if len(via) == 0 {
		return nil
	}
	prev := via[len(via)-1].URL
	cur := req.URL
	if !sameOrigin(prev, cur) {
		return fmt.Errorf("cross-origin redirect blocked: %s → %s", prev.Host, cur.Host)
	}
	return nil
}

// sameOrigin true если scheme + host (включая port) совпадают.
func sameOrigin(a, b *url.URL) bool {
	return a.Scheme == b.Scheme && a.Host == b.Host
}
