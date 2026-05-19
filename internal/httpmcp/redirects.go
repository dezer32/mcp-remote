package httpmcp

// TODO(unit-3): CheckRedirect-политика для http.Client.
// Запрещает cross-origin редиректы (защита от token leak через open redirect).
// Same-origin (scheme/host/port совпадают) — до 5 хопов.
