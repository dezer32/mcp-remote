//go:build integration

// Command browser_helper — заменитель браузера для интеграционных тестов
// OAuth. Принимает первым аргументом authorize-URL, делает GET (без авто-
// follow), ожидает 302, затем GET по Location (callback на локальный
// прокси-listener), закрывая OAuth-цикл.
//
// Exit codes (для удобной диагностики из t.Logf):
//
//	0 — успех (302 → GET location → ok)
//	2 — нет аргументов
//	3 — ошибка первого GET
//	4 — первый ответ не 302
//	5 — пустой Location
//	6 — ошибка GET по Location
package main

import (
	"net/http"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	authURL := os.Args[1]

	cli := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := cli.Get(authURL)
	if err != nil {
		os.Exit(3)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		os.Exit(4)
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		os.Exit(5)
	}
	resp2, err := cli.Get(loc)
	if err != nil {
		os.Exit(6)
	}
	resp2.Body.Close()
	os.Exit(0)
}
