package oauth

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dezer32/mcp-remote/internal/config"
)

func TestCallbackSuccess(t *testing.T) {
	cfg := &config.Config{}
	url, srv, err := listenCallback(cfg, "GOOD", 0, nil)
	if err != nil {
		t.Fatalf("listenCallback: %v", err)
	}
	defer func() {
		_ = srv.Shutdown(context.Background())
	}()

	resp, err := http.Get(url + "?code=XYZ&state=GOOD")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Authorization complete") {
		t.Fatalf("response body = %q", string(body))
	}

	res := srv.Wait(context.Background())
	if res.err != nil {
		t.Fatalf("res.err: %v", res.err)
	}
	if res.code != "XYZ" || res.state != "GOOD" {
		t.Fatalf("res = %+v", res)
	}
}

func TestCallbackErrorParam(t *testing.T) {
	cfg := &config.Config{}
	url, srv, err := listenCallback(cfg, "anything", 0, nil)
	if err != nil {
		t.Fatalf("listenCallback: %v", err)
	}
	defer func() {
		_ = srv.Shutdown(context.Background())
	}()

	resp, err := http.Get(url + "?error=access_denied&error_description=user%20rejected&state=anything")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	res := srv.Wait(context.Background())
	if res.err == nil {
		t.Fatalf("expected error, got code=%s state=%s", res.code, res.state)
	}
	if !strings.Contains(res.err.Error(), "access_denied") {
		t.Fatalf("err = %v, want contain access_denied", res.err)
	}
}

// error без state (или с чужим) — 400, ожидание не завершается.
func TestCallbackErrorWithoutStateIsIgnored(t *testing.T) {
	cfg := &config.Config{}
	url, srv, err := listenCallback(cfg, "EXPECTED", 0, nil)
	if err != nil {
		t.Fatalf("listenCallback: %v", err)
	}
	defer func() {
		_ = srv.Shutdown(context.Background())
	}()

	// Без keep-alive и с вычиткой тела: иначе неиспользованное соединение
	// держит graceful Shutdown до 5 с.
	cli := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	for _, q := range []string{"?error=access_denied", "?error=access_denied&state=WRONG", "?error=access_denied&state="} {
		resp, err := cli.Get(url + q)
		if err != nil {
			t.Fatalf("GET %s: %v", q, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("GET %s: status = %d, want 400", q, resp.StatusCode)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	res := srv.Wait(ctx)
	if !errors.Is(res.err, context.DeadlineExceeded) {
		t.Fatalf("Wait err = %v, want context deadline (flow must not finish)", res.err)
	}
}

// Неверный state не срывает флоу: следом пришедший верный callback успешен.
func TestCallbackStateMismatch(t *testing.T) {
	cfg := &config.Config{}
	url, srv, err := listenCallback(cfg, "EXPECTED", 0, nil)
	if err != nil {
		t.Fatalf("listenCallback: %v", err)
	}
	defer func() {
		_ = srv.Shutdown(context.Background())
	}()

	resp, err := http.Get(url + "?code=X&state=BAD")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}

	resp, err = http.Get(url + "?code=GOODCODE&state=EXPECTED")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	res := srv.Wait(ctx)
	if res.err != nil || res.code != "GOODCODE" {
		t.Fatalf("res = %+v, want success with GOODCODE", res)
	}
}

// Не-GET — 405 с Allow: GET, ожидание продолжается.
func TestCallbackNonGetMethod(t *testing.T) {
	cfg := &config.Config{}
	url, srv, err := listenCallback(cfg, "S", 0, nil)
	if err != nil {
		t.Fatalf("listenCallback: %v", err)
	}
	defer func() {
		_ = srv.Shutdown(context.Background())
	}()

	resp, err := http.Post(url+"?code=X&state=S", "application/x-www-form-urlencoded", strings.NewReader("code=X&state=S"))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}
	if got := resp.Header.Get("Allow"); got != http.MethodGet {
		t.Fatalf("Allow = %q, want GET", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if res := srv.Wait(ctx); !errors.Is(res.err, context.DeadlineExceeded) {
		t.Fatalf("Wait err = %v, want context deadline", res.err)
	}
}

func TestCallbackMissingCode(t *testing.T) {
	cfg := &config.Config{}
	url, srv, err := listenCallback(cfg, "S", 0, nil)
	if err != nil {
		t.Fatalf("listenCallback: %v", err)
	}
	defer func() {
		_ = srv.Shutdown(context.Background())
	}()

	resp, err := http.Get(url + "?state=S")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()

	res := srv.Wait(context.Background())
	if res.err == nil {
		t.Fatalf("expected error for missing code")
	}
}

func TestCallbackContextTimeout(t *testing.T) {
	cfg := &config.Config{}
	_, srv, err := listenCallback(cfg, "S", 0, nil)
	if err != nil {
		t.Fatalf("listenCallback: %v", err)
	}
	defer func() {
		_ = srv.Shutdown(context.Background())
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	res := srv.Wait(ctx)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Wait waited too long: %v", elapsed)
	}
	if res.err == nil {
		t.Fatalf("expected ctx error")
	}
}

func TestIsLoopbackHost(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"", true},
		{"localhost", true},
		{"LOCALHOST", true},
		{"127.0.0.1", true},
		{"127.0.0.2", true},
		{"::1", true},
		{"[::1]", true},
		{"0.0.0.0", false},
		{"::", false},
		{"192.168.1.10", false},
		{"example.com", false},
	}
	for _, tc := range tests {
		if got := isLoopbackHost(tc.host); got != tc.want {
			t.Errorf("isLoopbackHost(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestRegisteredCallbackPort(t *testing.T) {
	tests := []struct {
		name string
		host string
		uris []string
		want int
	}{
		{"default host", "", []string{"http://127.0.0.1:62505/callback"}, 62505},
		{"host case-insensitive", "LocalHost", []string{"http://localhost:8080/callback"}, 8080},
		{"localhost is not 127.0.0.1", "127.0.0.1", []string{"http://localhost:8080/callback"}, 0},
		{"ipv6 without brackets", "::1", []string{"http://[::1]:9000/callback"}, 9000},
		{"ipv6 with brackets", "[::1]", []string{"http://[::1]:9000/callback"}, 9000},
		{"foreign path", "", []string{"http://127.0.0.1:8080/cb"}, 0},
		{"https scheme", "", []string{"https://127.0.0.1:8080/callback"}, 0},
		{"non-numeric port", "", []string{"http://127.0.0.1:abc/callback"}, 0},
		{"no port", "", []string{"http://127.0.0.1/callback"}, 0},
		{"second uri matches", "", []string{"https://app.example/callback", "http://127.0.0.1:7000/callback"}, 7000},
		{"empty", "", nil, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := registeredCallbackPort(tc.host, tc.uris); got != tc.want {
				t.Fatalf("registeredCallbackPort(%q, %v) = %d, want %d", tc.host, tc.uris, got, tc.want)
			}
		})
	}
}

// freePort возвращает порт, который только что был свободен.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// holdPort занимает порт на время теста.
func holdPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().(*net.TCPAddr).Port
}

func TestCallbackPreferredPortFree(t *testing.T) {
	port := freePort(t)
	u, srv, err := listenCallback(&config.Config{}, "S", port, nil)
	if err != nil {
		t.Fatalf("listenCallback: %v", err)
	}
	defer func() { _ = srv.Shutdown(context.Background()) }()
	if want := "http://127.0.0.1:" + strconv.Itoa(port) + "/callback"; u != want {
		t.Fatalf("url = %q, want %q", u, want)
	}
}

func TestCallbackPreferredPortBusyFallsBack(t *testing.T) {
	port := holdPort(t)
	u, srv, err := listenCallback(&config.Config{}, "S", port, nil)
	if err != nil {
		t.Fatalf("listenCallback: %v", err)
	}
	defer func() { _ = srv.Shutdown(context.Background()) }()
	if strings.Contains(u, ":"+strconv.Itoa(port)+"/") {
		t.Fatalf("url = %q uses the busy port", u)
	}
}

func TestCallbackExplicitPortWinsAndBusyFails(t *testing.T) {
	explicit := freePort(t)
	preferred := freePort(t)
	u, srv, err := listenCallback(&config.Config{Port: explicit}, "S", preferred, nil)
	if err != nil {
		t.Fatalf("listenCallback: %v", err)
	}
	_ = srv.Shutdown(context.Background())
	if !strings.Contains(u, ":"+strconv.Itoa(explicit)+"/") {
		t.Fatalf("url = %q, want explicit port %d", u, explicit)
	}

	busy := holdPort(t)
	if _, _, err := listenCallback(&config.Config{Port: busy}, "S", 0, nil); err == nil {
		t.Fatal("expected error for busy explicit port")
	}
}
