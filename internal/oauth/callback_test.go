package oauth

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dezer32/mcp-remote/internal/config"
)

func TestCallbackSuccess(t *testing.T) {
	cfg := &config.Config{}
	url, srv, err := listenCallback(cfg, "GOOD")
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
	url, srv, err := listenCallback(cfg, "anything")
	if err != nil {
		t.Fatalf("listenCallback: %v", err)
	}
	defer func() {
		_ = srv.Shutdown(context.Background())
	}()

	resp, err := http.Get(url + "?error=access_denied&error_description=user%20rejected")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()

	res := srv.Wait(context.Background())
	if res.err == nil {
		t.Fatalf("expected error, got code=%s state=%s", res.code, res.state)
	}
	if !strings.Contains(res.err.Error(), "access_denied") {
		t.Fatalf("err = %v, want contain access_denied", res.err)
	}
}

func TestCallbackStateMismatch(t *testing.T) {
	cfg := &config.Config{}
	url, srv, err := listenCallback(cfg, "EXPECTED")
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

	res := srv.Wait(context.Background())
	if res.err == nil || !strings.Contains(res.err.Error(), "state") {
		t.Fatalf("err = %v, want state mismatch", res.err)
	}
}

func TestCallbackMissingCode(t *testing.T) {
	cfg := &config.Config{}
	url, srv, err := listenCallback(cfg, "S")
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
	_, srv, err := listenCallback(cfg, "S")
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
