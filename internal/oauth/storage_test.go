package oauth

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func newTestStorage(t *testing.T) *Storage {
	t.Helper()
	dir := t.TempDir()
	st, err := NewStorage(dir, "https://example.com/mcp")
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	return st
}

func TestStorageMkdir(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStorage(dir, "https://example.com/mcp")
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	fi, err := os.Stat(st.Root())
	if err != nil {
		t.Fatalf("stat root: %v", err)
	}
	if !fi.IsDir() {
		t.Fatalf("root is not a dir: %s", st.Root())
	}
	// Идентичные serverURL → одинаковый dir.
	st2, err := NewStorage(dir, "https://example.com/mcp")
	if err != nil {
		t.Fatalf("NewStorage again: %v", err)
	}
	if st.Root() != st2.Root() {
		t.Fatalf("stable dir mismatch: %s vs %s", st.Root(), st2.Root())
	}

	// Разные serverURL → разные dirs.
	st3, err := NewStorage(dir, "https://other.example.com/mcp")
	if err != nil {
		t.Fatalf("NewStorage other: %v", err)
	}
	if st.Root() == st3.Root() {
		t.Fatalf("expected different dir for different serverURL")
	}

	if runtime.GOOS != "windows" {
		const want = os.FileMode(0o700)
		if got := fi.Mode().Perm(); got != want {
			t.Fatalf("storage dir mode = %o, want %o", got, want)
		}
	}
}

func TestStorageNewStorageErrors(t *testing.T) {
	if _, err := NewStorage("", "https://x"); err == nil {
		t.Fatalf("expected error for empty configDir")
	}
	if _, err := NewStorage(t.TempDir(), ""); err == nil {
		t.Fatalf("expected error for empty serverURL")
	}
}

func TestStorageTokens(t *testing.T) {
	st := newTestStorage(t)

	if _, err := st.LoadTokens(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("LoadTokens before save: err = %v, want ErrNotExist", err)
	}

	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	in := &Tokens{
		AccessToken:  "AT",
		RefreshToken: "RT",
		ExpiresAt:    expires,
		TokenType:    "Bearer",
		Scope:        "mcp",
	}
	if err := st.SaveTokens(in); err != nil {
		t.Fatalf("SaveTokens: %v", err)
	}

	if runtime.GOOS != "windows" {
		fi, err := os.Stat(filepath.Join(st.Root(), fileTokens))
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if got, want := fi.Mode().Perm(), os.FileMode(0o600); got != want {
			t.Fatalf("tokens.json mode = %o, want %o", got, want)
		}
	}

	out, err := st.LoadTokens()
	if err != nil {
		t.Fatalf("LoadTokens: %v", err)
	}
	if out.AccessToken != in.AccessToken || out.RefreshToken != in.RefreshToken ||
		out.TokenType != in.TokenType || out.Scope != in.Scope ||
		!out.ExpiresAt.Equal(in.ExpiresAt) {
		t.Fatalf("round-trip mismatch:\ngot  %+v\nwant %+v", out, in)
	}

	if err := st.ClearTokens(); err != nil {
		t.Fatalf("ClearTokens: %v", err)
	}
	if _, err := st.LoadTokens(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("LoadTokens after clear: %v", err)
	}
	// Идемпотентность.
	if err := st.ClearTokens(); err != nil {
		t.Fatalf("ClearTokens twice: %v", err)
	}
}

func TestStorageClient(t *testing.T) {
	st := newTestStorage(t)
	in := &ClientInfo{
		ClientID:     "cid",
		ClientSecret: "csecret",
		RedirectURIs: []string{"http://127.0.0.1:1/cb"},
	}
	if err := st.SaveClient(in); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}
	out, err := st.LoadClient()
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	if out.ClientID != in.ClientID || out.ClientSecret != in.ClientSecret ||
		len(out.RedirectURIs) != 1 || out.RedirectURIs[0] != in.RedirectURIs[0] {
		t.Fatalf("client round-trip: got %+v, want %+v", out, in)
	}

	if runtime.GOOS != "windows" {
		fi, err := os.Stat(filepath.Join(st.Root(), fileClient))
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if got, want := fi.Mode().Perm(), os.FileMode(0o600); got != want {
			t.Fatalf("client.json mode = %o, want %o", got, want)
		}
	}
}

func TestStorageMetadata(t *testing.T) {
	st := newTestStorage(t)
	meta := &AuthServerMetadata{
		AuthorizationEndpoint: "https://as/authorize",
		TokenEndpoint:         "https://as/token",
		RegistrationEndpoint:  "https://as/register",
		ScopesSupported:       []string{"a", "b"},
	}
	if err := st.SaveMetadata(meta, "https://res"); err != nil {
		t.Fatalf("SaveMetadata: %v", err)
	}
	gotMeta, gotRes, err := st.LoadMetadata()
	if err != nil {
		t.Fatalf("LoadMetadata: %v", err)
	}
	if gotMeta.AuthorizationEndpoint != meta.AuthorizationEndpoint ||
		gotMeta.TokenEndpoint != meta.TokenEndpoint ||
		gotMeta.RegistrationEndpoint != meta.RegistrationEndpoint ||
		gotRes != "https://res" {
		t.Fatalf("metadata round-trip: got=%+v res=%s", gotMeta, gotRes)
	}
}

func TestStorageNilGuards(t *testing.T) {
	st := newTestStorage(t)
	if err := st.SaveTokens(nil); err == nil {
		t.Fatalf("SaveTokens(nil) must error")
	}
	if err := st.SaveClient(nil); err == nil {
		t.Fatalf("SaveClient(nil) must error")
	}
	if err := st.SaveMetadata(nil, "x"); err == nil {
		t.Fatalf("SaveMetadata(nil) must error")
	}
}
