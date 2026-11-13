package oauth

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestSanitizeBrowserURL(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "https with ampersands", in: "https://auth.example.com/authorize?response_type=code&client_id=abc&state=xyz", want: "https://auth.example.com/authorize?response_type=code&client_id=abc&state=xyz"},
		{name: "http loopback", in: "http://127.0.0.1:8080/cb", want: "http://127.0.0.1:8080/cb"},
		{name: "scheme case normalized", in: "HTTPS://Auth.Example.com/a", want: "https://Auth.Example.com/a"},
		{name: "file scheme", in: "file:///Applications/Calculator.app?response_type=code", wantErr: true},
		{name: "javascript scheme", in: "javascript:alert(1)", wantErr: true},
		{name: "smb scheme", in: "smb://evil.example/share", wantErr: true},
		{name: "userinfo", in: "https://login.example.com@evil.example/authorize?x=1", wantErr: true},
		{name: "userinfo with password", in: "https://user:pass@evil.example/a", wantErr: true},
		{name: "space", in: "https://auth.example.com/a b", wantErr: true},
		{name: "tab", in: "https://auth.example.com/a\tb", wantErr: true},
		{name: "newline", in: "https://auth.example.com/a\nb", wantErr: true},
		{name: "empty host", in: "https:///path", wantErr: true},
		{name: "empty port-only host", in: "https://:443/path", wantErr: true},
		{name: "leading dash", in: "-flag", wantErr: true},
		{name: "leading dash with scheme-like tail", in: "--url=https://a.example/", wantErr: true},
		{name: "relative", in: "/authorize?x=1", wantErr: true},
		{name: "empty", in: "", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := sanitizeBrowserURL(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("sanitizeBrowserURL(%q) = %q, want error", tc.in, got)
				}
				if !errors.Is(err, errUnsafeURL) {
					t.Fatalf("error %v does not wrap errUnsafeURL", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("sanitizeBrowserURL(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("sanitizeBrowserURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestBrowserCommand(t *testing.T) {
	const u = "https://auth.example.com/authorize?a=1&b=2&c=%25"

	t.Run("darwin", func(t *testing.T) {
		name, args := browserCommand("darwin", u)
		if name != "open" || !reflect.DeepEqual(args, []string{u}) {
			t.Fatalf("got %q %q", name, args)
		}
	})

	t.Run("linux", func(t *testing.T) {
		name, args := browserCommand("linux", u)
		if name != "xdg-open" || !reflect.DeepEqual(args, []string{u}) {
			t.Fatalf("got %q %q", name, args)
		}
	})

	t.Run("windows with SystemRoot", func(t *testing.T) {
		t.Setenv("SystemRoot", `C:\Windows`)
		name, args := browserCommand("windows", u)
		if name != `C:\Windows\System32\rundll32.exe` {
			t.Fatalf("name = %q", name)
		}
		if !reflect.DeepEqual(args, []string{"url.dll,FileProtocolHandler", u}) {
			t.Fatalf("args = %q", args)
		}
	})

	t.Run("windows without SystemRoot", func(t *testing.T) {
		t.Setenv("SystemRoot", "")
		name, args := browserCommand("windows", u)
		if name != "rundll32.exe" {
			t.Fatalf("name = %q", name)
		}
		if !reflect.DeepEqual(args, []string{"url.dll,FileProtocolHandler", u}) {
			t.Fatalf("args = %q", args)
		}
	})

	t.Run("cmd never used", func(t *testing.T) {
		for _, goos := range []string{"darwin", "windows", "linux", "freebsd"} {
			name, args := browserCommand(goos, u)
			all := strings.ToLower(name + " " + strings.Join(args, " "))
			if strings.Contains(all, "cmd") {
				t.Fatalf("%s: command mentions cmd: %q %q", goos, name, args)
			}
			if args[len(args)-1] != u {
				t.Fatalf("%s: URL is not the last argument: %q", goos, args)
			}
		}
	})
}

// Открытие небезопасного URL отклоняется до exec: $BROWSER указывает на
// несуществующий бинарь, и если бы дело дошло до запуска, ошибка была бы
// другой (не errUnsafeURL).
func TestDefaultOpenerRejectsUnsafeURLBeforeExec(t *testing.T) {
	t.Setenv("BROWSER", "/nonexistent/definitely-not-a-browser")

	err := DefaultOpener{}.Open(context.Background(), "file:///etc/passwd")
	if !errors.Is(err, errUnsafeURL) {
		t.Fatalf("Open(file://) err = %v, want errUnsafeURL", err)
	}

	// Контроль: безопасный URL до exec доходит и падает уже на запуске.
	err = DefaultOpener{}.Open(context.Background(), "https://auth.example.com/a?x=1&y=2")
	if err == nil {
		t.Fatal("Open with nonexistent BROWSER unexpectedly succeeded")
	}
	if errors.Is(err, errUnsafeURL) {
		t.Fatalf("safe URL rejected as unsafe: %v", err)
	}
}

// Сообщение об отказе не содержит исходный URL (он может быть вредоносным и
// попасть в лог/stderr).
func TestSanitizeBrowserURLErrorDoesNotEchoURL(t *testing.T) {
	for _, in := range []string{"https://evil.example/a\x00b?secret=1", "https://evil.example/%zz?secret=1", "file:///evil?secret=1"} {
		_, err := sanitizeBrowserURL(in)
		if err == nil {
			t.Fatalf("sanitizeBrowserURL(%q): expected error", in)
		}
		if strings.Contains(err.Error(), "secret=1") || strings.Contains(err.Error(), "evil") {
			t.Fatalf("error echoes URL: %v", err)
		}
	}
}
