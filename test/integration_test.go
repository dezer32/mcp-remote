//go:build integration

package test

// TODO(unit-6): end-to-end интеграционные тесты бинаря mcp-remote.
// Для каждого теста: go build бинаря в t.TempDir() → exec.Cmd с pipes stdin/stdout
// → initialize, tools/list, tools/call, session 404 recovery, OAuth flow через
// browser_helper (BROWSER env).
