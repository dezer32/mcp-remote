//go:build integration

package test

// TODO(unit-6): stateful httptest.Server, реализующий минимальный MCP-сервер
// для интеграционных тестов: initialize (Mcp-Session-Id + protocolVersion),
// tools/list, tools/call, симуляция session-404 и OAuth 401→PRM-flow.
