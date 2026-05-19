**English** | [Русский](docs/README.ru.md)

# mcp-remote

A local stdio↔Streamable HTTP MCP proxy in Go for connecting remote MCP servers to stdio-only clients (Claude Desktop and friends).

[![Go Version](https://img.shields.io/badge/go-1.26%2B-00ADD8?logo=go)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/dezer32/mcp-remote?include_prereleases)](https://github.com/dezer32/mcp-remote/releases)

## Overview

`mcp-remote` is a proxy that lets stdio-only MCP clients (primarily Claude
Desktop) talk to remote MCP servers exposed over the
[Streamable HTTP](https://modelcontextprotocol.io/specification/2025-03-26/basic/transports#streamable-http)
transport (MCP specification 2025-03-26). It is a Go port of the
[`mcp-remote`](https://github.com/geelen/mcp-remote) npm package, focused
on a single self-contained binary with no runtime dependencies.

Under the hood, mcp-remote runs as a child process of the client, reads
JSON-RPC messages from stdin, forwards them over HTTPS to the remote MCP
endpoint, and pipes responses (including the SSE stream of
server-initiated messages) back to stdout. On HTTP 401 it automatically
launches the OAuth 2.1 flow (PKCE + RFC7591 Dynamic Client Registration +
RFC9728/RFC8414 discovery), opens the browser, catches the localhost
redirect, and persists tokens to disk with 0600 permissions. Subsequent
runs reuse the saved tokens transparently.

## Installation

### Via Go toolchain

```bash
go install github.com/dezer32/mcp-remote@latest
```

The binary will be installed to `$(go env GOBIN)` (defaults to `$GOPATH/bin`).

### Prebuilt binaries

Download the archive for your platform from
[GitHub Releases](https://github.com/dezer32/mcp-remote/releases): builds
are available for `darwin`, `linux`, `windows` on `amd64` and `arm64`.
Extract and place `mcp-remote` into any directory on your `$PATH`.

```bash
# macOS / Linux example
tar -xzf mcp-remote_<version>_<os>_<arch>.tar.gz
sudo install mcp-remote /usr/local/bin/
```

### Homebrew (planned)

```bash
brew install dezer32/tap/mcp-remote
```

## Usage

mcp-remote is launched by the client — you typically do not need to
invoke it manually. Just declare the command and arguments in the
client's configuration.

### Claude Desktop

Configuration file:

| OS | Path |
|----|------|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

Minimal example:

```json
{
  "mcpServers": {
    "my-server": {
      "command": "/usr/local/bin/mcp-remote",
      "args": ["https://your-mcp-server.example.com/mcp"]
    }
  }
}
```

Example with an `Authorization` header and environment variable
substitution:

```json
{
  "mcpServers": {
    "my-server": {
      "command": "/usr/local/bin/mcp-remote",
      "args": [
        "https://api.example.com/mcp",
        "--header",
        "Authorization:Bearer ${TOKEN}"
      ],
      "env": {
        "TOKEN": "sk-..."
      }
    }
  }
}
```

More examples are in [`examples/claude_desktop_config.json`](examples/claude_desktop_config.json).

## CLI flags

```
mcp-remote <server-url> [port] [flags]
```

| Flag | Argument | Description |
|------|----------|-------------|
| `--header` | `"K: V"` | HTTP header appended to every request. Repeatable. Supports `${ENV}` interpolation. |
| `--allow-http` | — | Allow non-HTTPS `server-url` (disabled by default). |
| `--debug` | — | Verbose logs to stderr (DEBUG level). |
| `--silent` | — | Log errors only (ERROR level). |
| `--auth-timeout` | `30s` / `30` | OAuth callback timeout. Accepts a Go duration (`30s`, `2m`) or a number of seconds. Default: `30s`. |
| `--static-oauth-client-metadata` | `<json>` or `@<path>` | Override client_metadata for DCR. Inline JSON or `@file.json`. |
| `--static-oauth-client-info` | `<json>` or `@<path>` | Pre-existing `client_id` (and optionally `client_secret`) — DCR is skipped. |
| `--resource` | `<uri>` | Override the RFC9728 `resource` URI (auto-discovered by default). |
| `--host` | `127.0.0.1` | Bind host for the local OAuth callback. Default: `127.0.0.1`. |
| `--config-dir` | `<path>` | Root directory for token and OAuth metadata storage. |

Positional arguments: the first is the required remote MCP server URL;
the second (optional) is the desired port for the local callback server.
If omitted or `0`, the OS picks the port.

## Environment variables

| Variable | Purpose |
|----------|---------|
| `MCP_REMOTE_CONFIG_DIR` | Overrides the token storage root (equivalent to `--config-dir`; the flag takes precedence). |
| `BROWSER` | Path to the executable that opens the OAuth URL. When set, it overrides `open` / `xdg-open` / `cmd /c start`. |

## OAuth

On HTTP `401 Unauthorized` from the remote MCP server, mcp-remote
automatically launches the OAuth flow:

1. Parses `WWW-Authenticate` and/or performs RFC9728 protected-resource
   discovery to locate the Authorization Server.
2. Performs RFC8414 metadata discovery against the Authorization Server.
3. If needed, performs RFC7591 Dynamic Client Registration (or uses the
   data from `--static-oauth-client-info`).
4. Starts a local HTTP server on `--host:port` to receive the callback.
5. Opens the user's browser at the authorization endpoint
   (PKCE S256, state, redirect_uri = `http://<host>:<port>/callback`).
6. After a successful redirect, exchanges the `code` for access/refresh
   tokens.
7. Persists tokens, client info, and server metadata to the config-dir.

### Token storage location

Root: `--config-dir`, or `MCP_REMOTE_CONFIG_DIR`, or the system
configuration directory (`~/.config/mcp-remote` on Linux,
`~/Library/Application Support/mcp-remote` on macOS,
`%AppData%\mcp-remote` on Windows).

Inside, there is one subdirectory per server, named after the first 16
hex characters of `sha256(server-url)`:

```
<config-dir>/
  <hash16>/
    tokens.json     # access + refresh token, expiry
    client.json     # client_id / client_secret
    metadata.json   # discovered authorization server metadata
```

All files are `0600`; directories are `0700`.

### Resetting tokens

```bash
# macOS
rm -rf "$HOME/Library/Application Support/mcp-remote/<hash16>"
# Linux
rm -rf "$HOME/.config/mcp-remote/<hash16>"
# Windows (PowerShell)
Remove-Item -Recurse -Force "$env:AppData\mcp-remote\<hash16>"
```

To reset everything at once, remove the entire root directory.

## Troubleshooting

- **No output at all** — pass `--debug`; mcp-remote writes detailed logs
  to stderr, and Claude Desktop captures subprocess stderr in its own
  log file.
- **OAuth window does not open** — set the `BROWSER` environment
  variable to the path of a browser executable, or open the URL printed
  to stderr manually.
- **Hangs on callback** — increase `--auth-timeout` and verify that the
  redirect_uri is allowed on the Authorization Server side.
- **Server does not support DCR** — register the client manually and
  pass `--static-oauth-client-info '{"client_id":"...","client_secret":"..."}'`
  (or `@/path/to/file.json`).
- **Reset stuck state** — delete the token directory for that server
  (see above) and restart the client.
- **HTTP instead of HTTPS** — in a dev environment, pass `--allow-http`.
  **Do not** do this in production.

## Security

- HTTPS is mandatory. Non-HTTPS URLs are rejected unless `--allow-http`
  is provided (development only).
- Cross-origin redirects during the token-endpoint exchange are blocked
  — protection against `code` / `refresh_token` leakage to a third-party
  host.
- Reserved headers (`Mcp-Session-Id`, `Accept`, `Content-Type`,
  `Content-Length`, `Host`, `Connection`, `Upgrade`, etc.) cannot be
  overridden via `--header` — attempting to do so fails validation.
- If `Authorization` is supplied via `--header`, it overrides the OAuth
  flow: mcp-remote will not initiate authorization and will not persist
  tokens.
- Token files are stored with `0600` permissions; directories with
  `0700`.
- `${ENV}` references in `--header` values are resolved from the
  mcp-remote process environment; in Claude Desktop the environment is
  set via the `env` key in the server config.

## Project layout

| Package | Purpose |
|---------|---------|
| `internal/jsonrpc` | JSON-RPC 2.0 types and encoding |
| `internal/logging` | Structured logging (slog → stderr) |
| `internal/config`  | CLI flags, env vars, validation |
| `internal/stdio`   | stdin/stdout transport |
| `internal/httpmcp` | Streamable HTTP client to the remote MCP |
| `internal/oauth`   | OAuth 2.1 (PKCE + RFC7591 DCR + RFC9728/RFC8414 discovery) |
| `internal/proxy`   | JSON-RPC routing between transport and remote |
| `main.go`          | Wire-up |

Build: `make build`. Tests: `make test`. Integration: `make test-integration`.

## License

MIT — see [LICENSE](LICENSE).
