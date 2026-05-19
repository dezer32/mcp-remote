package oauth

// TODO(unit-4): хранение токенов и client-info на диске.
//   <config_dir>/<sha256(MCP-url)[:16]>/
//     tokens.json   (0600)  — access_token, refresh_token, expires_at
//     client.json   (0600)  — client_id, optional client_secret
//     metadata.json (0600)  — authorization_server metadata + resource
//   директории создаются с 0700.
//   config_dir берётся из cfg.ConfigDir либо $MCP_REMOTE_CONFIG_DIR либо
//   <os.UserConfigDir>/mcp-remote.
