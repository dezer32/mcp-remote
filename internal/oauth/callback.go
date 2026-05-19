package oauth

// TODO(unit-4): локальный OAuth callback listener.
//   net.Listen("tcp", host:0) → http.Server на /callback.
//   host из cfg.Host (default 127.0.0.1).
//   Принимает ?code=...&state=... либо ?error=...&error_description=...
//   state валидируется; mismatch → ошибка, токен не запрашивается.
//   Отвечает простой HTML "Authorization complete, you can close this tab".
//   Graceful shutdown при истечении cfg.AuthTimeout (через ctx).
