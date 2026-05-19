package oauth

// TODO(unit-4): двойной discovery:
//  1) RFC 9728 PRM (если challenge содержит resource_metadata=<url>): fetch
//     <url> → JSON {authorization_servers:[...], resource:"..."}; берём
//     authorization_servers[0] и резолвим эндпоинты по RFC 8414.
//  2) RFC 8414 fallback: <auth-base>/.well-known/oauth-authorization-server
//     с заголовком MCP-Protocol-Version: 2025-03-26; на 404 — дефолтные пути
//     /authorize, /token, /register.
//
// cfg.Resource (если задан) перебивает auto-discovered resource.
