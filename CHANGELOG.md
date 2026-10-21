# Changelog

## 0.1.1 (2026-10-21)

- **Fix (Windows):** `LoopbackBrowser` sends the "You're signed in" page with a `Content-Length` and a blocking close. Before, http.sys reset the connection when the listener was disposed, and the browser showed an error page.
- Tests: the shared RSA test key is generated eagerly (Windows CNG creates keys lazily, so parallel tests could race). The loopback test now awaits its simulated browser so failures surface.
- `.gitignore` now excludes `.nupkg`/`.snupkg` files.

## 0.1.0 — 2026-10-21

### Identvia (NuGet)
- `IdentviaClient`: a public client for WPF, WinUI, WinForms, MAUI and console apps.
  - Authorization code flow with mandatory PKCE S256, `state`, `nonce` and the RFC 9207 `iss` check.
  - ID token validation: RS256/ES256 with System.Security.Cryptography, plus `iss`, `aud`/`azp`, `exp`, `iat`, `nonce`, `at_hash` and `max_age`. Rejects `none` and HS*. An unknown `kid` triggers a JWKS refetch, at most every 30 s.
  - Refresh-token rotation with single-flight refresh. Reuse signs the user out locally (`IdentviaLoginRequiredException`).
- `LoopbackBrowser`: the system browser plus an RFC 8252 loopback listener.
- `DpapiTokenStore` (Windows) and `InMemoryTokenStore`; trim-safe JSON.
- `IdentviaServerClient`, a confidential client: refresh, introspection, revocation, and two stage-5 helpers that require server 2026-10-21_5+: RFC 8693 token exchange and CIBA (start/poll/wait).
- `AuthorizationDetail.AgentTask` (RFC 9396), also stage 5.

### Identvia.AspNetCore (NuGet)
- `AddIdentvia()` / `AddIdentviaAuthentication()`: the Microsoft OpenID Connect handler with Identvia defaults. That means code + PKCE, RFC 9207 `iss` check, RS256/ES256 only, raw claim names, `__Host-` cookie, and a required client secret.
- `MapIdentviaEndpoints()`: `GET /auth/login` (local return URLs only) and a same-origin-only `POST /auth/logout`.
- `HttpContext.GetIdentviaAccessTokenAsync()`: refreshes and writes the rotated refresh token back to the cookie.
