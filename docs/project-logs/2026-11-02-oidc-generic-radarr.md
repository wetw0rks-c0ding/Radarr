# 2026-11-02 — Radarr OIDC-generic (Authentik-specific code removed)

Branch: `feature-oidc-app-auth`

## What changed
- Config plumbing: `OidcRoleMappings` added to `AuthOptions`, `IConfigFileProvider`, `HostConfigResource`, and `HostConfigController` validator.
- Resolver: `OidcGroupMapping.Resolve(groups, mappings)` now mapping-aware (highest-wins across `RadarrRole`); unmapped/empty/malformed → null.
- Rename + de-hardcode: `AuthentikTokenValidationService` → `OidcTokenValidationService` (file renamed via `git mv`); fallback issuer/audience consts and substring logic removed; `GetIssuer()` returns `OidcAuthority` verbatim; audience exact-or-fail-closed; lazy-init `ConfigurationManager`; `MapInboundClaims=false`; in-call JWKS refresh+retry; no-throw on invalid token. `GetGroups` helper added to `AuthenticationBuilderExtensions`.
- Call sites (`/exchange`, callback) pass configured mappings.
- README banner rewritten to provider-neutral wording.

## Verification
- Build: `dotnet build src/Radarr.sln -c Debug -p:Platform=Posix` → 0 warnings, 0 errors.
- No OIDC test fixtures exist in Radarr (create-from-scratch per spec §3); runtime behavior mirrors the Sonarr reference.

## Backward-compat config recipe
Set `OidcAuthority=https://auth.piracyhub.win/application/o/arrstack/` (exact string incl. trailing slash), `OidcClientId=arrstack`, `OidcRoleMappings=homies=ReadOnly;family=AddSearch;maintenance=Manage;authentik Admins=Admin`.
