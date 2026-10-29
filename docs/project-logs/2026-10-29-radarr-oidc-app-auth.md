# 2026-10-29 — Radarr OIDC App-Auth (group-based auth + /exchange + /me)

Branch: `develop` (fork `wetw0rks-c0ding/Radarr`)
Commits: `a573f17b8`, `08cebb2ba`
Images: `ghcr.io/wetw0rks-c0ding/radarr-oidc:arrstack-08cebb2`, `:develop` (sha256:98e5ead4168...)

## Goal
Port Sonarr-oidc's group-based OIDC authorization and app-auth endpoints to Radarr for Seekarr mobile client integration. Use `radarr` as per-service issuer/audience with support for unified `arrstack` provider.

## Changes

### Core (auth model + migrations)
- `src/NzbDrone.Core/Authentication/RadarrRole.cs` — `ReadOnly(0)`, `AddSearch(1)`, `Manage(2)`, `Admin(3)`
- `src/NzbDrone.Core/Authentication/User.cs` — added `OidcSubject`, `OidcGroups`, `Role` (default `Admin`)
- `src/NzbDrone.Core/Datastore/Migration/244_oidc_user_role_and_subject.cs` — adds columns, default role for existing rows, partial unique index on `OidcSubject` where not null
- `src/NzbDrone.Core/Authentication/UserRepository.cs` — `FindBySubject`, `FindByUsername`, `FindLocalUser()`
- `src/NzbDrone.Core/Authentication/UserService.cs` — `UpsertOidcUser(subject, username, groupsCsv, role)`, subject-first JIT provisioning (no Forms→OIDC auto-link by username)

### AuthZ/RBAC + tokens
- `src/Radarr.Http/Authentication/OidcGroupMapping.cs` — `pirates`→T1 (blocked/403), `homies`→T2 ReadOnly, `family`→T3 AddSearch, `maintenance`→T4 Manage, `authentik Admins`→T5 Admin; highest wins
- `src/Radarr.Http/Authentication/RadarrServiceTokenService.cs` — HS256 JWT `iss`/`aud` `radarr`, 5 min TTL, key at `{AppData}/service-token.key`, `RadarrRolePermissions`
- `src/Radarr.Http/Authentication/AuthentikTokenValidationService.cs` — validates Authentik tokens via JWKS from `OidcAuthority`, audience matches `OidcClientId` or `arrstack`/per-service names, extracts groups from `OidcGroupsClaim` (default `groups`, array or comma-delimited), fail closed if unconfigured
- `src/Radarr.Http/Authentication/PermissionRequirement.cs`, `RequiresPermissionAttribute.cs`, `PermissionAuthorizationHandler.cs` — role-based authorization with policies `UI.Read/Add/Manage/Admin`

### HTTP wiring + endpoints
- `src/Radarr.Http/Authentication/AuthenticationBuilderExtensions.cs` — registers services/handler, JWT Bearer scheme `Bearer` for Radarr service tokens, adds authZ policies, enables PKCE + `offline_access` for OIDC, group-aware OIDC callback with fallback to `OidcUserIdentifier`
- `src/Radarr.Http/Authentication/AuthenticationController.cs` — `POST /api/auth/oidc/exchange` (AllowAnonymous, 10 req/min/IP), `GET /api/auth/me` (Bearer service token), `OidcExchangeRequest`
- `src/Radarr.Http/Radarr.Http.csproj` — added `Microsoft.AspNetCore.Authentication.JwtBearer`

### Config + fixes
- `src/NzbDrone.Common/Options/AuthOptions.cs`, `src/NzbDrone.Core/Configuration/ConfigFileProvider.cs` — added `OidcGroupsClaim` (default `groups`)
- `src/Radarr.Api.V3/Config/HostConfigController.cs` — exempt `AllowedHosts` requirement when `AuthenticationMethod == Oidc`

## Unified arrstack support
- Default issuer/fallback updated to `https://auth.piracyhub.win/application/o/arrstack/`
- Audience validation accepts configured clientId or `arrstack` (backward compatible with per-service `sonarr`/`radarr`/`lidarr`/`prowlarr`)
- No rebuild required when switching issuer/client/aud via HostConfig

## Verification
- Build: `dotnet build src/Radarr.sln -c Debug -p:Platform=Posix` — 0 warnings, 0 errors
- Endpoints confirmed present and wired
- Docker images built and pushed to GHCR
