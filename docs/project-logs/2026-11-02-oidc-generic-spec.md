# OIDC-Generic Spec (remove Authentik-specific code)

Date: 2026-11-02
Applies to: Sonarr-oidc, Radarr fork, Prowlarr fork (all on `feature-oidc-app-auth`)
Goal: make the OIDC stack provider-neutral so any standards-compliant IdP works, configured entirely through settings. Current Authentik deployment must keep working via configuration values.

## Current Authentik-specific surface

1. `*/Http/Authentication/AuthentikTokenValidationService.cs`
   - `FallbackIssuer = "https://auth.piracyhub.win/application/o/arrstack/"`
   - `RequiredAudienceSubstring = "arrstack"` + substring fallback list (`arrstack/sonarr/radarr/lidarr/prowlarr/readarr`)
   - `|| arrstack` carve-out in the exact-match audience validator
2. `*/Http/Authentication/OidcGroupMapping.cs` — hardcoded `GroupToTier` dict (`pirates/homies/family/maintenance/authentik Admins`); Prowlarr variant is `IsAuthorized` binary
3. Already generic (keep): JWKS via discovery doc, `aud` = `OidcClientId` exact match, `OidcGroupsClaim` (default `groups`), JSON-array/comma/single group parsing, PKCE + `offline_access`, subject-first JIT provisioning

## Changes

### 1) Config-driven group mapping (replaces hardcoded dict)
- `AuthOptions`: add `OidcRoleMappings` (string). Format: `group=Role` pairs, `;`-separated, e.g. `homies=ReadOnly;family=AddSearch;maintenance=Manage;authentik Admins=Admin`. Role names parsed case-insensitively against the fork's role enum.
- `IConfigFileProvider` + impl: `OidcRoleMappings` (default `""`). Empty mapping = deny-all for group auth (fail closed); `OidcUserIdentifier` allowlist fallback stays as backcompat.
- `HostConfigResource` + mapper: expose `oidcRoleMappings` in GET/PUT `/api/v3/config/host` (V5 `GeneralSettings` where present).
- Frontend: settings field for the mapping (plain text area first; pretty UI is phase 2).
- Resolution: replace static `OidcGroupMapping.Resolve(groups)` with a mapping-aware resolver `Resolve(groups, mappings)`; highest role wins (Sonarr/Radarr). Prowlarr: any mapped group → authorized as Admin (binary preserved).
- Unmapped groups → deny (`403 insufficient_group` on `/exchange`, login redirect on callback). `pirates` blocking falls out naturally (just don't map it).

### 2) Rename + de-hardcode token validation
- Rename `AuthentikTokenValidationService` → `OidcTokenValidationService` (interface `IAuthentikTokenValidationService` → `IOidcTokenValidationService`, impl, DI registrations, tests) in one commit per fork.
- Delete `FallbackIssuer`/`Issuer`/`RequiredAudienceSubstring` consts and all substring audience logic.
- `GetIssuer()`: return `OidcAuthority` verbatim (trimmed of trailing `/` only for discovery-URL construction, not for `ValidIssuer` — validate against the configured string exactly as the IdP advertises it).
- Audience rule: if `OidcClientId` set → exact match only (drop the `arrstack` carve-out). If unset → fail closed, no validation attempted.
- Lazy-init the `ConfigurationManager` on first `ValidateAsync` (currently constructed with a dummy URL when unconfigured).

### 3) Fixtures + tests (Radarr: create from scratch)
Radarr has no OIDC test fixtures today (no `*Authentik*Fixture`, `OidcGroupMappingFixture`, `AuthenticationControllerOidcFixture`, or `UpsertOidcUserFixture` in any `*.Test` project), so this step creates rather than renames:
- New validation-service fixture for the renamed `OidcTokenValidationService`: exact-match audience accept/reject driven by test `OidcAuthority`/`OidcClientId` values (no hardcoded `arrstack` strings).
- New mapping-resolver fixture: exact match, case-insensitivity, highest-wins across `RadarrRole`, unmapped → null, empty mapping → null, malformed pair ignored.
- New `/exchange` + `/me` controller fixture: unchanged behavior from §1 contract, updated service names.
- `UpsertOidcUser` coverage for subject-first provisioning (no username auto-link).

### 4) Migration / rollout
- No DB migration (config-file/env only).
- Backward compatible by configuration: set `OidcAuthority=https://auth.piracyhub.win/application/o/arrstack/`, `OidcClientId=arrstack`, `OidcRoleMappings=homies=ReadOnly;family=AddSearch;maintenance=Manage;authentik Admins=Admin` and the current deployment behaves identically.
- Update README fork banner (generic OIDC wording) + write per-fork project log.

## Non-goals
- Upstream contribution, multi-IdP simultaneous support, pretty mapping UI, changing `/exchange`/`/me` contract or service-token format.

## Verification (per fork)
- `dotnet build <sln> -c Debug -p:Platform=Posix` 0 warnings/errors
- Auth test fixtures green
- Live check against Authentik with mapping expressed in config: T5 → 200, T1 → 403, unmapped → 403
- Commit separately: (a) config plumbing, (b) rename + de-hardcode, (c) fixtures, (d) docs

## Effort estimate
- Reference (Sonarr first): ~1 day (plumbing + rename + fixtures + UI field)
- Radarr/Prowlarr replication: ~0.5 day each (copy pattern; Prowlarr simpler, binary auth)
