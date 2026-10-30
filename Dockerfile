# Radarr (OIDC fork) runtime image — framework-dependent .NET 10 + prebuilt UI.
# Build: docker build -t ghcr.io/wetw0rks-c0ding/radarr-oidc:<tag> .

# ---------- Frontend ----------
FROM node:24-bookworm-slim AS frontend
WORKDIR /src
COPY package.json yarn.lock .yarnrc tsconfig.json ./
COPY frontend ./frontend
RUN yarn install --frozen-lockfile --network-timeout 600000 --network-concurrency 4 --network-retry-delay 5000 \
    && yarn build

# ---------- Backend (mirrors CI: msbuild PublishAllRids, self-contained) ----------
FROM mcr.microsoft.com/dotnet/sdk:10.0.403 AS backend
WORKDIR /src
COPY global.json ./
COPY Logo ./Logo
COPY src ./src
RUN dotnet msbuild -restore src/Radarr.sln \
        -p:SelfContained=true \
        -p:Configuration=Release \
        -p:Platform=Posix \
        -p:RuntimeIdentifiers=linux-x64 \
        -p:EnableWindowsTargeting=true \
        -p:TreatWarningsAsErrors=false \
        -t:PublishAllRids \
    && mkdir -p /app/publish \
    && cp -r _output/net10.0/linux-x64/publish/* /app/publish/
# NOTE: TreatWarningsAsErrors=false is Docker-only. Newer SDK analyzer
# versions flag pre-existing upstream code; CI (pinned SDK) remains the strict gate.
COPY --from=frontend /src/_output/UI /app/publish/UI

# ---------- Runtime ----------
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
LABEL org.opencontainers.image.title="radarr-oidc" \
      org.opencontainers.image.description="Radarr (Servarr fork) with Authentik OIDC group-based authorization and Seekarr mobile app-auth" \
      org.opencontainers.image.source="https://github.com/wetw0rks-c0ding/Radarr"
ENV DEBIAN_FRONTEND=noninteractive \
    DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=false \
    TZ=Etc/UTC
RUN apt-get update \
    && apt-get install -y --no-install-recommends sqlite3 mediainfo tzdata \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=backend /app/publish ./
EXPOSE 7878
VOLUME ["/config"]
ENTRYPOINT ["/app/Radarr", "-nobrowser", "-data=/config"]
