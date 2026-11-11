# Serrier backend — FastAPI + scanners. Scanners installeras i bilden så containern är
# fullt kapabel; saknas någon ändå degraderar produkten tyst (base.tillganglig).
#
# Supply chain (G): varje extern binär är PINNAD till version OCH verifierad mot en
# SHA256-checksum FÖRE användning. Hasharna nedan är framtagna så här (aldrig uppfunna):
#   - gitleaks: ur den officiella gitleaks_8.30.1_checksums.txt i releasen.
#   - osv-scanner: osv publicerar INGEN checksums-fil för v2.2.3, så hashen härleddes
#     genom att hämta den TLS-verifierade artefakten från release-URL:en och `sha256sum`:a
#     den. Byt version → byt hash (hämta + verifiera på nytt). Digest-pinning av basbilder
#     är den starkare formen (se security-limitations.md).
FROM python:3.12-slim AS scanners
ARG GITLEAKS_VERSION=8.30.1
ARG OSV_VERSION=2.2.3
ARG GITLEAKS_SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
ARG OSV_SHA256=8cdb138b36cdb9c99c455cafb32a1c83e1823448dc00e1c8ab9afe474a5e93f0
ADD https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz /tmp/gitleaks.tar.gz
ADD https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_linux_amd64 /usr/local/bin/osv-scanner
# Verifiera FÖRE extraktion/användning — fail-closed om en hash inte stämmer.
RUN echo "${GITLEAKS_SHA256}  /tmp/gitleaks.tar.gz" | sha256sum -c - \
    && echo "${OSV_SHA256}  /usr/local/bin/osv-scanner" | sha256sum -c - \
    && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks /usr/local/bin/osv-scanner

FROM python:3.12-slim
# uv för reproducerbar install — PINNAD till en version (ej :latest). Digest-pinning
# (uv@sha256:…) är starkare och rekommenderas för release; se security-limitations.md.
COPY --from=ghcr.io/astral-sh/uv:0.5.14 /uv /uvx /usr/local/bin/
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*
COPY --from=scanners /usr/local/bin/gitleaks /usr/local/bin/osv-scanner /usr/local/bin/

WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy PATH="/app/.venv/bin:$PATH"
# Lås-lagret först (cache): deps ändras sällan, koden ofta.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --extra postgres --no-install-project
# semgrep separat (tungt, men ger modul A full täckning i containern).
RUN uv pip install semgrep==1.142.0
COPY . .
RUN uv sync --frozen --no-dev --extra postgres

ENV SERRIER_DB_URL=sqlite:////data/serrier.db SERRIER_SKIP_CREATE_ALL=1
EXPOSE 8000
ENTRYPOINT ["/app/docker-entrypoint.sh"]
