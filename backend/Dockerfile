# Serrier backend — FastAPI + scanners. Scanners installeras i bilden så containern är
# fullt kapabel; saknas någon ändå degraderar produkten tyst (base.tillganglig).
FROM python:3.12-slim AS scanners
ARG GITLEAKS_VERSION=8.30.1
ARG OSV_VERSION=2.2.3
ADD https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz /tmp/gitleaks.tar.gz
ADD https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_linux_amd64 /usr/local/bin/osv-scanner
RUN tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks && chmod +x /usr/local/bin/gitleaks /usr/local/bin/osv-scanner

FROM python:3.12-slim
# uv för reproducerbar install; git behövs för gitleaks historik-läge.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/
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
