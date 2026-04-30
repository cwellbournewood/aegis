FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
COPY aegis ./aegis
COPY README.md LICENSE ./

RUN pip install --upgrade pip \
    && pip install .

# Run as non-root for least-privilege.
RUN useradd --uid 65532 --create-home --shell /usr/sbin/nologin aegis \
    && mkdir -p /var/aegis \
    && chown -R aegis:aegis /var/aegis /app
USER aegis

ENV AEGIS_POLICY_PATH=/app/aegis/policies/default.yaml

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl --fail --silent http://127.0.0.1:8080/aegis/health || exit 1

CMD ["aegis", "up", "--host", "0.0.0.0", "--port", "8080"]
