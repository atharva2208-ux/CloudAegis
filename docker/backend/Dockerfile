# syntax=docker/dockerfile:1.7
# CloudAegis API + scan worker image. Build context: repository root.
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /srv

# Dependencies first for layer caching.
COPY apps/backend/requirements.txt apps/backend/requirements.txt
RUN pip install -r apps/backend/requirements.txt

# The security engine is an installable package shared with the API.
COPY packages/security-engine packages/security-engine
RUN pip install ./packages/security-engine

COPY apps/backend apps/backend
COPY docker/backend/entrypoint.sh /usr/local/bin/cloudaegis-entrypoint
RUN chmod 0755 /usr/local/bin/cloudaegis-entrypoint \
    && rm -f apps/backend/.env \
    && useradd --system --uid 10001 --home /srv cloudaegis \
    && chown -R cloudaegis /srv

USER cloudaegis
WORKDIR /srv/apps/backend
EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=3s --start-period=30s --retries=5 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health/live', timeout=2).status == 200 else 1)" || exit 1

ENTRYPOINT ["cloudaegis-entrypoint"]
CMD ["api"]
