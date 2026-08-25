# syntax=docker/dockerfile:1

# ─────────────────────────────────────────────────────────────────────────────
# Stage 1 — build the React dashboard.
# The API is served from the same container, so the bundle uses a same-origin
# (empty) base URL rather than a hard-coded host.
# ─────────────────────────────────────────────────────────────────────────────
FROM node:20-alpine AS frontend
WORKDIR /app/frontend

# Install against the lockfile first so this layer caches on dependency changes.
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
ENV REACT_APP_API_URL=""
ENV CI=true
RUN npm run build

# ─────────────────────────────────────────────────────────────────────────────
# Stage 2 — the FastAPI backend, serving the API and the built dashboard.
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./
COPY --from=frontend /app/frontend/build ./static

# Serve the dashboard from the same origin as the API (see main._mount_spa).
ENV AGT_STATIC_DIR=/app/static
# Bind all interfaces *inside* the container; the ingress controls exposure.
ENV AGT_HOST=0.0.0.0

# The listening port must match the Container Apps targetPort.
EXPOSE 8000

# Run as an unprivileged user (least privilege).
RUN useradd --create-home --uid 10001 appuser \
    && chown -R appuser:appuser /app
USER appuser

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
