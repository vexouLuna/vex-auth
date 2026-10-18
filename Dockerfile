# syntax=docker/dockerfile:1.27

# ── Build: install the locked dependency set into a venv with uv ───────────────
FROM python:3.13-slim AS build
COPY --from=ghcr.io/astral-sh/uv:0.12 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /app
# Dependencies first, so a source-only change doesn't re-resolve or re-download them.
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --locked --no-dev --no-install-project
COPY src ./src
RUN uv sync --locked --no-dev --no-editable

# ── Runtime ───────────────────────────────────────────────────────────────────
FROM python:3.13-slim AS runtime
ENV PATH="/opt/venv/bin:$PATH" PYTHONUNBUFFERED=1 AUTH_PORT=8090
RUN groupadd --system --gid 10001 auth && useradd --system --uid 10001 --gid auth --no-create-home auth
COPY --from=build /opt/venv /opt/venv
USER auth
EXPOSE 8090
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8090/healthz', timeout=4).status == 200 else 1)"]
ENTRYPOINT ["vex-auth"]
CMD ["serve"]
