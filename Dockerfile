FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.10.4 /uv /bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    PATH="/app/.venv/bin:$PATH"

WORKDIR /app

# Dependencies first, in their own layer, so a code change does not reinstall them.
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev --no-install-project

COPY README.md ./
COPY src ./src
RUN uv sync --locked --no-dev --no-editable

RUN useradd --system --no-create-home --uid 10001 coordinator
USER coordinator

EXPOSE 8000
CMD ["uvicorn", "coordinator.main:app", "--host", "0.0.0.0", "--port", "8000"]
