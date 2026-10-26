# Frontend
FROM node:24-alpine AS frontend
WORKDIR /frontend
COPY frontend/package.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

# Backend + fertiges Frontend
FROM python:3.13-slim
COPY --from=ghcr.io/astral-sh/uv:0.12.8 /uv /usr/local/bin/uv
ENV UV_PYTHON_DOWNLOADS=never
WORKDIR /app

COPY backend/pyproject.toml backend/uv.lock backend/.python-version ./
RUN uv sync --frozen --no-dev --no-install-project

COPY backend/src ./src
RUN uv sync --frozen --no-dev

COPY --from=frontend /frontend/dist ./static
ENV STATIC_DIR=/app/static

EXPOSE 8000
CMD ["sh", "-c", "uv run --no-sync python -m all_seeing_eye.database.models && uv run --no-sync uvicorn all_seeing_eye.api.main:app --host 0.0.0.0 --port 8000"]