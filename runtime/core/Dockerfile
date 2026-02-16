# RoboZilla Core Runtime image (build mode)
#
# This image is self-contained for `docker compose build` with `build: .` from
# `runtime/core/` by bundling a snapshot of constitutional schemas + registry
# documents under `bundle/`.
#
# It does NOT bundle secrets or any live infrastructure.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Create the non-root runtime user/group with UID/GID 986 (compatible with host mounts).
RUN addgroup --gid 986 robozilla \
    && adduser --disabled-password --gecos "" --uid 986 --gid 986 --shell /bin/false robozilla

WORKDIR /app

# Install dependencies first for better layer caching.
COPY requirements.txt /app/requirements.txt
RUN python -m pip install --no-cache-dir -r /app/requirements.txt

# Copy runtime source (this build context is runtime/core/).
COPY . /app
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Persistent directories (mounted by docker-compose).
RUN mkdir -p /data /logs \
    && chown -R 986:986 /data /logs /app

USER 986:986

EXPOSE 8787

# ENTRYPOINT runs uvicorn serving api.main:app.
# Config is generated at container start so DB_PATH / API_* env vars can be honored without changing runtime logic.
ENTRYPOINT ["/app/entrypoint.sh"]
