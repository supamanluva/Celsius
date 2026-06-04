# Celsius — security scanner web app.
#
# Runs as root *inside the container* on purpose: nmap requires euid 0 for raw
# sockets (-sS) and OS fingerprinting (-O). Container-root is namespaced and is
# NOT host root, so OS-detect works from the web UI without a root-running
# service on the host. Use the default bridge network (the container reaches LAN
# targets outbound via NAT) — do not add --privileged.
FROM python:3.11-slim

# Tools the scanner shells out to, plus fetch helpers.
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*

# nuclei (pinned to the version this repo was developed against).
ARG NUCLEI_VERSION=3.8.0
RUN curl -fsSL -o /tmp/nuclei.zip \
        "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
    && unzip -j /tmp/nuclei.zip nuclei -d /usr/local/bin \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip

# uv — project + venv manager (build backend is uv_build).
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app
# Resolve + install dependencies (web extra) into /app/.venv. Source is needed
# because the project installs itself (console script `celsius`).
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY celsius ./celsius
RUN uv sync --frozen --extra web --no-dev

# App data (SQLite store, NVD/portscan caches, nuclei templates) lives under
# $HOME — mount a volume at /data to persist it across container rebuilds.
ENV HOME=/data \
    PATH="/app/.venv/bin:$PATH"
RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 8000
CMD ["celsius", "serve", "--host", "0.0.0.0", "--port", "8000"]
