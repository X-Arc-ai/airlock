# Airlock — on-device firewall for AI agents.
#
# Arch-neutral: python:3.12-slim builds on x86_64 (Hetzner) and arm64 (Apple M1)
# with no changes. The image carries the Airlock app + screening proxy only.
#
# Gemma runs OUTSIDE the container in Ollama (it needs the host GPU/Metal). The
# container reaches it over the network — point AIRLOCK_MODEL_URL at the host:
#
#   # Ollama already running on the host at :11434
#   docker build -t airlock .
#   docker run --rm -it \
#     -e AIRLOCK_MODEL_URL=http://host.docker.internal:11434 \
#     --add-host host.docker.internal:host-gateway \
#     -p 8787:8787 -p 8899:8899 \
#     airlock ui --no-open
#
# Then open the event feed at http://127.0.0.1:8787.
FROM python:3.12-slim

# mitmproxy needs a CA store; tini gives us clean signal handling for the proxy.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tini \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    AIRLOCK_MODEL=gemma3:12b-it-qat \
    AIRLOCK_MODEL_URL=http://host.docker.internal:11434 \
    AIRLOCK_DB=/data/airlock.db \
    AIRLOCK_UI_PORT=8787 \
    AIRLOCK_PROXY_PORT=8899

WORKDIR /app

# Dependency layer first for cache-friendly rebuilds. The pywebview / rumps
# requirements are macOS-only markers, so nothing GUI is pulled into the image.
COPY requirements.txt ./
RUN python -m pip install --upgrade pip \
    && python -m pip install -r requirements.txt

# App source.
COPY airlock ./airlock
COPY corpus ./corpus
COPY bench ./bench
COPY CONTRACTS.md README.md ./

# Ledger lives on a volume so the trust history survives container restarts.
RUN mkdir -p /data
VOLUME ["/data"]

# UI event feed + screening proxy.
EXPOSE 8787 8899

ENTRYPOINT ["tini", "--", "python", "-m", "airlock"]
CMD ["ui", "--no-open"]
