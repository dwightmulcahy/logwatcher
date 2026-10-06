FROM python:3.12-slim

ARG VERSION=dev
ENV LOGWATCH_VERSION=${VERSION} \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY logwatch.py .

LABEL org.opencontainers.image.title="logwatcher" \
      org.opencontainers.image.description="Nightly Docker log analyzer with rule checks, bot detection and Claude-written HTML email reports" \
      org.opencontainers.image.source="https://github.com/dwightmulcahy/logwatcher" \
      org.opencontainers.image.version="${VERSION}"

# Runs as root: it needs the mounted /var/run/docker.sock to read container logs.
VOLUME ["/data"]
CMD ["python", "/app/logwatch.py"]
