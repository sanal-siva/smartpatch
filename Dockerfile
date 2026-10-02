FROM python:3.11.16-slim-bookworm@sha256:a36c24f9cbdf4fd0f52d67f0823eeac19c2028c637cecc392d97f980d4fec56b
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /opt/smart-patch
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl git openssl gpgv \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 smart-patch && useradd --uid 10001 --gid smart-patch --no-create-home smart-patch
COPY requirements.txt requirements.lock pyproject.toml setup.py MANIFEST.in ./
RUN python -m pip install --no-cache-dir -r requirements.lock
COPY app ./app
COPY scripts/install-scanner.sh ./scripts/install-scanner.sh
RUN ./scripts/install-scanner.sh /usr/local/bin \
    && python -m pip install --no-cache-dir --no-deps . \
    && mkdir -p /var/lib/smart-patch && chown smart-patch:smart-patch /var/lib/smart-patch
USER 10001:10001
ENV HOST=0.0.0.0 PORT=8000 STATE_DIR=/var/lib/smart-patch \
    DATABASE_URL=sqlite:////var/lib/smart-patch/smart_patch.db \
    SCANNER_BINARY=/usr/local/bin/grype SCANNER_DB_DIR=/var/lib/smart-patch/grype-db
EXPOSE 8000
CMD ["python", "-m", "app.main"]
