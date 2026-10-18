FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 TGDRIVE_DATA=/data
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY tgdrive ./tgdrive
RUN pip install --no-cache-dir . \
 && useradd --create-home --uid 1000 tgdrive \
 && mkdir -p /data && chown tgdrive /data
USER tgdrive
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz')"
CMD ["tgdrive", "serve", "--host", "0.0.0.0", "--port", "8080"]
