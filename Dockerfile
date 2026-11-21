FROM python:3.13-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY quickpool ./quickpool
RUN pip install --no-cache-dir . && useradd --create-home --uid 10001 quickpool \
    && mkdir -p /app/data && chown -R quickpool:quickpool /app
USER quickpool
ENV QUICKPOOL_HOST=0.0.0.0 QUICKPOOL_PORT=8045 QUICKPOOL_DATA_DIR=/app/data PYTHONUNBUFFERED=1
VOLUME ["/app/data"]
EXPOSE 8045
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8045/healthz',timeout=2)"
CMD ["python", "-m", "quickpool"]

