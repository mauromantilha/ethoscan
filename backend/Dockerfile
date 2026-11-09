FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates passwd \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# API roda non-root; o worker sobrescreve para root no compose (raw sockets).
RUN mkdir -p /app/artifacts \
    && useradd --create-home --uid 1000 app \
    && chown -R app:app /app
USER app

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
