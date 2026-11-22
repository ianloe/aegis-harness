FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src ./src
COPY config ./config
COPY policies ./policies

RUN pip install --no-cache-dir -e .

EXPOSE 8787

CMD ["harness", "dashboard", "--host", "0.0.0.0", "--port", "8787"]
