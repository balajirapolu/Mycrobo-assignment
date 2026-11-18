FROM python:3.11-slim

WORKDIR /app
COPY . /app

RUN apt-get update && apt-get install --no-install-recommends -y curl gcc \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m appuser
USER appuser

CMD ["python", "main.py"]

