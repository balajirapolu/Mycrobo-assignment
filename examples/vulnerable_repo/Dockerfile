FROM python:latest

WORKDIR /app
COPY . /app

RUN apt-get update && apt-get install -y curl gcc

CMD ["python", "main.py"]
