FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PORT=8080
EXPOSE 8080

SHELL ["/bin/sh", "-c"]
CMD gunicorn --bind "0.0.0.0:${PORT}" --workers 1 --threads 4 app:app
