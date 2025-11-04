FROM python:3.11-slim
WORKDIR /app

# System deps (optional but nice to have)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all source (make sure .dockerignore is sane)
COPY . .

# Cloud Run provides PORT; bind gunicorn to it
ENV PORT=8080
CMD ["gunicorn", "-w", "2", "-k", "gthread", "-b", "0.0.0.0:8080", "app:app"]
