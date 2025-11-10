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
CMD ["gunicorn","-w","4","-k","gthread","--threads","4","--timeout","120","--max-requests","2000","--max-requests-jitter","200","--access-logfile","-","-b","0.0.0.0:8080","app:app"]
