# syntax=docker/dockerfile:1
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    FORUM_DB_PATH=/data/forum.db \
    PORT=8080

WORKDIR /app

# Install dependencies first (better layer caching)
COPY requirements.txt ./
RUN python -m pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . ./

# Create data dir for the SQLite database
RUN mkdir -p /data
VOLUME [ "/data" ]

EXPOSE 8080

# Run with gunicorn (production-ready WSGI server)
CMD ["gunicorn", "-b", "0.0.0.0:8080", "app:app"]
