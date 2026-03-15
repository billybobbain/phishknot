# Web app + pipeline. For Railway: build from this so app.py and phishing_brand_graph.py are in /app.
FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py phishing_brand_graph.py .

ENV PYTHONUNBUFFERED=1

# Railway: set OUTPUT_DIR=/data and mount a volume at /data. Start command can stay default (this CMD).
CMD ["python", "app.py"]
