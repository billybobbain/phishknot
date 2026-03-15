# Run the phishing graph script in an isolated container when using NO_DOWNLOAD=0.
# No browser or JS execution — only HTTP requests + HTML parsing.
FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY phishing_brand_graph.py .

ENV PYTHONUNBUFFERED=1

# Mount your project dir so the script sees its folder and writes outputs there:
#   docker run --rm -v C:\Users\billy\phishing_graph_prototype:/app -w /app -e NO_DOWNLOAD=0 -e CO_OCCURRENCE_ONLY=1 -e MAX_URLS=100 your-image
# Then url_history.db, *.gexf, *.csv are written to the host folder.
CMD ["python", "phishing_brand_graph.py"]
