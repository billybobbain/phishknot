# Running with Docker (for safe download mode)

When you set **NO_DOWNLOAD=0**, the script fetches phishing page HTML to detect brands/artists from page content. Running in Docker keeps that traffic isolated from your host (no browser, no JS — just `requests` + BeautifulSoup).

## Build

From the project folder:

```bash
docker build -t phishing-graph .
```

## Run (feed-only, no download)

Same as running locally; outputs go to the current directory:

```bash
docker run --rm -v "%cd%":/app -w /app phishing-graph
```

(On PowerShell you can use `-v "${PWD}:/app"`.)

## Run with download + co-occurrence only

- **NO_DOWNLOAD=0** — fetch page content (brand/artist from body).
- **CO_OCCURRENCE_ONLY=1** — keep only URLs where both at least one brand and one artist were found.
- **MAX_URLS** — cap how many URLs to fetch (e.g. 100 for a first run).

```bash
docker run --rm -v "%cd%":/app -w /app -e NO_DOWNLOAD=0 -e CO_OCCURRENCE_ONLY=1 -e MAX_URLS=100 phishing-graph
```

Outputs (`phishing_graph.gexf`, `co_occurrence.gexf`, `co_occurrence_urls.csv`, `url_brands.csv`, `url_history.db`, etc.) are written into your project folder via the mount.

## Optional env vars

- **SPOTIFY_CLIENT_ID** / **SPOTIFY_CLIENT_SECRET** — artist popularity (pass with `-e`).
- **URLHAUS_AUTH_KEY** — free key from https://auth.abuse.ch/ ; adds up to 1000 recent URLs per run (recommended; PhishTank registration is often disabled).
- **MAX_URLS** — when downloading, limit number of URLs to fetch per run.

## Preparation before first download run

1. Build the image and do a quick feed-only run so `url_history.db` is created and populated.
2. Set **MAX_URLS** to a small number (e.g. 50–100) for the first download run to check that co-occurrence and outputs look right.
3. Then increase **MAX_URLS** or use **MAX_URLS_FROM_HISTORY** and run again; history will keep growing.
