# Railway deployment

Deploy as a **web service**. Add a **volume**, set its mount path to `/data`, then add the variables below. The app runs the pipeline on a schedule and serves graph images from the volume.

**Deploy from local (no GitHub needed):** Install the [Railway CLI](https://docs.railway.com/guides/cli), then from the project directory run `railway login`, `railway link` (to create or link a project), and `railway up`. Railway builds and deploys from your local files. You can also connect a GitHub repo in the dashboard for automatic deploys on push.

---

## Environment variables (Railway)

Add these in the Railway dashboard under your service **Variables**.

| Variable | Required | Example | Description |
|----------|----------|---------|-------------|
| `OUTPUT_DIR` | **Yes** | `/data` | Volume mount path. All data (DB, cache, images) is written here so it persists across restarts. |
| `REFRESH_INTERVAL_HOURS` | No | `12` | How often to run the pipeline (hours). Default: 12. |
| `MAX_IMAGE_NODES` | No | `200` | Max nodes in rendered PNG (smaller = more readable). Default: 200. |
| `URLHAUS_AUTH_KEY` | No | *(from auth.abuse.ch)* | Free key for more URLs (up to 1000 per run). |
| `NO_DOWNLOAD` | No | `true` | `true` = feed-only (safe). Set `0` to fetch page content (run in container). Default: true. |
| `CO_OCCURRENCE_ONLY` | No | `0` | Set `1` to keep only URLs with both a brand and an artist. Default: 0. |
| `SPOTIFY_CLIENT_ID` | No | — | Spotify API client ID (artist popularity). |
| `SPOTIFY_CLIENT_SECRET` | No | — | Spotify API client secret. |
| `PHISHTANK_APP_KEY` | No | — | PhishTank app key (registration often disabled). |
| `MAX_URLS_FROM_HISTORY` | No | — | Cap URLs per run from history (empty = no cap). |
| `PROCESS_LAST_DAYS` | No | — | Only use URLs seen in last N days (empty = all). |

**Note:** `PORT` is set by Railway; do not override it unless needed.

---

## Setup checklist

1. Create a **Volume** and set mount path to `/data`.
2. Set **Variables**: at minimum `OUTPUT_DIR=/data`.
3. **Start command:** `python app.py` (or in Procfile: `web: python app.py`).
4. Deploy. The first run may take a few minutes; then open `/` to see the latest graph image.
