# Railway deployment

Deploy as a **web service**. Add a **volume**, set its mount path to `/data`, then add the variables below. The app runs the pipeline on a schedule and serves graph images from the volume.

**Deploy from local (no GitHub needed):** Install the [Railway CLI](https://docs.railway.com/guides/cli), then from the project directory run `railway login`, `railway link` (to create or link a project), and `railway up`. Railway builds and deploys from your local files. You can also connect a GitHub repo in the dashboard for automatic deploys on push.

---

## Environment variables (Railway)

Add these in the Railway dashboard under your service **Variables**. If you use **shared variables** (project-level), you still have to **assign** them to this service so the container sees them.


| Variable                 | Required | Example                | Description                                                                                     |
| ------------------------ | -------- | ---------------------- | ----------------------------------------------------------------------------------------------- |
| `OUTPUT_DIR`             | **Yes**  | `/data`                | Volume mount path. All data (DB, cache, images) is written here so it persists across restarts. |
| `REFRESH_INTERVAL_HOURS` | No       | `12`                   | How often to run the pipeline (hours). Default: 12.                                             |
| `MAX_IMAGE_NODES`        | No       | `200`                  | Max nodes in rendered PNG (smaller = more readable). Default: 200.                              |
| `URLHAUS_AUTH_KEY`       | No       | *(from auth.abuse.ch)* | Free key for more URLs (up to 1000 per run).                                                    |
| `NO_DOWNLOAD`            | No       | `true`                 | `true` = feed-only (safe). Set `0` to fetch page content (run in container). Default: true.     |
| `CO_OCCURRENCE_ONLY`     | No       | `0`                    | Set `1` to keep only URLs with both a brand and an artist. Default: 0.                          |
| `SPOTIFY_CLIENT_ID`      | No       | —                      | Spotify API client ID (artist popularity).                                                      |
| `SPOTIFY_CLIENT_SECRET`  | No       | —                      | Spotify API client secret.                                                                      |
| `PHISHTANK_APP_KEY`      | No       | —                      | PhishTank app key (registration often disabled).                                                |
| `MAX_URLS_FROM_HISTORY`  | No       | —                      | Cap URLs per run from history (empty = no cap).                                                 |
| `PROCESS_LAST_DAYS`      | No       | —                      | Only use URLs seen in last N days (empty = all).                                                |


**Note:** The app listens on the port given by `PORT` (default 8080). In Railway’s **Settings → Networking**, if it asks “port your app is listening on”, enter **8080** so traffic is routed correctly.

---

## Setup checklist

1. Create a **Volume** and set mount path to `/data`.
2. Set **Variables**: at minimum `OUTPUT_DIR=/data` (so DB, cache, and images use the volume and persist).
3. **Start command:** Railway must run the **web app**, not the one-off script. Set the start command to:
   ```bash
   python app.py
   ```
   (If you use a Procfile, the `web` process should be `python app.py`.) If Railway runs `phishing_brand_graph.py` instead, the pipeline runs once and exits, so the container stops and the site never responds.
4. Deploy. Open your Railway URL (root only, no path): e.g. `https://your-app.up.railway.app/` — that’s the page. No subpath (e.g. no `/app` or `/graph`). To confirm the app is up before images exist, hit `https://your-app.up.railway.app/health` (returns `ok`). The first pipeline run happens in the background; refresh `/` after a minute or two to see the image.

