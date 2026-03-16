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
| `LASTFM_API_KEY`        | No       | *(from last.fm/api)*   | Last.fm API key. If set, top artists from Last.fm are merged with static artist keywords for matching. Cache refreshes every `LASTFM_CACHE_HOURS` (default 24). |
| `LASTFM_TOP_ARTISTS_LIMIT` | No    | `200`                  | Max number of top artists to fetch from Last.fm (default 200).                                    |
| `LASTFM_CACHE_HOURS`    | No       | `24`                   | Hours after which Last.fm cache is refreshed (default 24).                                      |
| `PHISHTANK_APP_KEY`      | No       | —                      | PhishTank app key (registration often disabled).                                                |
| `MAX_URLS_FROM_HISTORY`  | No       | —                      | Cap URLs per run from history (empty = no cap).                                                 |
| `PROCESS_LAST_DAYS`      | No       | —                      | Only use URLs seen in last N days (empty = all).                                                |


**Note:** The app listens on the port given by `PORT` (default 8080). In Railway’s **Settings → Networking**, if it asks “port your app is listening on”, enter **8080** so traffic is routed correctly.

---

## Setup checklist

1. Create a **Volume** and set mount path to `/data`.
2. Set **Variables**: at minimum `OUTPUT_DIR=/data` (so DB, cache, and images use the volume and persist).
3. **Start command:** Railway must run the **web app**, not the one-off script. The repo includes a **`railway.toml`** that sets `startCommand = "python app.py"` (config-as-code overrides the dashboard). If you removed it or use a custom config path, set Start Command in the service to:
   ```bash
   python app.py
   ```
   If Railway runs `phishing_brand_graph.py` instead, the pipeline runs once and exits, so the container stops and the site never responds.
4. Deploy. Open your Railway URL (root only, no path): e.g. `https://your-app.up.railway.app/` — that’s the page. No subpath (e.g. no `/app` or `/graph`). Hit `/health` to confirm the app is up (returns `ok`). The first pipeline run happens in the background; refresh `/` after a minute or two to see the image.

**If you see `can't open file '/app/app.py'`:** Use the **Dockerfile** so the image includes `app.py`. In **Settings → Build**, set the builder to **Dockerfile**. Leave **Root Directory** empty and redeploy. The container’s working directory doesn’t contain your code. In the Railway service go to **Settings**. Find **Root Directory** (or **Source** / **Watch Paths**). It must point at the directory that has `app.py` at the top level. If your repo root is the project (e.g. phishknot with `app.py` at root), leave Root Directory **empty**. If the project lives in a subfolder (e.g. `phishing_graph_prototype/`), set Root Directory to that folder name so the build and run context is that folder and `/app` contains `app.py`.

**If /health and / don’t respond (no file error):** In **Deployments → View logs**, look for `Listening on 0.0.0.0:XXXX`. If it’s missing, the app didn’t start. If it’s there but you get 502, in **Settings → Networking** set the port to that number (e.g. 8080).

**Data not persisting / "No data yet" on every restart / tiny graph:** Data and URL history are only kept if written to a **volume**. Otherwise they're lost on each deploy. (1) Add variable **OUTPUT_DIR** = **/data**. (2) Add a **Volume** to the service with mount path **/data**. (3) Redeploy. Check **/debug** — you should see `output_dir_set: true` and after a run `latest_png_exists: true`, `url_history_db_exists: true`. URL history then accumulates so the graph grows over time.

