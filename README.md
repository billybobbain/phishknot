# Phishing graph

Explores phishing URLs linked to brands and artists: pulls from OpenPhish (and optional URLhaus), keeps URL history in SQLite, builds a graph, and can serve rendered images on a schedule.

- **Run locally:** `python phishing_brand_graph.py` (writes GEXF, CSV, and optionally images to the current directory).
- **Web + auto-refresh:** See [RAILWAY.md](RAILWAY.md) for deploying to Railway (env vars, volume, `app.py`).
- **Docker (safe download mode):** See [DOCKER.md](DOCKER.md).
- **Gephi:** See [GEPHI.md](GEPHI.md) for opening the GEXF and reading labels.
- **Student-friendly write-up:** See [SPRING_BREAK.md](SPRING_BREAK.md) (“what I did over spring break” style overview).

## Live Demo URLs

- Main static page: [https://phishknot-production.up.railway.app/](https://phishknot-production.up.railway.app/)
- Interactive page: [https://phishknot-production.up.railway.app/graph/interactive](https://phishknot-production.up.railway.app/graph/interactive)

## Responsible Use & Safety

- This project is for defensive research and education.
- Do not use it to build phishing kits, steal credentials, or target real users.
- Prefer safe mode (`NO_DOWNLOAD=true`) unless you understand and accept the risks of fetching live phishing pages.
- Use an isolated environment (container/VM), keep dependencies updated, and avoid opening suspicious URLs directly in a normal browser profile.

No secrets in the repo; set API keys and `OUTPUT_DIR` via environment variables (see RAILWAY.md).
