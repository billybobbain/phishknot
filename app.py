"""
Web app for phishing graph: serves latest graph images and runs the pipeline on a schedule.
Set OUTPUT_DIR to the Railway volume path (e.g. /data) so data and images persist.
"""
import json
import os
import re
import threading
import time
from pathlib import Path

from flask import Flask, send_from_directory, abort, jsonify

# Output dir for pipeline and images (must be set before importing phishing_brand_graph in the worker)
OUTPUT_DIR = os.environ.get("OUTPUT_DIR") or os.environ.get("RAILWAY_VOLUME_MOUNT_PATH", "")
if OUTPUT_DIR:
    os.environ.setdefault("OUTPUT_DIR", OUTPUT_DIR)
else:
    # So pipeline and any later imports see it if Railway injects it later
    os.environ.setdefault("OUTPUT_DIR", "")
DATA_DIR = Path(OUTPUT_DIR).resolve() if OUTPUT_DIR else Path(__file__).resolve().parent
IMAGES_DIR = DATA_DIR / "output"

app = Flask(__name__)

# Safe filename: alphanumeric, underscore, hyphen, one dot
SAFE_FILENAME = re.compile(r"^[a-zA-Z0-9_.-]+$")

STATS_FILE = IMAGES_DIR / "stats.json"


def _read_stats():
    """Read last pipeline stats (display_nodes, full_nodes, full_edges, brands_count, artists_count)."""
    if not STATS_FILE.is_file():
        return None
    try:
        with open(STATS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def run_pipeline():
    """Run the full pipeline (feeds, history, graph, images)."""
    from phishing_brand_graph import main
    main()


def scheduler_loop():
    """Background: run pipeline every REFRESH_INTERVAL_HOURS. Sleep first so only startup_pipeline_once runs at startup."""
    interval_hours = float(os.environ.get("REFRESH_INTERVAL_HOURS", "12"))
    interval_sec = max(60, interval_hours * 3600)
    time.sleep(interval_sec)
    while True:
        try:
            run_pipeline()
        except Exception as e:
            print(f"Pipeline error: {e}")
        time.sleep(interval_sec)


@app.route("/health")
def health():
    """Simple health check so Railway can verify the app is up (returns 200 immediately)."""
    return "ok", 200


@app.route("/debug")
def debug():
    """Persistence check: confirm OUTPUT_DIR is set and volume files exist. Use to debug data loss on restart."""
    latest = IMAGES_DIR / "latest.png"
    history_db = DATA_DIR / "url_history.db"
    out = {
        "output_dir_set": bool(OUTPUT_DIR),
        "output_dir": OUTPUT_DIR or "(not set — data will not persist across restarts)",
        "data_dir": str(DATA_DIR),
        "images_dir": str(IMAGES_DIR),
        "latest_png_exists": latest.is_file(),
        "url_history_db_exists": history_db.is_file(),
    }
    stats = _read_stats()
    if stats is not None:
        out["graph_stats"] = stats
        out["graph_summary"] = (
            f"Display: {stats.get('display_nodes', 0)} nodes "
            f"({stats.get('brands_count', 0)} brand, {stats.get('artists_count', 0)} artist). "
            f"Full graph: {stats.get('full_nodes', 0)} nodes, {stats.get('full_edges', 0)} edges."
        )
    return jsonify(out)


@app.route("/")
def index():
    """Show latest graph image and list recent timestamped images. Mobile-friendly viewport and CSS."""
    IMAGES_DIR.mkdir(parents=True, exist_ok=True)
    latest = IMAGES_DIR / "latest.png"
    history = sorted(IMAGES_DIR.glob("graph_*.png"), key=lambda p: p.stat().st_mtime, reverse=True)
    lines = [
        "<!DOCTYPE html><html lang='en'><head>",
        "<meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1'>",
        "<title>Phishing graph</title>",
        "<style>",
        "body { margin: 0; padding: 1rem; font-family: system-ui, sans-serif; font-size: 1rem; line-height: 1.5; color: #333; max-width: 900px; margin-left: auto; margin-right: auto; box-sizing: border-box; }",
        "* { box-sizing: border-box; }",
        "h1 { font-size: clamp(1.25rem, 4vw, 1.75rem); margin-top: 0; }",
        "img { max-width: 100%; height: auto; display: block; }",
        "a { display: inline-block; min-height: 44px; line-height: 44px; padding: 0 0.5rem; color: #0066cc; text-decoration: none; }",
        "a:hover, a:focus { text-decoration: underline; }",
        "ul { padding-left: 1.25rem; margin: 0.5rem 0; }",
        "li { margin: 0.5rem 0; }",
        "li a { min-height: 44px; line-height: 44px; }",
        ".summary { color: #555; font-size: 0.95rem; }",
        "</style>",
        "</head><body>",
        "<main>",
        "<h1>Phishing graph</h1>",
    ]
    if latest.exists():
        lines.append("<section><p><strong>Latest</strong> (brands &amp; artists only)</p>")
        lines.append("<img src='/images/latest.png' alt='Latest graph' />")
        stats = _read_stats()
        if stats is not None:
            summary = (
                f"Display: {stats.get('display_nodes', 0)} nodes "
                f"({stats.get('brands_count', 0)} brand, {stats.get('artists_count', 0)} artist). "
                f"Full graph: {stats.get('full_nodes', 0)} nodes, {stats.get('full_edges', 0)} edges."
            )
            lines.append(f"<p class='summary'>{summary}</p>")
        lines.append("<p><a href='/graph/interactive'>Interactive graph</a></p></section>")
    else:
        lines.append("<p>No data yet. The first pipeline run will create an image.</p>")
    if history:
        lines.append("<section><p><strong>Recent</strong></p><ul>")
        for p in history[:5]:
            name = p.name
            if SAFE_FILENAME.match(name):
                lines.append(f"<li><a href='/images/{name}'>{name}</a></li>")
        lines.append("</ul></section>")
    lines.append("</main></body></html>")
    return "\n".join(lines)


@app.route("/graph/embed")
def serve_graph_embed():
    """Serve the raw Plotly HTML (for iframe in wrapper)."""
    path = IMAGES_DIR / "graph_interactive.html"
    if not path.is_file():
        abort(404)
    return send_from_directory(IMAGES_DIR, "graph_interactive.html", mimetype="text/html")


@app.route("/graph/interactive")
def serve_interactive_graph():
    """Serve a responsive wrapper page that embeds the interactive graph (mobile-friendly)."""
    path = IMAGES_DIR / "graph_interactive.html"
    if not path.is_file():
        abort(404)
    wrapper = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Phishing graph (interactive)</title>
<style>
body { margin: 0; padding: 0; height: 100vh; display: flex; flex-direction: column; }
header { flex: 0 0 auto; padding: 0.5rem 1rem; background: #f5f5f5; border-bottom: 1px solid #ddd; font-family: system-ui, sans-serif; font-size: 0.9rem; }
header a { color: #0066cc; text-decoration: none; min-height: 44px; line-height: 44px; display: inline-block; }
header a:hover { text-decoration: underline; }
.graph-container { flex: 1 1 auto; min-height: 0; width: 100%; }
.graph-container iframe { width: 100%; height: 100%; border: none; display: block; }
</style>
</head>
<body>
<header><a href="/">&larr; Back to graph</a></header>
<div class="graph-container"><iframe src="/graph/embed" title="Interactive phishing graph"></iframe></div>
</body>
</html>"""
    return wrapper, 200, {"Content-Type": "text/html; charset=utf-8"}


@app.route("/images/<filename>")
def serve_image(filename):
    """Serve an image from the output directory. Restrict filename to avoid path traversal."""
    if not SAFE_FILENAME.match(filename):
        abort(404)
    path = IMAGES_DIR / filename
    if not path.is_file():
        abort(404)
    return send_from_directory(IMAGES_DIR, filename, mimetype="image/png")


def startup_pipeline_once():
    """Run pipeline once in the background so the server can respond immediately."""
    if OUTPUT_DIR:
        print("Running pipeline once on startup (background)...")
        try:
            run_pipeline()
        except Exception as e:
            print(f"Startup pipeline error: {e}")


if __name__ == "__main__":
    if not OUTPUT_DIR:
        print("WARNING: OUTPUT_DIR is not set. Data (DB, images) is written to the container and is LOST on restart. Set OUTPUT_DIR=/data and mount a volume at /data.")
    # Start Flask immediately so Railway gets 200 (no 502). Run first pipeline in background.
    t = threading.Thread(target=startup_pipeline_once, daemon=True)
    t.start()
    thread = threading.Thread(target=scheduler_loop, daemon=True)
    thread.start()
    port = int(os.environ.get("PORT", "8080"))
    print(f"Listening on 0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port)
