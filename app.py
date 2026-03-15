"""
Web app for phishing graph: serves latest graph images and runs the pipeline on a schedule.
Set OUTPUT_DIR to the Railway volume path (e.g. /data) so data and images persist.
"""
import os
import re
import threading
import time
from pathlib import Path

from flask import Flask, send_from_directory, abort

# Output dir for pipeline and images (must be set before importing phishing_brand_graph in the worker)
OUTPUT_DIR = os.environ.get("OUTPUT_DIR") or os.environ.get("RAILWAY_VOLUME_MOUNT_PATH", "")
if OUTPUT_DIR:
    os.environ.setdefault("OUTPUT_DIR", OUTPUT_DIR)
DATA_DIR = Path(OUTPUT_DIR).resolve() if OUTPUT_DIR else Path(__file__).resolve().parent
IMAGES_DIR = DATA_DIR / "output"

app = Flask(__name__)

# Safe filename: alphanumeric, underscore, hyphen, one dot
SAFE_FILENAME = re.compile(r"^[a-zA-Z0-9_.-]+$")


def run_pipeline():
    """Run the full pipeline (feeds, history, graph, images)."""
    from phishing_brand_graph import main
    main()


def scheduler_loop():
    """Background: run pipeline every REFRESH_INTERVAL_HOURS."""
    interval_hours = float(os.environ.get("REFRESH_INTERVAL_HOURS", "12"))
    interval_sec = max(60, interval_hours * 3600)
    while True:
        try:
            run_pipeline()
        except Exception as e:
            print(f"Pipeline error: {e}")
        time.sleep(interval_sec)


@app.route("/")
def index():
    """Show latest graph image and list recent timestamped images."""
    IMAGES_DIR.mkdir(parents=True, exist_ok=True)
    latest = IMAGES_DIR / "latest.png"
    history = sorted(IMAGES_DIR.glob("graph_*.png"), key=lambda p: p.stat().st_mtime, reverse=True)
    lines = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Phishing graph</title></head><body>",
        "<h1>Phishing graph</h1>",
    ]
    if latest.exists():
        lines.append(f"<p><strong>Latest</strong></p><img src='/images/latest.png' alt='Latest graph' style='max-width:100%;' />")
    else:
        lines.append("<p>No data yet. The first pipeline run will create an image.</p>")
    if history:
        lines.append("<p><strong>Recent</strong></p><ul>")
        for p in history[:5]:
            name = p.name
            if SAFE_FILENAME.match(name):
                lines.append(f"<li><a href='/images/{name}'>{name}</a></li>")
        lines.append("</ul>")
    lines.append("</body></html>")
    return "\n".join(lines)


@app.route("/images/<filename>")
def serve_image(filename):
    """Serve an image from the output directory. Restrict filename to avoid path traversal."""
    if not SAFE_FILENAME.match(filename):
        abort(404)
    path = IMAGES_DIR / filename
    if not path.is_file():
        abort(404)
    return send_from_directory(IMAGES_DIR, filename, mimetype="image/png")


if __name__ == "__main__":
    # Run pipeline once on startup so there is at least one image
    if OUTPUT_DIR:
        print("Running pipeline once on startup...")
        try:
            run_pipeline()
        except Exception as e:
            print(f"Startup pipeline error: {e}")
    # Start background scheduler
    thread = threading.Thread(target=scheduler_loop, daemon=True)
    thread.start()
    # Serve
    port = int(os.environ.get("PORT", "8080"))
    app.run(host="0.0.0.0", port=port)
