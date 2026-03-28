"""
Web app for phishing graph: serves latest graph images and runs the pipeline on a schedule.
Set OUTPUT_DIR to the Railway volume path (e.g. /data) so data and images persist.
"""
import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import quote, urlparse

from flask import Flask, send_from_directory, abort, jsonify, request

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
SAFE_ID = re.compile(r"^[a-zA-Z0-9_-]+$")

# Spotify artist images: browser + Cytoscape canvas need same-origin or CORS; Spotify CDN often omits CORS.
# We proxy these URLs through Flask so the graph can paint them reliably.
_PROXIED_IMAGE_HOSTS = frozenset(
    {
        # Spotify CDN
        "i.scdn.co",
        "mosaic.scdn.co",
        "wrapped-images.spotifycdn.com",
        "seed-mix-image.spotifycdn.com",
        "lineup-images.spotifycdn.com",
        # Wikimedia Commons (brand logos)
        "upload.wikimedia.org",
    }
)


def _proxify_spotify_image_url(url: str) -> str:
    """Rewrite known external image URLs to same-origin /image-proxy so Cytoscape can draw them on canvas."""
    u = (url or "").strip()
    if not u.startswith("https://"):
        return u
    try:
        host = urlparse(u).netloc.lower()
        if host in _PROXIED_IMAGE_HOSTS:
            return f"/image-proxy?url={quote(u, safe='')}"
    except Exception:
        pass
    return u


STATS_FILE = IMAGES_DIR / "stats.json"
RUN_META_FILE = IMAGES_DIR / "run_meta.json"
KEYWORDS_FILE = IMAGES_DIR / "keywords.json"
MATCHES_FILE = IMAGES_DIR / "matches.json"


def _read_stats():
    """Read last pipeline stats (display_nodes, full_nodes, full_edges, brands_count, artists_count)."""
    if not STATS_FILE.is_file():
        return None
    try:
        with open(STATS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _read_json_file(path: Path):
    if not path.is_file():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
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


@app.route("/history")
def history_stats():
    """URL history database statistics — totals, by source, processed vs unprocessed, date ranges."""
    try:
        from phishing_brand_graph import get_history_stats
        stats = get_history_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


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
        "<p class='summary'><strong>Production URLs:</strong> "
        "<a href='https://phishknot-production.up.railway.app/' target='_blank' rel='noreferrer'>main static page</a> • "
        "<a href='https://phishknot-production.up.railway.app/graph/interactive' target='_blank' rel='noreferrer'>interactive page</a>"
        "</p>",
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
    """
    Option B: Serve a real interactive UI page (no iframe).
    Graph data and detailed run metadata are fetched from /graph/meta and /graph/data.
    """
    ui = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Phishing graph (interactive)</title>
<style>
  :root {
    --bg: #0b1020;
    --panel: #111a33;
    --panel2: #0e1730;
    --text: #e7ecff;
    --muted: #aab4de;
    --border: rgba(255,255,255,0.12);
    --accent: #7aa2ff;
    --brand: #2ecc71;
    --artist: #e67e22;
    --domain: #9b59b6;
  }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 0; min-height: 100vh; background: var(--bg); color: var(--text); font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; }
  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }
  header { position: sticky; top: 0; z-index: 10; display: flex; align-items: center; gap: 12px; padding: 10px 12px; background: rgba(17,26,51,0.92); backdrop-filter: blur(10px); border-bottom: 1px solid var(--border); }
  header .left { display: flex; align-items: center; gap: 10px; min-width: 0; flex: 1; }
  header .right { display: flex; align-items: center; gap: 10px; }
  .pill { border: 1px solid var(--border); background: rgba(0,0,0,0.15); padding: 6px 10px; border-radius: 999px; font-size: 12px; color: var(--muted); white-space: nowrap; }
  .btn { cursor: pointer; border: 1px solid var(--border); background: rgba(255,255,255,0.06); color: var(--text); padding: 8px 10px; border-radius: 10px; font-size: 13px; }
  .btn:hover { background: rgba(255,255,255,0.09); }
  .lens-group { display: flex; gap: 0; border-radius: 8px; overflow: hidden; border: 1px solid var(--border); }
  .lens-btn { flex: 1; cursor: pointer; border: none; border-right: 1px solid var(--border); background: rgba(255,255,255,0.04); color: var(--muted); padding: 7px 0; font-size: 12px; }
  .lens-btn:last-child { border-right: none; }
  .lens-btn:hover { background: rgba(255,255,255,0.09); color: var(--text); }
  .lens-btn.active { background: rgba(99,140,255,0.22); color: #a8bfff; font-weight: 600; }
  .layout { display: grid; grid-template-columns: 360px 1fr; min-height: calc(100vh - 52px); }
  @media (max-width: 980px) { .layout { grid-template-columns: 1fr; } }
  .panel { border-right: 1px solid var(--border); background: var(--panel); padding: 12px; overflow: auto; }
  @media (max-width: 980px) { .panel { border-right: none; border-bottom: 1px solid var(--border); } }
  .panel h2 { margin: 8px 0 10px; font-size: 14px; letter-spacing: 0.02em; color: var(--muted); text-transform: uppercase; }
  .row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
  .field { width: 100%; display: grid; grid-template-columns: 140px 1fr; gap: 10px; padding: 8px 0; border-bottom: 1px solid rgba(255,255,255,0.06); }
  .label { color: var(--muted); font-size: 13px; }
  .value { font-size: 13px; }
  select, input[type="number"], input[type="text"] {
    width: 100%;
    background: var(--panel2);
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 8px 10px;
    font-size: 13px;
  }
  details { border: 1px solid rgba(255,255,255,0.10); border-radius: 12px; overflow: hidden; background: rgba(0,0,0,0.14); margin: 10px 0; }
  summary { cursor: pointer; padding: 10px 12px; color: var(--text); font-size: 13px; }
  details .content { padding: 10px 12px; border-top: 1px solid rgba(255,255,255,0.10); color: var(--muted); font-size: 12px; }
  pre { margin: 0; white-space: pre-wrap; word-break: break-word; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  th, td { border-bottom: 1px solid rgba(255,255,255,0.08); padding: 6px 4px; vertical-align: top; }
  th { color: var(--muted); font-weight: 600; text-align: left; }
  .graph { width: 100%; min-height: calc(100vh - 52px); background: #0a0f1f; }
  /* Cytoscape container should fill available space */
  #graph { width: 100%; height: calc(100vh - 52px); }
  .legend { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 10px; }
  .chip { display: inline-flex; align-items: center; gap: 6px; border: 1px solid rgba(255,255,255,0.12); background: rgba(0,0,0,0.12); padding: 4px 8px; border-radius: 999px; font-size: 12px; color: var(--muted); }
  .node-chip { cursor: pointer; border: 1px solid rgba(255,255,255,0.15); background: rgba(255,255,255,0.05); padding: 3px 9px; border-radius: 999px; font-size: 11px; color: var(--muted); transition: background 0.15s, color 0.15s; white-space: nowrap; }
  .node-chip:hover { background: rgba(255,255,255,0.10); color: var(--text); }
  .node-chip.active-brand { background: rgba(46,204,113,0.25); border-color: #2ecc71; color: #2ecc71; }
  .node-chip.active-artist { background: rgba(230,126,34,0.25); border-color: #e67e22; color: #e67e22; }
  .node-chip.dimmed { opacity: 0.35; }
  .dot { width: 10px; height: 10px; border-radius: 999px; display: inline-block; }
  .dot.brand { background: var(--brand); }
  .dot.artist { background: var(--artist); }
  .dot.domain { background: var(--domain); }
  .error { color: #ffb3b3; font-size: 13px; }
</style>
<script src="https://unpkg.com/cytoscape@3.27.0/dist/cytoscape.min.js"></script>
</head>
<body>
<header>
  <div class="left">
    <a class="btn" href="/">&larr; Back</a>
    <a class="pill" href="https://phishknot-production.up.railway.app/" target="_blank" rel="noreferrer">Prod static URL</a>
    <a class="pill" href="https://phishknot-production.up.railway.app/graph/interactive" target="_blank" rel="noreferrer">Prod interactive URL</a>
    <div id="status" class="pill">Loading…</div>
    <div id="summary" class="pill">—</div>
  </div>
  <div class="right">
    <button id="refreshBtn" class="btn" type="button">Refresh</button>
  </div>
</header>
<div class="layout">
  <div class="panel">
    <h2>Controls</h2>
    <div class="field">
      <div class="label">Dataset</div>
      <div class="value">
        <select id="coToggle">
          <option value="0">All matched URLs (brand OR artist)</option>
          <option value="1">Co-occurrence only (URLs with BOTH brand + artist)</option>
        </select>
      </div>
    </div>
    <div class="field">
      <div class="label">View</div>
      <div class="value">
        <select id="viewMode">
          <option value="brand_artist">Brands + Artists (co-mentioned)</option>
          <option value="focus">Brands + Artists + Domains</option>
        </select>
      </div>
    </div>
    <div class="field">
      <div class="label">Max nodes</div>
      <div class="value">
        <input id="maxNodes" type="number" min="10" max="2000" step="10" value="200" />
      </div>
    </div>
    <div class="field">
      <div class="label">Lens</div>
      <div class="value">
        <div class="lens-group">
          <button class="lens-btn active" data-lens="both" type="button">Both</button>
          <button class="lens-btn" data-lens="artist" type="button">Artist</button>
          <button class="lens-btn" data-lens="brand" type="button">Brand</button>
        </div>
      </div>
    </div>
    <div class="field">
      <div class="label">Layout</div>
      <div class="value">
        <select id="layoutMode">
          <option value="preset" selected>Preset (server positions)</option>
          <option value="cose">CoSE (force-directed)</option>
          <option value="circle">Circle</option>
          <option value="concentric">Concentric</option>
          <option value="grid">Grid</option>
          <option value="breadthfirst">Breadthfirst</option>
          <option value="random">Random</option>
        </select>
      </div>
    </div>
    <div class="field">
      <div class="label">Search</div>
      <div class="value">
        <input id="searchBox" type="text" placeholder="Find node label (e.g., ccb / Yeat / domain)" />
      </div>
    </div>

    <details id="coseDetails">
      <summary style="cursor:pointer;color:var(--muted);font-size:13px;padding:6px 0">CoSE tuning</summary>
      <div style="padding:4px 0">
        <div class="field"><div class="label" style="font-size:12px">Repulsion</div>
          <div class="value"><input id="coseRepulsion" type="range" min="1000" max="200000" step="1000" value="55000" style="width:100%">
          <span id="coseRepulsionVal" style="font-size:11px;color:var(--muted)">55000</span></div></div>
        <div class="field"><div class="label" style="font-size:12px">Edge length</div>
          <div class="value"><input id="coseEdgeLen" type="range" min="50" max="500" step="10" value="220" style="width:100%">
          <span id="coseEdgeLenVal" style="font-size:11px;color:var(--muted)">220</span></div></div>
        <div class="field"><div class="label" style="font-size:12px">Gravity</div>
          <div class="value"><input id="coseGravity" type="range" min="0" max="100" step="1" value="10" style="width:100%">
          <span id="coseGravityVal" style="font-size:11px;color:var(--muted)">0.10</span></div></div>
        <div class="field"><div class="label" style="font-size:12px">Iterations</div>
          <div class="value"><input id="coseIter" type="range" min="100" max="3000" step="100" value="1000" style="width:100%">
          <span id="coseIterVal" style="font-size:11px;color:var(--muted)">1000</span></div></div>
        <button class="btn" id="rerunLayout" style="width:100%;margin-top:6px">Re-run layout</button>
      </div>
    </details>

    <div class="legend">
      <span class="chip"><span class="dot brand"></span> brand</span>
      <span class="chip"><span class="dot artist"></span> artist</span>
      <span class="chip"><span class="dot domain"></span> domain</span>
    </div>

    <details open>
      <summary>Brands</summary>
      <div class="content">
        <div id="brandChips" style="display:flex;flex-wrap:wrap;gap:5px;padding:4px 0"></div>
      </div>
    </details>
    <details open>
      <summary>Artists</summary>
      <div class="content">
        <div id="artistChips" style="display:flex;flex-wrap:wrap;gap:5px;padding:4px 0"></div>
      </div>
    </details>

    <div id="chipInfo" style="display:none;margin:10px 0;padding:10px 12px;border-radius:10px;background:rgba(0,0,0,0.18);border:1px solid var(--border)">
      <div id="chipInfoLabel" style="font-size:13px;font-weight:600;color:var(--text);margin-bottom:4px"></div>
      <div id="chipInfoMeta" style="font-size:11px;color:var(--muted);line-height:1.7"></div>
    </div>

    <details open>
      <summary>Run summary</summary>
      <div class="content">
        <div id="runSummary">Loading…</div>
      </div>
    </details>
    <details>
      <summary>Effective config</summary>
      <div class="content"><pre id="configPre"></pre></div>
    </details>
    <details>
      <summary>Keywords (counts + hashes)</summary>
      <div class="content"><pre id="keywordsPre"></pre></div>
    </details>
    <details>
      <summary>Matches (URLs → brands/artists + provenance)</summary>
      <div class="content">
        <div style="margin-bottom:8px;color:var(--muted)">Showing latest run matches. Use browser find to search within.</div>
        <div id="matchesTableWrap"></div>
      </div>
    </details>
    <div id="error" class="error" style="display:none"></div>
  </div>
  <div id="graph" class="graph"></div>
</div>

<script>
const el = (id) => document.getElementById(id);
const state = { meta: null, data: null };
let cy = null;

function fmtBool(v){ return v ? "true" : "false"; }

function setError(msg){
  const e = el("error");
  e.style.display = msg ? "block" : "none";
  e.textContent = msg || "";
}

function currentLens(){
  const active = document.querySelector(".lens-btn.active");
  return active ? active.dataset.lens : "both";
}

function buildQuery(){
  const coEl = el("coToggle");
  const viewEl = el("viewMode");
  const maxNodesEl = el("maxNodes");
  // Defensive defaults so UI doesn't crash if an element is missing.
  const co = coEl ? coEl.value : "0";
  const view = viewEl ? viewEl.value : "brand_artist";
  const maxNodesRaw = maxNodesEl ? maxNodesEl.value : "200";
  const maxNodes = Math.max(10, parseInt(maxNodesRaw || "200", 10));
  const lens = currentLens();
  const params = new URLSearchParams({ co, view, max_nodes: String(maxNodes), lens });
  return params.toString();
}

async function fetchJSON(url){
  const r = await fetch(url, { cache: "no-store" });
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  return await r.json();
}

function renderMeta(meta){
  el("status").textContent = `Updated: ${meta.generated_at_utc || "unknown"}`;
  const rs = meta.run_stats || {};
  const ds = meta.display_stats || {};
  const img = meta.image_summary || {};
  el("summary").textContent =
    `Display ${ds.display_nodes ?? "?"} nodes • Full ${rs.full_nodes ?? "?"} nodes / ${rs.full_edges ?? "?"} edges`;

  el("runSummary").innerHTML = `
    <div><b>Dataset</b>: ${meta.dataset_label || "—"}</div>
    <div><b>URLs processed</b>: ${meta.counts?.urls_processed ?? "?"} (download_failed=${meta.counts?.download_failed ?? "0"})</div>
    <div><b>Kept</b>: any_match=${meta.counts?.kept_any_match ?? "?"}, brand=${meta.counts?.kept_brand ?? "?"}, artist=${meta.counts?.kept_artist ?? "?"}, both=${meta.counts?.kept_both ?? "?"}</div>
    <div><b>Mode</b>: NO_DOWNLOAD=${fmtBool(meta.config?.NO_DOWNLOAD)}, CO_OCCURRENCE_ONLY(env)=${fmtBool(meta.config?.CO_OCCURRENCE_ONLY)}</div>
    <div><b>Artist images</b>: spotify=${img.spotify_artist_images ?? "?"} / artists=${img.artists_total ?? "?"} (fallback avatars for the rest)</div>
  `;
  el("configPre").textContent = JSON.stringify(meta.config || {}, null, 2);
  el("keywordsPre").textContent = JSON.stringify(meta.keywords || {}, null, 2);
}

function renderMatches(matches){
  if (!matches || !Array.isArray(matches.results)) {
    el("matchesTableWrap").innerHTML = "<div style='color:var(--muted)'>No match data available.</div>";
    return;
  }
  const rows = matches.results.slice(0, 250);
  const html = [];
  html.push("<table>");
  html.push("<thead><tr><th>Brands</th><th>Artists</th><th>Provenance</th><th>Domain</th><th>URL</th></tr></thead><tbody>");
  for (const r of rows) {
    const brands = (r.brands || []).join(", ");
    const artists = (r.artists || []).map(a => a.name || a.artist_keyword).filter(Boolean).join(", ");
    const md = r.match_detail || {};
    const prov = [
      (md.brands_in_url?.length ? `brands:url(${md.brands_in_url.length})` : ""),
      (md.brands_in_text?.length ? `brands:text(${md.brands_in_text.length})` : ""),
      (md.artists_in_url?.length ? `artists:url(${md.artists_in_url.length})` : ""),
      (md.artists_in_text?.length ? `artists:text(${md.artists_in_text.length})` : ""),
    ].filter(Boolean).join(" • ");
    html.push("<tr>");
    html.push(`<td>${brands ? brands.slice(0, 120) : ""}</td>`);
    html.push(`<td>${artists ? artists.slice(0, 120) : ""}</td>`);
    html.push(`<td>${prov}</td>`);
    html.push(`<td style="color:var(--muted);font-size:11px">${(r.domain || "").slice(0, 50)}</td>`);
    html.push(`<td><a href="${r.url}" target="_blank" rel="noreferrer">${(r.url || "").slice(0, 80)}</a></td>`);
    html.push("</tr>");
  }
  html.push("</tbody></table>");
  el("matchesTableWrap").innerHTML = html.join("");
}

function colorForType(t){
  if (t === "brand") return "#2ecc71";
  if (t === "artist") return "#e67e22";
  if (t === "domain") return "#9b59b6";
  return "#95a5a6";
}

let _serverPos = {};  // server-computed babbleknot positions, keyed by node id

function getLayoutOpts(){
  const layoutEl = el("layoutMode");
  const name = (layoutEl && layoutEl.value) ? layoutEl.value : "preset";
  const base = { animate: false, fit: true, padding: 40 };
  if (name === "preset") {
    return { ...base, name: "preset", positions: (node) => _serverPos[node.id()] };
  }
  if (name === "cose") {
    const repulsion = parseInt(el("coseRepulsion")?.value || "55000", 10);
    const edgeLen = parseInt(el("coseEdgeLen")?.value || "220", 10);
    const gravity = parseInt(el("coseGravity")?.value || "10", 10) / 100;
    const iters = parseInt(el("coseIter")?.value || "1000", 10);
    return { ...base, name: "cose", nodeRepulsion: repulsion, idealEdgeLength: edgeLen, edgeElasticity: 0.35, gravity, numIter: iters };
  }
  if (name === "concentric") {
    return { ...base, name: "concentric", concentric: (node) => node.degree(), levelWidth: () => 1 };
  }
  if (name === "breadthfirst") {
    return { ...base, name: "breadthfirst", directed: false, spacingFactor: 1.2 };
  }
  return { ...base, name };
}

function renderGraph(data){
  if (!data || !data.nodes || data.nodes.length === 0) {
    if (cy) { try { cy.destroy(); } catch (_) {} cy = null; }
    el("graph").innerHTML = "<div style='padding:16px;color:var(--muted)'>No nodes to display for this selection.</div>";
    return;
  }

  const nodes = data.nodes;
  const edges = data.edges || [];

  _serverPos = {};
  const elements = [];
  const fallbackImage = (node) => {
    const u = (node.image_url || "").trim();
    if (u) return u;
    const t = node.type || "node";
    const id = node.id || node.label || "n";
    return `/avatar/${t}/${id}.svg`;
  };
  const absoluteImageUrl = (u) => {
    if (!u || typeof u !== "string") return u;
    const s = u.trim();
    if (s.startsWith("http://") || s.startsWith("https://")) return s;
    try {
      return new URL(s, window.location.href).href;
    } catch (_) {
      return s;
    }
  };
  for (const n of nodes) {
    const data = {
      id: n.id,
      label: n.label,
      type: n.type,
      degree: n.degree || 0,
      image_url: absoluteImageUrl(fallbackImage(n)),
    };
    const el = { data };
    if (n.x != null && n.y != null && Number.isFinite(n.x) && Number.isFinite(n.y)) {
      const p = { x: n.x, y: n.y };
      el.position = p;
      _serverPos[n.id] = p;
    }
    elements.push(el);
  }
  for (const e of edges) {
    elements.push({
      data: {
        id: `${e.source}__${e.target}`,
        source: e.source,
        target: e.target,
        type: e.type || "unknown",
      }
    });
  }

  const borderColor = (t) => {
    if (t === "brand") return "#2ecc71";
    if (t === "artist") return "#e67e22";
    if (t === "domain") return "#9b59b6";
    return "rgba(255,255,255,0.35)";
  };
  const bgColor = (t) => {
    if (t === "brand") return "rgba(46, 204, 113, 0.22)";
    if (t === "artist") return "rgba(230, 126, 34, 0.22)";
    if (t === "domain") return "rgba(155, 89, 182, 0.22)";
    return "rgba(255,255,255,0.10)";
  };
  const cyStyle = [
    {
      selector: "node",
      style: {
        "shape": "ellipse",
        "width": "data(size)",
        "height": "data(size)",
        "background-color": (ele) => bgColor(ele.data("type")),
        "background-image": "data(image_url)",
        "background-fit": "cover",
        "border-width": (ele) => ele.data("is_anchor") ? 4 : 2,
        "border-color": (ele) => borderColor(ele.data("type")),
        "label": "data(label)",
        "color": "rgba(231,236,255,0.92)",
        "font-size": "data(font_size)",
        "text-valign": "bottom",
        "text-halign": "center",
        "text-margin-y": 12,
        "text-wrap": "wrap",
        "text-max-width": 140,
        "text-outline-width": 2,
        "text-outline-color": "#0a0f1f",
      },
    },
    {
      selector: "edge",
      style: {
        "curve-style": "unbundled-bezier",
        "width": 1.2,
        "line-color": "rgba(255,255,255,0.18)",
        "target-arrow-shape": "triangle",
        "target-arrow-color": "rgba(255,255,255,0.18)",
        "arrow-scale": 0.9,
      },
    },
  ];
  const layoutOpts = getLayoutOpts();

  if (cy) {
    cy.batch(() => {
      cy.elements().remove();
      cy.add(elements);
    });
    cy.layout(layoutOpts).run();
    return;
  }

  el("graph").innerHTML = "";
  cy = cytoscape({
    container: el("graph"),
    elements,
    style: cyStyle,
    layout: layoutOpts,
  });

  cy.on("tap", "node", (evt) => {
    const nodeId = evt.target.id();
    showNodeInfo(nodeId);
  });
}

function applySearch(){
  const q = (el("searchBox").value || "").trim().toLowerCase();
  if (!q || !state.data || !state.data.nodes) return;
  if (!cy) return;
  const hits = cy.nodes().filter(n => (n.data("label") || "").toLowerCase().includes(q));
  if (hits.length === 0) return;
  cy.nodes().unselect();
  const n = hits[0];
  n.select();
  cy.animate({ center: { eles: n }, zoom: Math.max(cy.zoom(), 1.2) }, { duration: 250 });
}

let _activeChipId = null;

function buildNodeChips(nodes) {
  const brands = nodes.filter(n => n.type === "brand").sort((a,b) => a.label.localeCompare(b.label));
  const artists = nodes.filter(n => n.type === "artist").sort((a,b) => a.label.localeCompare(b.label));

  function makeChip(n, colorClass) {
    const chip = document.createElement("span");
    chip.className = "node-chip";
    chip.textContent = n.label;
    chip.dataset.nodeId = n.id;
    chip.addEventListener("click", () => handleChipClick(n.id, colorClass, chip));
    return chip;
  }

  const brandContainer = el("brandChips");
  const artistContainer = el("artistChips");
  if (brandContainer) {
    brandContainer.innerHTML = "";
    brands.forEach(n => brandContainer.appendChild(makeChip(n, "active-brand")));
    if (!brands.length) brandContainer.innerHTML = "<span style='color:var(--muted);font-size:11px'>None in current graph</span>";
  }
  if (artistContainer) {
    artistContainer.innerHTML = "";
    artists.forEach(n => artistContainer.appendChild(makeChip(n, "active-artist")));
    if (!artists.length) artistContainer.innerHTML = "<span style='color:var(--muted);font-size:11px'>None in current graph</span>";
  }
}

function showNodeInfo(nodeId) {
  if (!state.data || !state.data.nodes) return;
  const n = state.data.nodes.find(x => x.id === nodeId);
  if (!n) return;
  const infoBox = el("chipInfo");
  const labelEl = el("chipInfoLabel");
  const metaEl = el("chipInfoMeta");
  if (!infoBox) return;
  const typeLabel = n.type.charAt(0).toUpperCase() + n.type.slice(1);
  const neighbors = cy ? cy.getElementById(nodeId).neighborhood().nodes() : [];
  const connectedBrands = [...neighbors].filter(x => x.data("type") === "brand").length;
  const connectedArtists = [...neighbors].filter(x => x.data("type") === "artist").length;
  const connectedDomains = [...neighbors].filter(x => x.data("type") === "domain").length;
  const connectedUrls = [...neighbors].filter(x => x.data("type") === "phishing_url").length;
  let meta = `Type: ${typeLabel} &nbsp;·&nbsp; Connections: ${n.degree}`;
  if (connectedBrands) meta += ` &nbsp;·&nbsp; Brands: ${connectedBrands}`;
  if (connectedArtists) meta += ` &nbsp;·&nbsp; Artists: ${connectedArtists}`;
  if (connectedDomains) meta += ` &nbsp;·&nbsp; Domains: ${connectedDomains}`;
  if (connectedUrls) meta += ` &nbsp;·&nbsp; URLs: ${connectedUrls}`;
  if (n.full_url) meta += `<br><span style="word-break:break-all">${n.full_url}</span>`;
  labelEl.textContent = n.label;
  metaEl.innerHTML = meta;
  infoBox.style.display = "block";
}

function handleChipClick(nodeId, colorClass, chip) {
  if (!cy) return;
  const cyNode = cy.getElementById(nodeId);
  if (!cyNode || cyNode.length === 0) return;

  const isActive = _activeChipId === nodeId;

  // Reset all chips and node opacity
  document.querySelectorAll(".node-chip").forEach(c => {
    c.classList.remove("active-brand", "active-artist", "dimmed");
  });
  cy.elements().style("opacity", 1);
  cy.nodes().unselect();

  if (isActive) {
    _activeChipId = null;
    const infoBox = el("chipInfo");
    if (infoBox) infoBox.style.display = "none";
    return;
  }

  // Highlight this node and its neighbors; dim everything else
  _activeChipId = nodeId;
  chip.classList.add(colorClass);
  const neighborhood = cyNode.closedNeighborhood();
  cy.elements().not(neighborhood).style("opacity", 0.12);
  cyNode.select();
  cy.animate({ center: { eles: cyNode }, zoom: Math.max(cy.zoom(), 1.4) }, { duration: 250 });

  // Dim other chips
  document.querySelectorAll(".node-chip").forEach(c => {
    if (c.dataset.nodeId !== nodeId) c.classList.add("dimmed");
  });

  showNodeInfo(nodeId);
}

async function refreshAll(){
  try {
    setError("");
    el("status").textContent = "Loading…";
    const q = buildQuery();
    const meta = await fetchJSON(`/graph/meta?${q}`);
    const data = await fetchJSON(`/graph/data?${q}`);
    const matches = await fetchJSON(`/graph/matches?${q}`);
    state.meta = meta;
    state.data = data;
    renderMeta(meta);
    renderMatches(matches);
    renderGraph(data);
    _activeChipId = null;
    if (cy) cy.elements().style("opacity", 1);
    buildNodeChips(data.nodes || []);
  } catch (e) {
    setError(`Failed to load graph data: ${e.message}`);
    el("status").textContent = "Error";
  }
}

const refreshBtn = el("refreshBtn");
if (refreshBtn) refreshBtn.addEventListener("click", refreshAll);
document.querySelectorAll(".lens-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".lens-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    refreshAll();
  });
});
const coToggle = el("coToggle");
if (coToggle) coToggle.addEventListener("change", refreshAll);
const viewMode = el("viewMode");
if (viewMode) viewMode.addEventListener("change", refreshAll);
const maxNodesEl = el("maxNodes");
if (maxNodesEl) maxNodesEl.addEventListener("change", refreshAll);
const layoutMode = el("layoutMode");
if (layoutMode) layoutMode.addEventListener("change", () => {
  if (cy && cy.elements().length > 0) cy.layout(getLayoutOpts()).run();
});
const searchBox = el("searchBox");
if (searchBox) searchBox.addEventListener("keydown", (ev) => { if (ev.key === "Enter") applySearch(); });

// CoSE tuning sliders
[
  ["coseRepulsion", "coseRepulsionVal", v => v],
  ["coseEdgeLen",   "coseEdgeLenVal",   v => v],
  ["coseGravity",   "coseGravityVal",   v => (parseInt(v,10)/100).toFixed(2)],
  ["coseIter",      "coseIterVal",      v => v],
].forEach(([sliderId, valId, fmt]) => {
  const s = el(sliderId);
  if (s) s.addEventListener("input", () => { const v = el(valId); if(v) v.textContent = fmt(s.value); });
});
const rerunLayout = el("rerunLayout");
if (rerunLayout) rerunLayout.addEventListener("click", () => {
  if (cy && cy.elements().length > 0) cy.layout(getLayoutOpts()).run();
});

refreshAll();
</script>
</body>
</html>"""
    return ui, 200, {"Content-Type": "text/html; charset=utf-8"}


def _load_graph_from_gexf(path: Path):
    try:
        import networkx as nx
        if not path.is_file():
            return None
        return nx.read_gexf(str(path))
    except Exception:
        return None


def _pick_dataset_gexf(co: bool):
    # Prefer co_occurrence.gexf when requested; fall back to phishing_graph.gexf.
    co_path = DATA_DIR / "co_occurrence.gexf"
    full_path = DATA_DIR / "phishing_graph.gexf"
    if co and co_path.is_file():
        return co_path
    return full_path


def _load_spotify_image_cache():
    """
    Load cached Spotify artist lookups written by the pipeline to cache/spotify_artists.json.
    Schema: { "<lowercase-key>": { name, popularity, spotify_id, image_url } | null, ... }
    """
    path = DATA_DIR / "cache" / "spotify_artists.json"
    if not path.is_file():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _spotify_image_for_label(cache: dict, label: str) -> str:
    if not cache:
        return ""
    key = (label or "").strip().lower()
    if not key:
        return ""
    entry = cache.get(key)
    if isinstance(entry, dict):
        return (entry.get("image_url") or "").strip()
    return ""


@app.route("/graph/meta")
def graph_meta():
    """
    Metadata for the interactive UI:
    - effective config and counts (from output/run_meta.json)
    - keyword summaries (from output/keywords.json)
    - last run stats (from output/stats.json)
    """
    co = (request.args.get("co", "0") or "0").lower() in ("1", "true", "yes")
    view = (request.args.get("view", "brand_artist") or "brand_artist").strip()
    max_nodes = request.args.get("max_nodes", None)

    run_meta = _read_json_file(RUN_META_FILE) or {}
    keywords = _read_json_file(KEYWORDS_FILE) or {}
    stats = _read_stats() or {}
    spotify_cache = _load_spotify_image_cache()
    matches = _read_json_file(MATCHES_FILE) or {}

    # Image summary: how many artist nodes have Spotify image URLs available.
    artist_labels = set()
    try:
        for r in (matches.get("results") or []):
            for a in (r.get("artists") or []):
                if isinstance(a, dict):
                    label = (a.get("name") or a.get("artist_keyword") or "").strip()
                    if label:
                        artist_labels.add(label)
    except Exception:
        artist_labels = set()

    spotify_hits = 0
    for lbl in artist_labels:
        if _spotify_image_for_label(spotify_cache, lbl):
            spotify_hits += 1

    out = {
        "generated_at_utc": run_meta.get("generated_at_utc") or keywords.get("generated_at_utc") or "",
        "dataset_label": "Co-occurrence only (brand+artist URLs)" if co else "All matched URLs (brand OR artist)",
        "requested": {"co": co, "view": view, "max_nodes": max_nodes},
        "config": run_meta.get("config") or {},
        "counts": run_meta.get("counts") or {},
        "run_stats": run_meta.get("graph_stats") or {},
        "display_stats": stats or {},
        "image_summary": {
            "artists_total": len(artist_labels),
            "spotify_artist_images": spotify_hits,
        },
        "keywords": {
            "brands": {
                "total": (keywords.get("brands") or {}).get("total"),
                "sha256": (keywords.get("brands") or {}).get("sha256"),
                "bank_count": len((keywords.get("brands") or {}).get("bank_keywords") or []),
                "other_count": len((keywords.get("brands") or {}).get("other_brand_keywords") or []),
            },
            "artists": {
                "static_count": (keywords.get("artists") or {}).get("static_count"),
                "combined_count": (keywords.get("artists") or {}).get("combined_count"),
                "sha256": (keywords.get("artists") or {}).get("sha256"),
                "lastfm_enabled": (keywords.get("artists") or {}).get("lastfm_enabled"),
            },
            "note": "Full keyword lists are stored in output/keywords.json (not fully inlined here).",
        },
    }
    return jsonify(out)


@app.route("/graph/matches")
def graph_matches():
    """Return per-URL match provenance from the latest run (output/matches.json)."""
    matches = _read_json_file(MATCHES_FILE) or {"results": []}
    return jsonify(matches)


def _babbleknot_layout(H, anchor_types=None):
    """
    Two-tier layout inspired by babbleknot graph visualization:
    - Anchor nodes (default: artist + brand) are evenly spaced on a circle as visual anchors.
    - Light nodes (everything else) cluster around the centroid of their connected anchors.

    anchor_types: set of node type strings to treat as anchors (default {"artist","brand"})
    Returns dict: node_id -> (x, y)
    """
    import networkx as nx
    import math
    import random

    HEAVY = anchor_types if anchor_types is not None else {"artist", "brand"}

    heavy = [n for n in H.nodes() if (H.nodes[n] or {}).get("type") in HEAVY]
    light = [n for n in H.nodes() if (H.nodes[n] or {}).get("type") not in HEAVY]

    pos = {}

    if not heavy:
        return nx.spring_layout(H, k=2.0, seed=42, iterations=100)

    # Pixel scale: heavy anchors spread over ~2000px canvas; light nodes in rings around them
    ANCHOR_SCALE = 700   # radius of the heavy-node circle in px
    CLUSTER_RADIUS = 120  # base px radius of light-node rings; grows with sqrt(cluster size)

    # Place heavy nodes evenly on a circle — spring layout clumps them because
    # they're densely connected; a forced circle spreads them as real anchors.
    n = len(heavy)
    if n == 1:
        pos[heavy[0]] = (0.0, 0.0)
    else:
        for i, node in enumerate(heavy):
            angle = 2 * math.pi * i / n
            pos[node] = (math.cos(angle) * ANCHOR_SCALE, math.sin(angle) * ANCHOR_SCALE)

    # Position each light node near the centroid of its heavy neighbors
    rng = random.Random(42)
    centroid_counts = {}
    for node in light:
        heavy_nb = tuple(sorted(nb for nb in H.neighbors(node) if nb in pos))
        centroid_counts[heavy_nb] = centroid_counts.get(heavy_nb, 0) + 1

    centroid_idx = {}
    for node in light:
        heavy_nb = tuple(sorted(nb for nb in H.neighbors(node) if nb in pos))
        if heavy_nb:
            cx = sum(pos[nb][0] for nb in heavy_nb) / len(heavy_nb)
            cy = sum(pos[nb][1] for nb in heavy_nb) / len(heavy_nb)
        else:
            # Orphan — place on outer ring beyond all anchors
            angle = rng.uniform(0, 2 * math.pi)
            cx, cy = math.cos(angle) * ANCHOR_SCALE * 1.5, math.sin(angle) * ANCHOR_SCALE * 1.5

        count = centroid_counts.get(heavy_nb, 1)
        idx = centroid_idx.get(heavy_nb, 0)
        centroid_idx[heavy_nb] = idx + 1
        # Radius grows with cluster size so nodes don't stack
        radius = CLUSTER_RADIUS * math.sqrt(count)
        angle = (2 * math.pi * idx / max(count, 1)) + rng.uniform(-0.05, 0.05)
        pos[node] = (cx + math.cos(angle) * radius, cy + math.sin(angle) * radius)

    return pos


@app.route("/graph/data")
def graph_data():
    """
    Return node/edge lists (with x/y positions) for client-side Plotly rendering.
    Query params:
      - co=0|1: choose dataset (phishing_graph.gexf vs co_occurrence.gexf when available)
      - view=brand_artist|focus
      - max_nodes=int
      - lens=both|artist|brand  (which node type acts as anchor)
    """
    co = (request.args.get("co", "0") or "0").lower() in ("1", "true", "yes")
    view = (request.args.get("view", "brand_artist") or "brand_artist").strip()
    lens = (request.args.get("lens", "both") or "both").strip().lower()
    if lens not in ("artist", "brand"):
        lens = "both"
    anchor_types = {"artist"} if lens == "artist" else {"brand"} if lens == "brand" else {"artist", "brand"}
    try:
        max_nodes = int(request.args.get("max_nodes", "200"))
    except Exception:
        max_nodes = 200
    max_nodes = max(10, min(max_nodes, 5000))

    gexf_path = _pick_dataset_gexf(co)
    G = _load_graph_from_gexf(gexf_path)
    if G is None:
        return jsonify({"title": "Phishing graph", "nodes": [], "edges": [], "note": "No graph available yet."})

    try:
        import networkx as nx
        # Reuse existing subgraph helpers from the pipeline module.
        from phishing_brand_graph import _brand_artist_subgraph, _focus_subgraph, _subgraph_for_display
        spotify_cache = _load_spotify_image_cache()

        if view == "focus":
            H = _focus_subgraph(G)
            H = _subgraph_for_display(H, max_nodes)
            title = "Phishing graph (brands + artists + domains)"
        else:
            H = _brand_artist_subgraph(G, max_nodes=max_nodes)
            title = "Phishing graph (brands + artists, co-mentioned)"

        if H.number_of_nodes() == 0:
            return jsonify({"title": title, "nodes": [], "edges": []})

        try:
            pos = _babbleknot_layout(H, anchor_types=anchor_types)
        except Exception:
            pos = nx.random_layout(H, seed=42)

        deg = dict(H.degree())
        nodes = []
        for n in H.nodes():
            data = H.nodes[n] or {}
            n_type = data.get("type", "") or ""
            img = data.get("image_url", "") or ""
            label = (data.get("label") or data.get("title") or data.get("type") or str(n))
            # Backward-compat: older GEXF may not include image_url yet.
            # Provide safe local avatars based on node type and id so images show immediately.
            if not img:
                if n_type == "brand":
                    img = f"/avatar/brand/{str(n)}.svg"
                elif n_type == "artist":
                    # Prefer Spotify cached image for this label when available (safe source, no phishing fetch).
                    s_img = _spotify_image_for_label(spotify_cache, label)
                    img = s_img or f"/avatar/artist/{str(n)}.svg"
                else:
                    # domain, url, or other: use type-based avatar so Cytoscape never gets empty background-image.
                    img = f"/avatar/{n_type or 'node'}/{str(n)}.svg"
            img = _proxify_spotify_image_url(img)
            is_anchor = n_type in anchor_types
            # Size: anchors large + readable, domain medium, url/other small
            if is_anchor:
                node_size = 80
                node_font_size = 14
            elif n_type == "domain":
                node_size = 44
                node_font_size = 11
            else:
                node_size = 34
                node_font_size = 10
            nodes.append({
                "id": str(n),
                "label": label,
                "type": n_type,
                "is_anchor": is_anchor,
                "size": node_size,
                "font_size": node_font_size,
                "domain": data.get("domain", ""),
                "full_url": data.get("full_url", ""),
                "popularity": data.get("popularity", 0),
                "image_url": img,
                "degree": int(deg.get(n, 0)),
                "x": float(pos[n][0]) if n in pos else 0.0,
                "y": float(pos[n][1]) if n in pos else 0.0,
            })

        edges = []
        for u, v, data in H.edges(data=True):
            edges.append({
                "source": str(u),
                "target": str(v),
                "type": (data or {}).get("relationship_type", "unknown"),
                "evidence": (data or {}).get("evidence_source", ""),
            })

        return jsonify({
            "title": title,
            "dataset": "co_occurrence" if co else "all",
            "view": view,
            "max_nodes": max_nodes,
            "nodes": nodes,
            "edges": edges,
            "stats": {
                "nodes": H.number_of_nodes(),
                "edges": H.number_of_edges(),
                "brands": sum(1 for x in H.nodes() if (H.nodes[x] or {}).get("type") == "brand"),
                "artists": sum(1 for x in H.nodes() if (H.nodes[x] or {}).get("type") == "artist"),
                "domains": sum(1 for x in H.nodes() if (H.nodes[x] or {}).get("type") == "domain"),
            },
        })
    except Exception as e:
        return jsonify({"title": "Phishing graph", "nodes": [], "edges": [], "error": str(e)})


@app.route("/image-proxy")
def image_proxy():
    """
    Fetch a Spotify CDN image server-side and return it same-origin.
    Cytoscape draws node backgrounds on canvas; crossOrigin + missing CORS headers breaks external Spotify URLs.
    """
    raw = (request.args.get("url") or "").strip()
    if not raw.startswith("https://"):
        abort(400)
    try:
        host = urlparse(raw).netloc.lower()
    except Exception:
        abort(400)
    if host not in _PROXIED_IMAGE_HOSTS:
        abort(404)
    try:
        req = urllib.request.Request(raw, headers={
            "User-Agent": "PhishKnot/1.0 (https://github.com/billybobbain/phishknot; defensive security research)",
            "Accept": "image/svg+xml,image/*,*/*;q=0.8",
        })
        with urllib.request.urlopen(req, timeout=12) as resp:
            ct = resp.headers.get("Content-Type") or "image/jpeg"
            data = resp.read()
        if len(data) > 5_000_000:
            abort(413)
        if not ct.startswith("image/"):
            abort(404)
        return data, 200, {
            "Content-Type": ct,
            "Cache-Control": "public, max-age=86400",
        }
    except (urllib.error.URLError, OSError, ValueError):
        abort(502)


@app.route("/page-images/<filename>")
def serve_page_image(filename):
    """Serve a cached page hero image. Strict filename validation to prevent path traversal."""
    if not SAFE_FILENAME.match(filename):
        abort(404)
    path = IMAGES_DIR / "page_images" / filename
    if not path.is_file():
        abort(404)
    ext = Path(filename).suffix.lower()
    mime = {"jpg": "image/jpeg", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
            ".png": "image/png", ".gif": "image/gif", ".webp": "image/webp"}.get(ext, "image/jpeg")
    return send_from_directory(IMAGES_DIR / "page_images", filename, mimetype=mime)


@app.route("/images/<filename>")
def serve_image(filename):
    """Serve an image from the output directory. Restrict filename to avoid path traversal."""
    if not SAFE_FILENAME.match(filename):
        abort(404)
    path = IMAGES_DIR / filename
    if not path.is_file():
        abort(404)
    return send_from_directory(IMAGES_DIR, filename, mimetype="image/png")


def _avatar_svg(label: str, kind: str) -> str:
    """
    Generate a simple SVG avatar for nodes (no external fetch).
    We use the node id as the label seed so this is stable across runs.
    """
    import hashlib as _hashlib
    label = (label or "").strip()
    seed = f"{kind}:{label}".encode("utf-8", errors="replace")
    h = int.from_bytes(_hashlib.sha256(seed).digest()[:3], "big")
    hue = h % 360
    bg = f"hsl({hue} 60% 45%)"
    fg = "rgba(255,255,255,0.92)"
    initials = "".join([c for c in label.upper() if c.isalnum()])[:2] or kind[:2].upper()
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="96" height="96" viewBox="0 0 96 96" role="img" aria-label="{kind} {label}">
  <defs>
    <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="{bg}" stop-opacity="1"/>
      <stop offset="100%" stop-color="black" stop-opacity="0.18"/>
    </linearGradient>
  </defs>
  <rect x="0" y="0" width="96" height="96" rx="18" fill="url(#g)"/>
  <text x="48" y="56" text-anchor="middle" font-family="system-ui,Segoe UI,Arial" font-size="34" fill="{fg}" font-weight="700">{initials}</text>
</svg>"""


@app.route("/avatar/<kind>/<node_id>.svg")
def avatar(kind, node_id):
    """Serve generated SVG avatars for nodes (brand/artist/domain/url)."""
    kind = (kind or "").strip().lower()
    if kind not in ("brand", "artist", "domain", "url"):
        abort(404)
    if not SAFE_ID.match(node_id or ""):
        abort(404)
    svg = _avatar_svg(node_id.replace("_", " ")[:24], kind)
    return svg, 200, {
        "Content-Type": "image/svg+xml; charset=utf-8",
        "Cache-Control": "public, max-age=86400",
    }


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
