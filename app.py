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

import math
import random

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

# ---------------------------------------------------------------------------
# Julia set layout helpers (used by /graph/julia)
# ---------------------------------------------------------------------------

_JULIA_TYPE_POOL_ORDER = {
    'artist':            ['boundary', 'near'],
    'brand':             ['near', 'boundary', 'mid'],
    'domain':            ['mid', 'near', 'far'],
    'registered_domain': ['interior', 'mid'],
    'phishing_url':      ['far', 'mid'],
}


def _julia_iter_map(c, res=600, max_iter=256, extent=2.0):
    """Vectorised escape-time map for f(z) = z² + c."""
    import numpy as np
    re_axis = np.linspace(-extent, extent, res, dtype=np.float64)
    im_axis = np.linspace( extent,-extent, res, dtype=np.float64)
    Z = re_axis[np.newaxis, :] + 1j * im_axis[:, np.newaxis]
    iters   = np.full(Z.shape, max_iter, dtype=np.int32)
    escaped = np.zeros(Z.shape, dtype=bool)
    for i in range(1, max_iter + 1):
        mask = ~escaped
        Z[mask] = Z[mask] ** 2 + c
        new_esc = mask & (np.abs(Z) > 2.0)
        iters[new_esc] = i
        escaped |= new_esc
    return iters


def _julia_build_pools(iters, res, extent, max_iter, rng, downsample=4):
    import numpy as np
    re_axis = np.linspace(-extent, extent, res)
    im_axis = np.linspace( extent,-extent, res)

    def mask_to_pts(mask):
        rows, cols = np.where(mask)
        keep = (rows % downsample == 0) & (cols % downsample == 0)
        rows, cols = rows[keep], cols[keep]
        pts = list(zip(re_axis[cols].tolist(), im_axis[rows].tolist()))
        rng.shuffle(pts)
        return pts

    b_hi = max(2, max_iter // 30)
    n_hi = max_iter // 6
    m_hi = max_iter // 2
    return {
        'interior': mask_to_pts(iters == max_iter),
        'boundary': mask_to_pts((iters >= 1)    & (iters < b_hi)),
        'near':     mask_to_pts((iters >= b_hi)  & (iters < n_hi)),
        'mid':      mask_to_pts((iters >= n_hi)  & (iters < m_hi)),
        'far':      mask_to_pts(iters >= m_hi),
    }


def _julia_assign_positions(G, pools, rng, scale=400):
    import networkx as nx
    deg = dict(G.degree())
    nodes_by_type = {}
    for n, d in G.nodes(data=True):
        t = d.get('type', 'domain')
        nodes_by_type.setdefault(t, []).append((n, d))
    for t in nodes_by_type:
        nodes_by_type[t].sort(key=lambda x: -deg.get(x[0], 0))

    pool_iters = {k: iter(v) for k, v in pools.items()}

    def next_pt(pool_order):
        for pname in pool_order:
            try:
                return next(pool_iters[pname])
            except StopIteration:
                continue
        angle = rng.uniform(0, 2 * math.pi)
        r = rng.uniform(0, 1.5)
        return (r * math.cos(angle), r * math.sin(angle))

    positions = {}
    for t, node_list in nodes_by_type.items():
        pool_order = _JULIA_TYPE_POOL_ORDER.get(t, ['mid', 'far'])
        for n, _ in node_list:
            cx, cy_val = next_pt(pool_order)
            positions[n] = {'x': round(cx * scale, 2), 'y': round(cy_val * scale, 2)}
    return positions
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


@app.route("/campaigns")
def campaigns_page():
    """Campaign gallery — one card per artist showing co-mentioned brands and URL count."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PhishKnot — Campaigns</title>
<style>
  :root { --bg:#0b1020; --panel:#111a33; --text:#e7ecff; --muted:#aab4de; --border:rgba(255,255,255,0.12); --accent:#7aa2ff; --brand:#2ecc71; --artist:#e67e22; }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--text); font-family: system-ui, -apple-system, sans-serif; min-height: 100vh; }
  header { position: sticky; top: 0; z-index: 10; display: flex; align-items: center; gap: 12px; padding: 8px 16px; background: rgba(11,16,32,0.96); backdrop-filter: blur(10px); border-bottom: 1px solid var(--border); height: 48px; }
  .logo { font-size: 17px; font-weight: 700; color: var(--text); text-decoration: none; }
  .logo span { color: var(--accent); }
  nav a { font-size: 13px; color: var(--muted); text-decoration: none; padding: 4px 10px; border-radius: 8px; }
  nav a:hover { color: var(--text); background: rgba(255,255,255,0.06); }
  .page { max-width: 1100px; margin: 0 auto; padding: 24px 16px; }
  h1 { font-size: 22px; font-weight: 700; margin: 0 0 4px; }
  .subtitle { color: var(--muted); font-size: 13px; margin-bottom: 24px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 14px; }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 14px; overflow: hidden; display: flex; flex-direction: column; gap: 0; }
  .card-thumb-link { display: block; border-bottom: 1px solid var(--border); }
  .card-thumb { width: 100%; height: 220px; object-fit: cover; display: block; transition: opacity 0.15s; }
  .card-thumb-link:hover .card-thumb { opacity: 0.85; }
  .card-body { padding: 14px 16px 16px; display: flex; flex-direction: column; gap: 10px; }
  .card-header { display: flex; align-items: center; gap: 12px; }
  .avatar { width: 52px; height: 52px; border-radius: 999px; object-fit: cover; border: 2px solid var(--artist); flex-shrink: 0; background: rgba(230,126,34,0.15); }
  .card-title { font-size: 16px; font-weight: 600; }
  .card-stats { font-size: 11px; color: var(--muted); }
  .brands { display: flex; flex-wrap: wrap; gap: 4px; }
  .brand-tag { font-size: 11px; padding: 2px 8px; border-radius: 999px; background: rgba(46,204,113,0.15); color: var(--brand); border: 1px solid rgba(46,204,113,0.25); }
  #loading { color: var(--muted); font-size: 14px; padding: 40px 0; text-align: center; }
</style>
</head>
<body>
<header>
  <a class="logo" href="/">Phish<span>Knot</span></a>
  <nav>
    <a href="/graph/interactive">Graph</a>
    <a href="/campaigns">Campaigns</a>
  </nav>
  <div style="flex:1"></div>
  <div style="display:flex;align-items:center;gap:6px">
    <select id="timeRange" style="background:var(--panel);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:4px 8px;font-size:12px;cursor:pointer">
      <option value="1h">Last 1h</option>
      <option value="4h">Last 4h</option>
      <option value="12h">Last 12h</option>
      <option value="24h">Last 24h</option>
      <option value="3d">Last 3d</option>
      <option value="7d">Last 7d</option>
      <option value="30d">Last 30d</option>
      <option value="all" selected>All time</option>
      <option value="custom">Custom…</option>
    </select>
    <span id="customRange" style="display:none;align-items:center;gap:4px;font-size:12px;color:#aab4de">
      <input type="date" id="dateSince" style="background:var(--panel);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:4px 6px;font-size:12px;width:130px">
      <span>–</span>
      <input type="date" id="dateUntil" style="background:var(--panel);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:4px 6px;font-size:12px;width:130px">
    </span>
  </div>
</header>
<div class="page">
  <h1>Campaigns</h1>
  <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;margin-bottom:16px">
    <div class="subtitle" id="subtitle">Loading campaign data…</div>
    <div style="display:flex;align-items:center;gap:8px;font-size:13px;color:var(--muted)">
      Sort:
      <select id="sortMode" style="background:var(--panel);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:4px 8px;font-size:13px">
        <option value="last_seen">Last seen</option>
        <option value="first_seen">First seen</option>
        <option value="brand_count">Brand count</option>
        <option value="url_count">URL count</option>
      </select>
    </div>
  </div>
  <div class="grid" id="grid"><div id="loading">Loading…</div></div>
</div>
<script>
let _campaigns = [];
const TIME_HOURS_C = { "1h":1, "4h":4, "12h":12, "24h":24, "3d":72, "7d":168, "30d":720 };

function getTimeParamsC() {
  const preset = localStorage.getItem("pk_time") || "all";
  if (preset === "all") return "";
  if (preset === "custom") {
    const s = localStorage.getItem("pk_since") || "";
    const u = localStorage.getItem("pk_until") || "";
    const p = new URLSearchParams();
    if (s) p.set("since", s);
    if (u) p.set("until", u);
    return p.toString();
  }
  const h = TIME_HOURS_C[preset] || 0;
  if (!h) return "";
  const since = new Date(Date.now() - h * 3600 * 1000).toISOString().slice(0, 10);
  return `since=${since}`;
}

function initTimePickerC() {
  const sel = document.getElementById("timeRange");
  const customEl = document.getElementById("customRange");
  const sinceEl = document.getElementById("dateSince");
  const untilEl = document.getElementById("dateUntil");
  if (!sel) return;
  const saved = localStorage.getItem("pk_time") || "all";
  sel.value = saved;
  if (saved === "custom" && customEl) customEl.style.display = "flex";
  if (sinceEl) sinceEl.value = localStorage.getItem("pk_since") || "";
  if (untilEl) untilEl.value = localStorage.getItem("pk_until") || "";
  sel.addEventListener("change", () => {
    localStorage.setItem("pk_time", sel.value);
    if (customEl) customEl.style.display = sel.value === "custom" ? "flex" : "none";
    if (sel.value !== "custom") load();
  });
  if (sinceEl) sinceEl.addEventListener("change", () => { localStorage.setItem("pk_since", sinceEl.value); load(); });
  if (untilEl) untilEl.addEventListener("change", () => { localStorage.setItem("pk_until", untilEl.value); load(); });
}

function sortAndRender() {
  const mode = document.getElementById("sortMode").value;
  const sorted = [..._campaigns].sort((a, b) => {
    if (mode === "last_seen")   return (b.last_seen || "") < (a.last_seen || "") ? -1 : 1;
    if (mode === "first_seen")  return (a.first_seen || "") > (b.first_seen || "") ? -1 : 1;
    if (mode === "brand_count") return b.brand_count - a.brand_count;
    if (mode === "url_count")   return b.url_count - a.url_count;
    return 0;
  });
  document.getElementById("grid").innerHTML = sorted.map(c => {
    const img = c.image_url ? `<img class="avatar" src="${c.image_url}" alt="${c.label}" onerror="this.style.display='none'">` : `<div class="avatar" style="display:flex;align-items:center;justify-content:center;font-weight:700;font-size:18px;color:var(--artist)">${(c.label||"?")[0].toUpperCase()}</div>`;
    const brands = (c.brands || []).map(b => `<span class="brand-tag">${b}</span>`).join("");
    const stats = `${c.url_count} URL${c.url_count !== 1 ? "s" : ""} · ${c.brand_count} brand${c.brand_count !== 1 ? "s" : ""}`;
    const dates = (c.first_seen || c.last_seen)
      ? `<div style="font-size:11px;color:var(--muted);margin-top:2px">First: ${c.first_seen || "?"} · Last: ${c.last_seen || "?"}</div>`
      : "";
    const exploreHref = `/graph/interactive?focus_artist=${encodeURIComponent(c.label)}`;
    const thumb = c.thumb_url ? `<a class="card-thumb-link" href="${exploreHref}"><img class="card-thumb" src="${c.thumb_url}" alt="${c.label} campaign" onerror="this.parentElement.style.display='none'"></a>` : "";
    return `<div class="card">
      ${thumb}
      <div class="card-body">
        <div class="card-header">${img}<div><div class="card-title">${c.label}</div><div class="card-stats">${stats}</div>${dates}</div></div>
        <div class="brands">${brands || "<span style='color:var(--muted);font-size:11px'>No brands</span>"}</div>
      </div>
    </div>`;
  }).join("");
}

async function load() {
  const tq = getTimeParamsC();
  const resp = await fetch(`/campaigns/data${tq ? "?" + tq : ""}`);
  const data = await resp.json();
  _campaigns = data.campaigns || [];
  const subtitle = document.getElementById("subtitle");
  subtitle.textContent = `${_campaigns.length} artist-led campaign${_campaigns.length !== 1 ? "s" : ""} detected across ${data.total_brands || "?"} brands`;
  if (!_campaigns.length) { document.getElementById("grid").innerHTML = "<div style='color:var(--muted)'>No campaigns found.</div>"; return; }
  sortAndRender();
  document.getElementById("sortMode").addEventListener("change", sortAndRender);
}
initTimePickerC();
load().catch(e => { document.getElementById("grid").innerHTML = `<div style='color:#ffb3b3'>Error: ${e.message}</div>`; });
</script>
</body>
</html>"""


@app.route("/campaigns/data")
def campaigns_data():
    """Return per-artist campaign summaries from the current graph."""
    co = (request.args.get("co", "1") or "1").lower() in ("1", "true", "yes")
    since = (request.args.get("since") or "").strip()
    until = (request.args.get("until") or "").strip()
    gexf_path = _pick_dataset_gexf(co)
    G = _load_graph_from_gexf(gexf_path)
    if G is None:
        return jsonify({"campaigns": [], "total_brands": 0})

    try:
        import networkx as nx
        from phishing_brand_graph import _brand_artist_subgraph
        spotify_cache = _load_spotify_image_cache()
        H = _brand_artist_subgraph(G, max_nodes=2000)

        campaigns = []
        brand_set = set()
        for n in H.nodes():
            data = H.nodes[n] or {}
            if data.get("type") != "artist":
                continue
            label = data.get("label") or str(n)
            img = data.get("image_url") or ""
            if not img:
                s_img = _spotify_image_for_label(spotify_cache, label)
                img = s_img or f"/avatar/artist/{n}.svg"
            img = _proxify_spotify_image_url(img)

            neighbors = list(H.neighbors(n))
            brands = sorted(set(
                (H.nodes[nb] or {}).get("label") or str(nb)
                for nb in neighbors
                if (H.nodes[nb] or {}).get("type") == "brand"
            ))
            brand_set.update(brands)

            # Count URLs from original graph: artist -> url (successors in DiGraph)
            url_count = 0
            if n in G:
                neighbors_fn = G.successors if G.is_directed() else G.neighbors
                for nb in neighbors_fn(n):
                    if (G.nodes[nb] or {}).get("type") == "phishing_url":
                        url_count += 1

            if brands:
                import re as _re
                safe_id = _re.sub(r"[^a-zA-Z0-9_-]", "_", str(n))
                thumb_path = IMAGES_DIR / "campaign_thumbs" / f"{safe_id}.png"
                thumb_url = f"/campaign-thumb/{safe_id}.png" if thumb_path.is_file() else None
                campaigns.append({
                    "id": str(n),
                    "label": label,
                    "image_url": img,
                    "thumb_url": thumb_url,
                    "brands": brands,
                    "brand_count": len(brands),
                    "url_count": url_count,
                    "popularity": int(data.get("popularity") or 0),
                    "first_seen": None,
                    "last_seen": None,
                })

        # Pull first/last seen from url_history for each artist
        try:
            import sqlite3 as _sqlite3
            with _sqlite3.connect(str(DATA_DIR / "url_history.db")) as _conn:
                for c in campaigns:
                    _lbl = c["label"]
                    row = _conn.execute(
                        "SELECT MIN(first_seen), MAX(last_seen) FROM url_history "
                        "WHERE artists LIKE ?", (f'%"{_lbl}"%',)
                    ).fetchone()
                    if row and row[0]:
                        c["first_seen"] = row[0][:10]
                        c["last_seen"] = row[1][:10]
        except Exception:
            pass

        # Date filter
        if since or until:
            def _in_range(c):
                ls = c.get("last_seen") or ""
                fs = c.get("first_seen") or ""
                if since and ls and ls < since: return False
                if until and fs and fs > until: return False
                return True
            campaigns = [c for c in campaigns if _in_range(c)]
            brand_set = {b for c in campaigns for b in c["brands"]}

        campaigns.sort(key=lambda c: (c["last_seen"] or "0000-00-00", c["brand_count"], c["url_count"]), reverse=True)
        return jsonify({"campaigns": campaigns, "total_brands": len(brand_set)})
    except Exception as e:
        return jsonify({"campaigns": [], "error": str(e)})


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

    # Compound domain node diagnostics
    try:
        gexf_path = DATA_DIR / "phishing_graph.gexf"
        G = _load_graph_from_gexf(gexf_path)
        if G is not None:
            node_types = {}
            registered_domains = []
            for n, d in G.nodes(data=True):
                t = (d or {}).get("type", "unknown")
                node_types[t] = node_types.get(t, 0) + 1
                if t == "registered_domain":
                    label = (d or {}).get("label", str(n))
                    # Count domain children
                    children = [x for x, dx in G.nodes(data=True) if (dx or {}).get("parent_id") == n]
                    registered_domains.append({"label": label, "child_domains": len(children)})
            out["node_type_counts"] = node_types
            out["registered_domains"] = sorted(registered_domains, key=lambda x: -x["child_domains"])[:20]
        else:
            out["compound_debug"] = "GEXF not found or unreadable"
    except Exception as e:
        out["compound_debug_error"] = str(e)

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
  header { position: sticky; top: 0; z-index: 10; display: flex; align-items: center; gap: 10px; padding: 8px 12px; background: rgba(11,16,32,0.96); backdrop-filter: blur(10px); border-bottom: 1px solid var(--border); height: 48px; }
  .logo { font-size: 17px; font-weight: 700; letter-spacing: -0.01em; color: var(--text); white-space: nowrap; }
  .logo span { color: var(--accent); }
  header .stats { display: flex; align-items: center; gap: 6px; flex: 1; flex-wrap: wrap; }
  header .right { display: flex; align-items: center; gap: 8px; }
  .pill { border: 1px solid var(--border); background: rgba(0,0,0,0.15); padding: 4px 10px; border-radius: 999px; font-size: 11px; color: var(--muted); white-space: nowrap; }
  .pill strong { color: var(--text); }
  .btn { cursor: pointer; border: 1px solid var(--border); background: rgba(255,255,255,0.06); color: var(--text); padding: 6px 10px; border-radius: 8px; font-size: 13px; }
  .btn:hover { background: rgba(255,255,255,0.09); }
  .lens-group { display: flex; gap: 0; border-radius: 8px; overflow: hidden; border: 1px solid var(--border); }
  .lens-btn { flex: 1; cursor: pointer; border: none; border-right: 1px solid var(--border); background: rgba(255,255,255,0.04); color: var(--muted); padding: 7px 0; font-size: 12px; }
  .lens-btn:last-child { border-right: none; }
  .lens-btn:hover { background: rgba(255,255,255,0.09); color: var(--text); }
  .lens-btn.active { background: rgba(99,140,255,0.22); color: #a8bfff; font-weight: 600; }
  .layout { display: grid; grid-template-columns: 280px 1fr; min-height: calc(100vh - 48px); transition: grid-template-columns 0.25s ease; }
  .layout.panel-collapsed { grid-template-columns: 0px 1fr; }
  @media (max-width: 900px) { .layout { grid-template-columns: 1fr; } }
  .panel { border-right: 1px solid var(--border); background: var(--panel); padding: 12px; overflow: auto; transition: padding 0.25s; }
  .layout.panel-collapsed .panel { padding: 0; overflow: hidden; }
  .panel h2 { margin: 8px 0 10px; font-size: 12px; letter-spacing: 0.06em; color: var(--muted); text-transform: uppercase; }
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
  .graph { width: 100%; min-height: calc(100vh - 48px); background: #0a0f1f; }
  #graphWrap { position: relative; overflow: hidden; height: calc(100vh - 48px); }
  #graph { width: 100%; height: 100%; }
  #timelineBar { display: none; position: absolute; bottom: 0; left: 0; right: 0; height: 56px;
    background: rgba(10,15,31,0.94); border-top: 1px solid var(--border);
    padding: 0 14px; align-items: center; gap: 10px; z-index: 20;
    backdrop-filter: blur(6px); }
  #tlSlider { flex: 1; accent-color: var(--accent); cursor: pointer; height: 4px; }
  #tlDateLabel { font-size: 12px; color: var(--muted); white-space: nowrap; min-width: 86px; font-variant-numeric: tabular-nums; }
  .legend { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 10px; }
  .chip { display: inline-flex; align-items: center; gap: 6px; border: 1px solid rgba(255,255,255,0.12); background: rgba(0,0,0,0.12); padding: 4px 8px; border-radius: 999px; font-size: 12px; color: var(--muted); }
  .match-card { border: 1px solid rgba(255,255,255,0.08); border-radius: 8px; padding: 8px 10px; margin-bottom: 6px; background: rgba(0,0,0,0.12); }
  .match-card .mc-tags { display: flex; flex-wrap: wrap; gap: 4px; margin-bottom: 5px; }
  .match-card .mc-tag { font-size: 11px; padding: 2px 7px; border-radius: 999px; }
  .mc-tag.brand { background: rgba(46,204,113,0.18); color: #2ecc71; border: 1px solid rgba(46,204,113,0.3); }
  .mc-tag.artist { background: rgba(230,126,34,0.18); color: #e67e22; border: 1px solid rgba(230,126,34,0.3); }
  .match-card .mc-meta { font-size: 11px; color: var(--muted); margin-bottom: 4px; }
  .match-card .mc-url { font-size: 11px; word-break: break-all; }
  .match-card .mc-url a { color: var(--accent); }
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
  <button id="panelToggle" class="btn" type="button" title="Toggle controls">☰</button>
  <div class="logo">Phish<span>Knot</span></div>
  <a href="/campaigns" style="font-size:12px;color:var(--muted);text-decoration:none;white-space:nowrap;padding:4px 8px;border-radius:8px;border:1px solid var(--border)">Campaigns</a>
  <div class="stats">
    <div id="statBrands" class="pill">Brands: —</div>
    <div id="statArtists" class="pill">Artists: —</div>
    <div id="statUrls" class="pill">URLs: —</div>
    <div id="statRun" class="pill">Run: —</div>
    <div id="status" class="pill" style="display:none">Loading…</div>
  </div>
  <div class="right" style="display:flex;align-items:center;gap:6px">
    <select id="timeRange" class="btn" style="padding:5px 8px;font-size:12px;cursor:pointer" title="Time range filter">
      <option value="1h">Last 1h</option>
      <option value="4h">Last 4h</option>
      <option value="12h">Last 12h</option>
      <option value="24h">Last 24h</option>
      <option value="3d">Last 3d</option>
      <option value="7d">Last 7d</option>
      <option value="30d">Last 30d</option>
      <option value="all" selected>All time</option>
      <option value="custom">Custom…</option>
    </select>
    <span id="customRange" style="display:none;align-items:center;gap:4px;font-size:12px;color:var(--muted)">
      <input type="date" id="dateSince" style="background:var(--panel);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:4px 6px;font-size:12px;width:130px">
      <span>–</span>
      <input type="date" id="dateUntil" style="background:var(--panel);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:4px 6px;font-size:12px;width:130px">
    </span>
    <button id="refreshBtn" class="btn" type="button">↺ Refresh</button>
    <button id="downloadPng" class="btn" type="button">⬇ PNG</button>
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
          <option value="focus" selected>Brands + Artists + Domains</option>
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
          <button class="lens-btn" data-lens="both" type="button">Both</button>
          <button class="lens-btn active" data-lens="artist" type="button">Artist</button>
          <button class="lens-btn" data-lens="brand" type="button">Brand</button>
        </div>
      </div>
    </div>
    <div class="field">
      <div class="label">Layout</div>
      <div class="value">
        <select id="layoutPreset">
          <option value="groups">Groups (domain clusters)</option>
          <option value="campaign">Campaign (concentric)</option>
          <option value="network" selected>Network (force-directed)</option>
          <option value="3d">3D Perspective</option>
          <option value="julia">Julia set</option>
          <option value="julia3d">3D Julia set</option>
          <option value="circle">Circle</option>
          <option value="grid">Grid</option>
        </select>
      </div>
    </div>
    <div class="field" style="grid-column:1/-1;display:flex;gap:6px">
      <button class="btn" id="rerunLayout" style="flex:1">Re-run</button>
      <button class="btn" id="fitGraph" style="flex:1">Fit</button>
      <button class="btn" id="toggleEdges" style="flex:1">Edges</button>
      <button class="btn" id="toggleLabels" style="flex:1">Labels</button>
    </div>
    <div class="field" id="rotateField" style="display:none">
      <div class="label"> </div>
      <div class="value">
        <button class="btn" id="rotate3DBtn" style="width:100%">&#9654; Rotate</button>
      </div>
    </div>
    <div class="field">
      <div class="label">Search</div>
      <div class="value">
        <input id="searchBox" type="text" placeholder="Find node label (e.g., ccb / Yeat / domain)" />
      </div>
    </div>

    <details id="juliaDetails" style="display:none">
      <summary style="cursor:pointer;color:var(--muted);font-size:13px;padding:6px 0">Julia set c</summary>
      <div style="padding:4px 0">
        <div class="field"><div class="label" style="font-size:12px">Preset</div>
          <div class="value">
            <select id="juliaCPreset" style="width:100%" onchange="onJuliaCPresetChange()">
              <option value="-0.7+0.27j">Classic dendrite</option>
              <option value="-0.4+0.6j">Douady&#39;s rabbit</option>
              <option value="0.285+0.01j">Cauliflower</option>
              <option value="-0.835-0.2321j">Fine filaments</option>
              <option value="-1.755+0j">Airplane</option>
              <option value="-2.1+0j">Cantor dust</option>
              <option value="0+1j">Unit circle</option>
              <option value="-1+0j">Basilica</option>
              <option value="custom">Custom&hellip;</option>
            </select>
          </div>
        </div>
        <div class="field" id="juliaCCustomField" style="display:none">
          <div class="label" style="font-size:12px">c (a+bj)</div>
          <div class="value">
            <input id="juliaCCustom" type="text" value="-0.7+0.27j" placeholder="-0.7+0.27j" style="width:100%">
          </div>
        </div>
        <div class="field"><div class="label" style="font-size:12px">Resolution</div>
          <div class="value"><input id="juliaRes" type="range" min="200" max="800" step="100" value="600" style="width:100%">
          <span id="juliaResVal" style="font-size:11px;color:var(--muted)">600</span></div></div>
        <div class="field"><div class="label" style="font-size:12px">Max iter</div>
          <div class="value"><input id="juliaIter" type="range" min="64" max="512" step="64" value="256" style="width:100%">
          <span id="juliaIterVal" style="font-size:11px;color:var(--muted)">256</span></div></div>
      </div>
    </details>

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
      <summary>Matches</summary>
      <div class="content">
        <div id="matchesFilter" style="margin-bottom:8px;font-size:11px;color:var(--muted)">All matches — click a brand or artist chip to filter.</div>
        <div id="matchesTableWrap"></div>
      </div>
    </details>
    <div id="error" class="error" style="display:none"></div>
  </div>
  <div id="graphWrap">
    <div id="graph" class="graph"></div>
    <div id="timelineBar">
      <button class="btn" id="tlPlayBtn" style="min-width:34px;padding:5px 8px" title="Play/Pause">&#9654;</button>
      <button class="btn" id="tlResetBtn" style="padding:5px 8px;font-size:13px" title="Reset to start">&#8635;</button>
      <span id="tlDateLabel">—</span>
      <input type="range" id="tlSlider" min="0" max="10000" value="0">
      <span style="font-size:12px;color:var(--muted)">Speed</span>
      <select id="tlSpeed" style="background:var(--panel);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:3px 6px;font-size:12px">
        <option value="7">7 d/s</option>
        <option value="30" selected>30 d/s</option>
        <option value="90">90 d/s</option>
        <option value="365">1 yr/s</option>
      </select>
    </div>
  </div>
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

// ── Time range picker (shared logic, persisted in localStorage) ──────────────
const TIME_HOURS = { "1h":1, "4h":4, "12h":12, "24h":24, "3d":72, "7d":168, "30d":720 };

function initTimePicker(onChangeFn) {
  const sel = el("timeRange");
  const customEl = el("customRange");
  const sinceEl = el("dateSince");
  const untilEl = el("dateUntil");
  if (!sel) return;

  // Restore from localStorage
  const saved = localStorage.getItem("pk_time") || "all";
  sel.value = saved;
  if (saved === "custom") {
    if (customEl) customEl.style.display = "flex";
    if (sinceEl) sinceEl.value = localStorage.getItem("pk_since") || "";
    if (untilEl) untilEl.value = localStorage.getItem("pk_until") || "";
  }

  sel.addEventListener("change", () => {
    localStorage.setItem("pk_time", sel.value);
    if (customEl) customEl.style.display = sel.value === "custom" ? "flex" : "none";
    if (sel.value !== "custom") onChangeFn();
  });
  if (sinceEl) sinceEl.addEventListener("change", () => { localStorage.setItem("pk_since", sinceEl.value); onChangeFn(); });
  if (untilEl) untilEl.addEventListener("change", () => { localStorage.setItem("pk_until", untilEl.value); onChangeFn(); });
}

function getTimeParams() {
  const preset = localStorage.getItem("pk_time") || "all";
  if (preset === "all") return { since: "", until: "" };
  if (preset === "custom") {
    return { since: localStorage.getItem("pk_since") || "", until: localStorage.getItem("pk_until") || "" };
  }
  const h = TIME_HOURS[preset] || 0;
  if (!h) return { since: "", until: "" };
  const since = new Date(Date.now() - h * 3600 * 1000).toISOString().slice(0, 10);
  return { since, until: "" };
}
// ─────────────────────────────────────────────────────────────────────────────

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
  const { since, until } = getTimeParams();
  const params = new URLSearchParams({ co, view, max_nodes: String(maxNodes), lens });
  if (since) params.set("since", since);
  if (until) params.set("until", until);
  return params.toString();
}

async function fetchJSON(url){
  const r = await fetch(url, { cache: "no-store" });
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  return await r.json();
}

function renderMeta(meta){
  const rs = meta.run_stats || {};
  const ds = meta.display_stats || {};
  const img = meta.image_summary || {};
  const counts = meta.counts || {};
  // Header stat pills
  const sb = el("statBrands"); if (sb) sb.innerHTML = `<strong>${ds.brands_count ?? rs.display_brands ?? "?"}</strong> brands`;
  const sa = el("statArtists"); if (sa) sa.innerHTML = `<strong>${ds.artists_count ?? rs.display_artists ?? "?"}</strong> artists`;
  const su = el("statUrls"); if (su) su.innerHTML = `<strong>${counts.urls_processed ?? "?"}</strong> URLs`;
  const sr = el("statRun");
  if (sr && meta.generated_at_utc) {
    const d = new Date(meta.generated_at_utc);
    sr.innerHTML = `Run: <strong>${d.toLocaleTimeString([], {hour:"2-digit",minute:"2-digit"})}</strong>`;
  }

  el("runSummary").innerHTML = `
    <div><b>Dataset</b>: ${meta.dataset_label || "—"}</div>
    <div><b>URLs processed</b>: ${meta.counts?.urls_processed ?? "?"} (download_failed=${meta.counts?.download_failed ?? "0"})</div>
    <div><b>Kept</b>: any_match=${meta.counts?.kept_any_match ?? "?"}, brand=${meta.counts?.kept_brand ?? "?"}, artist=${meta.counts?.kept_artist ?? "?"}, both=${meta.counts?.kept_both ?? "?"}</div>
    <div><b>Mode</b>: NO_DOWNLOAD=${fmtBool(meta.config?.NO_DOWNLOAD)}, CO_OCCURRENCE_ONLY(env)=${fmtBool(meta.config?.CO_OCCURRENCE_ONLY)}</div>
    <div><b>Artist images</b>: spotify=${img.spotify_artist_images ?? "?"} / artists=${img.artists_total ?? "?"} (fallback avatars for the rest)</div>
  `;
}

function _buildMatchCards(rows) {
  if (!rows.length) return "<div style='color:var(--muted);font-size:12px'>No matches.</div>";
  const html = [];
  for (const r of rows) {
    const brands = (r.brands || []);
    const artists = (r.artists || []).map(a => a.name || a.artist_keyword).filter(Boolean);
    const md = r.match_detail || {};
    const prov = [
      (md.brands_in_url?.length ? `brands:url(${md.brands_in_url.length})` : ""),
      (md.brands_in_text?.length ? `brands:text(${md.brands_in_text.length})` : ""),
      (md.artists_in_url?.length ? `artists:url(${md.artists_in_url.length})` : ""),
      (md.artists_in_text?.length ? `artists:text(${md.artists_in_text.length})` : ""),
    ].filter(Boolean).join(" · ");
    html.push(`<div class="match-card">`);
    html.push(`<div class="mc-tags">`);
    brands.forEach(b => html.push(`<span class="mc-tag brand">${b}</span>`));
    artists.forEach(a => html.push(`<span class="mc-tag artist">${a}</span>`));
    html.push(`</div>`);
    if (prov) html.push(`<div class="mc-meta">${prov} &nbsp;·&nbsp; ${r.domain || ""}</div>`);
    html.push(`<div class="mc-url"><a href="${r.url}" target="_blank" rel="noreferrer noopener">${r.url || ""}</a></div>`);
    html.push(`</div>`);
  }
  return html.join("");
}

function renderMatches(matches){
  if (!matches || !Array.isArray(matches.results)) {
    el("matchesTableWrap").innerHTML = "<div style='color:var(--muted)'>No match data available.</div>";
    return;
  }
  el("matchesTableWrap").innerHTML = _buildMatchCards(matches.results.slice(0, 250));
}

function filterMatches(label, type) {
  if (!state.matches || !Array.isArray(state.matches.results)) return;
  const filterEl = el("matchesFilter");
  if (!label) {
    el("matchesTableWrap").innerHTML = _buildMatchCards(state.matches.results.slice(0, 250));
    if (filterEl) filterEl.textContent = "All matches — click a brand or artist chip to filter.";
    return;
  }
  const lc = label.toLowerCase();
  const filtered = state.matches.results.filter(r => {
    if (type === "brand") return (r.brands || []).some(b => b.toLowerCase() === lc);
    if (type === "artist") return (r.artists || []).some(a => (a.name || a.artist_keyword || "").toLowerCase() === lc);
    return false;
  });
  el("matchesTableWrap").innerHTML = _buildMatchCards(filtered);
  if (filterEl) filterEl.textContent = `Showing ${filtered.length} match${filtered.length !== 1 ? "es" : ""} for "${label}" — click chip again to clear.`;
}

function colorForType(t){
  if (t === "brand") return "#2ecc71";
  if (t === "artist") return "#e67e22";
  if (t === "domain") return "#9b59b6";
  return "#95a5a6";
}

let _serverPos = {};  // server-computed babbleknot positions, keyed by node id

function layoutCompoundChildren() {
  if (!cy) return;
  cy.nodes('[type="registered_domain"]').forEach(parent => {
    const children = parent.children().filter(':visible');
    if (children.length === 0) return;
    const n = children.length;
    const radius = Math.max(40, n * 18);
    const cx = parent.position('x');
    const cy_y = parent.position('y');
    children.forEach((child, i) => {
      const angle = (2 * Math.PI * i / n) - Math.PI / 2;
      child.position({
        x: cx + radius * Math.cos(angle),
        y: cy_y + radius * Math.sin(angle),
      });
    });
  });
}

// After layoutCompoundChildren expands children into circles, compound bounding boxes
// may still overlap because CoSE placed the group centers close. This iteratively
// pushes overlapping groups apart until none of their bounding boxes touch.
function separateCompoundGroups() {
  if (!cy) return;
  const parents = cy.nodes('[type="registered_domain"]').filter(':visible');
  if (parents.length < 2) return;
  const PADDING = 60;
  let anyOverlap = true;
  let iters = 0;
  while (anyOverlap && iters < 80) {
    anyOverlap = false;
    iters++;
    for (let i = 0; i < parents.length; i++) {
      for (let j = i + 1; j < parents.length; j++) {
        const a = parents[i], b = parents[j];
        const ba = a.boundingBox(), bb = b.boundingBox();
        const ox = Math.min(ba.x2, bb.x2) - Math.max(ba.x1, bb.x1);
        const oy = Math.min(ba.y2, bb.y2) - Math.max(ba.y1, bb.y1);
        if (ox <= 0 || oy <= 0) continue;
        anyOverlap = true;
        const cax = (ba.x1 + ba.x2) / 2, cay = (ba.y1 + ba.y2) / 2;
        const cbx = (bb.x1 + bb.x2) / 2, cby = (bb.y1 + bb.y2) / 2;
        let dx = cbx - cax, dy = cby - cay;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        dx /= dist; dy /= dist;
        // Push along the axis of least overlap so movement is minimal
        const push = (ox < oy ? ox : oy) / 2 + PADDING / 2;
        a.children().forEach(c => c.position({ x: c.position('x') - dx * push, y: c.position('y') - dy * push }));
        b.children().forEach(c => c.position({ x: c.position('x') + dx * push, y: c.position('y') + dy * push }));
      }
    }
  }
}

function afterGroupsLayout() {
  layoutCompoundChildren();
  separateCompoundGroups();
}

// ── 3D Perspective + rotation ────────────────────────────────────────────────
// _3d_base: node_id → {x0, y0, z0} centered, normalized to ±400
// Two rotation angles: _3d_angle (Y-axis, horizontal) + _3d_tilt (X-axis, vertical)
let _3d_base = {}, _3d_screenCx = 0, _3d_screenCy = 0;
let _3d_angle = 0, _3d_tilt = 0;
let _3d_raf = null, _3d_spinning = false, _3d_last_ts = 0;
let _3d_drag = null; // { x, y, startAngle, startTilt, wasSpinning }
const FOCAL_3D = 2000;
const ROT_SPEED = 0.007; // radians per 16ms (≈60fps baseline)

// Core render: apply Ry(_3d_angle) then Rx(_3d_tilt), project, update styles.
function _3d_render_frame() {
  if (!cy || !Object.keys(_3d_base).length) return;
  const cosA = Math.cos(_3d_angle), sinA = Math.sin(_3d_angle);
  const cosT = Math.cos(_3d_tilt),  sinT = Math.sin(_3d_tilt);
  cy.batch(() => {
    cy.nodes(':visible').filter(n => n.data('type') !== 'registered_domain').forEach(n => {
      const b = _3d_base[n.id()];
      if (!b) return;
      // Ry(angle): rotate around Y
      const xr  = b.x0 * cosA + b.z0 * sinA;
      const zry = -b.x0 * sinA + b.z0 * cosA;
      // Rx(tilt): rotate around X
      const yr  = b.y0 * cosT - zry * sinT;
      const zr  = b.y0 * sinT + zry * cosT;
      const s   = FOCAL_3D / (FOCAL_3D + zr);
      n.position({ x: _3d_screenCx + xr * s, y: _3d_screenCy + yr * s });
      const tlHidden = n.hasClass('tl-hidden');
      n.style({
        'width':     Math.max(5, (n.data('size')      || 34) * s),
        'height':    Math.max(5, (n.data('size')      || 34) * s),
        'opacity':   tlHidden ? 0 : Math.max(0.15, 0.3 + s * 0.7),
        'font-size': Math.max(5, (n.data('font_size') || 10) * s),
      });
    });
  });
}

function stop3DRotation() {
  if (_3d_raf) { cancelAnimationFrame(_3d_raf); _3d_raf = null; }
  _3d_spinning = false;
  const btn = el('rotate3DBtn');
  if (btn) btn.innerHTML = '&#9654; Rotate';
}

function _apply3DFrame(ts) {
  if (!cy || !_3d_spinning) return;
  const dt = (_3d_last_ts && ts > _3d_last_ts) ? Math.min(ts - _3d_last_ts, 50) : 16;
  _3d_last_ts = ts;
  _3d_angle += ROT_SPEED * (dt / 16);
  _3d_render_frame();
  _3d_raf = requestAnimationFrame(_apply3DFrame);
}

function start3DRotation() {
  stop3DRotation();
  if (!Object.keys(_3d_base).length) return;
  _3d_spinning = true;
  _3d_last_ts = 0;
  const btn = el('rotate3DBtn');
  if (btn) btn.innerHTML = '&#9646;&#9646; Pause';
  _3d_raf = requestAnimationFrame(_apply3DFrame);
}

let _3d_wheel_handler = null;

function _3d_enable_interaction() {
  if (!cy) return;
  cy.userPanningEnabled(false);
  cy.userZoomingEnabled(false);   // disable cy's mouse-position zoom (causes translation)
  cy.nodes().ungrabify();
  const g = el('graph');
  if (!g) return;
  g.style.cursor = 'grab';
  // Replace with viewport-center zoom so scroll never translates the graph
  _3d_wheel_handler = (e) => {
    e.preventDefault();
    const factor = e.deltaY < 0 ? 1.15 : (1 / 1.15);
    cy.zoom({ level: cy.zoom() * factor,
              renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
  };
  g.addEventListener('wheel', _3d_wheel_handler, { passive: false });
}

function _3d_disable_interaction() {
  if (!cy) return;
  cy.userPanningEnabled(true);
  cy.userZoomingEnabled(true);
  cy.nodes().grabify();
  const g = el('graph');
  if (!g) return;
  g.style.cursor = '';
  if (_3d_wheel_handler) {
    g.removeEventListener('wheel', _3d_wheel_handler);
    _3d_wheel_handler = null;
  }
}

// 3D Perspective preset: run CoSE for base X/Y, assign Z by node type + degree,
// normalize, store _3d_base, then start rotation and enable drag interaction.
function run3DLayout() {
  if (!cy) return;
  stop3DRotation();
  _3d_base = {};
  const baseLayout = cy.layout({
    name: 'cose', animate: false, fit: false, padding: 40,
    ..._coseRepulsionOpts(), nestingFactor: 1.2, componentSpacing: 80,
  });
  baseLayout.one('layoutstop', () => {
    const Z_BASE = { artist: 200, brand: 500, domain: 800, registered_domain: 1100 };
    let maxDeg = 1;
    cy.nodes().forEach(n => { if ((n.data('degree') || 0) > maxDeg) maxDeg = n.data('degree'); });
    const visible = cy.nodes(':visible').filter(n => n.data('type') !== 'registered_domain');
    let sumX = 0, sumY = 0;
    visible.forEach(n => { sumX += n.position().x; sumY += n.position().y; });
    const cx = visible.length ? sumX / visible.length : 0;
    const cy_c = visible.length ? sumY / visible.length : 0;
    let maxR = 1;
    visible.forEach(n => {
      const dx = n.position().x - cx, dy = n.position().y - cy_c;
      const r = Math.sqrt(dx*dx + dy*dy);
      if (r > maxR) maxR = r;
    });
    const norm = Math.min(1, 400 / maxR);
    visible.forEach(n => {
      const degN = (n.data('degree') || 0) / maxDeg;
      const z0 = Math.max(50, (Z_BASE[n.data('type')] ?? 800) - degN * 200);
      _3d_base[n.id()] = {
        x0: (n.position().x - cx) * norm,
        y0: (n.position().y - cy_c) * norm,
        z0,
      };
    });
    const vp = cy.extent();
    _3d_screenCx = (vp.x1 + vp.x2) / 2;
    _3d_screenCy = (vp.y1 + vp.y2) / 2;
    _3d_render_frame();
    cy.fit(undefined, 60);
    const vp2 = cy.extent();
    _3d_screenCx = (vp2.x1 + vp2.x2) / 2;
    _3d_screenCy = (vp2.y1 + vp2.y2) / 2;
    _3d_enable_interaction();
    start3DRotation();
  });
  baseLayout.run();
}

// 3D Julia: fetch Julia X/Y positions, then apply the same Z-assignment
// and perspective projection as run3DLayout().
async function run3DJuliaLayout() {
  if (!cy) return;
  stop3DRotation();
  _3d_base = {};
  const c    = _juliaGetC();
  const res  = (el('juliaRes')  || {}).value || 600;
  const iter = (el('juliaIter') || {}).value || 256;
  const statusEl = el('runStatus');
  const prev = statusEl ? statusEl.textContent : '';
  if (statusEl) statusEl.textContent = 'Computing Julia\u20133D\u2026';
  try {
    const resp = await fetch(`/graph/julia?c=${encodeURIComponent(c)}&res=${res}&iter=${iter}`);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    if (data.error) throw new Error(data.error);
    const pos = data.positions || {};
    cy.batch(() => {
      cy.nodes().forEach(n => {
        const p = pos[n.id()];
        if (p) n.position({ x: p.x, y: p.y });
      });
    });
  } catch (e) {
    console.error('Julia-3D layout error:', e);
    if (statusEl) statusEl.textContent = 'Julia-3D error: ' + e.message;
    return;
  }
  if (statusEl) statusEl.textContent = prev;

  // Same Z-assignment and rotation startup as run3DLayout()
  const Z_BASE = { artist: 200, brand: 500, domain: 800, registered_domain: 1100 };
  let maxDeg = 1;
  cy.nodes().forEach(n => { if ((n.data('degree') || 0) > maxDeg) maxDeg = n.data('degree'); });
  const visible = cy.nodes(':visible').filter(n => n.data('type') !== 'registered_domain');
  let sumX = 0, sumY = 0;
  visible.forEach(n => { sumX += n.position().x; sumY += n.position().y; });
  const cx   = visible.length ? sumX / visible.length : 0;
  const cy_c = visible.length ? sumY / visible.length : 0;
  let maxR = 1;
  visible.forEach(n => {
    const dx = n.position().x - cx, dy = n.position().y - cy_c;
    const r = Math.sqrt(dx*dx + dy*dy);
    if (r > maxR) maxR = r;
  });
  const norm = Math.min(1, 400 / maxR);
  visible.forEach(n => {
    const degN = (n.data('degree') || 0) / maxDeg;
    const z0 = Math.max(50, (Z_BASE[n.data('type')] ?? 800) - degN * 200);
    _3d_base[n.id()] = {
      x0: (n.position().x - cx) * norm,
      y0: (n.position().y - cy_c) * norm,
      z0,
    };
  });
  const vp = cy.extent();
  _3d_screenCx = (vp.x1 + vp.x2) / 2;
  _3d_screenCy = (vp.y1 + vp.y2) / 2;
  _3d_render_frame();
  cy.fit(undefined, 60);
  const vp2 = cy.extent();
  _3d_screenCx = (vp2.x1 + vp2.x2) / 2;
  _3d_screenCy = (vp2.y1 + vp2.y2) / 2;
  _3d_enable_interaction();
  start3DRotation();
}

// ── Mouse-drag rotation ──────────────────────────────────────────────────────
// Drag left/right → Y-axis (angle); drag up/down → X-axis (tilt).
// Dragging pauses the RAF loop; releasing resumes it if it was spinning.
(function() {
  const SENS = 0.007; // radians per pixel
  const graphDiv = el('graph');
  if (!graphDiv) return;

  graphDiv.addEventListener('mousedown', (e) => {
    if (!Object.keys(_3d_base).length) return;
    e.preventDefault();
    const wasSpinning = _3d_spinning;
    if (_3d_raf) { cancelAnimationFrame(_3d_raf); _3d_raf = null; }
    _3d_spinning = false;
    _3d_drag = { x: e.clientX, y: e.clientY, startAngle: _3d_angle, startTilt: _3d_tilt, wasSpinning };
    graphDiv.style.cursor = 'grabbing';
  });

  window.addEventListener('mousemove', (e) => {
    if (!_3d_drag) return;
    const dx = e.clientX - _3d_drag.x;
    const dy = e.clientY - _3d_drag.y;
    _3d_angle = _3d_drag.startAngle + dx * SENS;
    _3d_tilt  = Math.max(-Math.PI / 2, Math.min(Math.PI / 2,
                  _3d_drag.startTilt + dy * SENS));
    _3d_render_frame();
  });

  window.addEventListener('mouseup', () => {
    if (!_3d_drag) return;
    const resume = _3d_drag.wasSpinning;
    _3d_drag = null;
    const g = el('graph');
    if (g) g.style.cursor = Object.keys(_3d_base).length ? 'grab' : '';
    if (resume) start3DRotation();
  });
})();

// Groups preset: skip CoSE entirely for compound groups — manually place each in a grid,
// children arranged in a circle. Free nodes (brands/artists/standalone domains) get their
// own CoSE layout in the space to the right of the grid.
function runGroupsLayout() {
  if (!cy) return;
  const parents = cy.nodes('[type="registered_domain"]').filter(':visible');

  if (parents.length === 0) {
    cy.layout({ animate: false, fit: false, padding: 40, name: "cose",
                ..._coseRepulsionOpts(), nestingFactor: 1.2, componentSpacing: 80 }).run();
    return;
  }

  const PADDING = 80;
  const groups = [];
  parents.forEach(p => {
    const children = p.children().filter(':visible');
    if (children.length === 0) return;
    const n = children.length;
    const radius = Math.max(60, n * 20);
    groups.push({ parent: p, children, n, radius });
  });
  groups.sort((a, b) => b.radius - a.radius);

  const maxRadius = groups[0].radius;
  const cellSize = maxRadius * 2 + PADDING;
  const cols = Math.ceil(Math.sqrt(groups.length));
  const rows = Math.ceil(groups.length / cols);

  groups.forEach((g, i) => {
    const col = i % cols;
    const row = Math.floor(i / cols);
    const cx = col * cellSize + cellSize / 2;
    const cy_y = row * cellSize + cellSize / 2;
    g.children.forEach((child, j) => {
      const angle = (2 * Math.PI * j / g.n) - Math.PI / 2;
      child.position({ x: cx + g.radius * Math.cos(angle), y: cy_y + g.radius * Math.sin(angle) });
    });
  });

  // Place free nodes (not inside any compound group) in a CoSE layout alongside the grid
  const freeNodes = cy.nodes(':visible').filter(n =>
    n.data('type') !== 'registered_domain' && !n.data('parent')
  );
  if (freeNodes.length > 0) {
    const gridW = cols * cellSize;
    const gridH = rows * cellSize;
    freeNodes.layout({
      name: 'cose', animate: false, fit: false, padding: 20,
      boundingBox: { x1: gridW + PADDING, y1: 0,
                     w: Math.max(300, freeNodes.length * 25),
                     h: Math.max(300, gridH) },
      nodeRepulsion: 150000, idealEdgeLength: 300, numIter: 800,
    }).run();
  }
}

// ---------------------------------------------------------------------------
// Julia set layout
// ---------------------------------------------------------------------------

function onJuliaCPresetChange() {
  const sel = el('juliaCPreset');
  const customField = el('juliaCCustomField');
  if (sel && customField) customField.style.display = sel.value === 'custom' ? '' : 'none';
}

function _juliaGetC() {
  const sel = el('juliaCPreset');
  if (!sel || sel.value === 'custom') {
    return (el('juliaCCustom') || {}).value || '-0.7+0.27j';
  }
  return sel.value;
}

async function runJuliaLayout() {
  if (!cy || cy.elements().length === 0) return;
  const c   = _juliaGetC();
  const res  = (el('juliaRes')  || {}).value || 600;
  const iter = (el('juliaIter') || {}).value || 256;
  const statusEl = el('runStatus');
  const prev = statusEl ? statusEl.textContent : '';
  if (statusEl) statusEl.textContent = 'Computing Julia layout\u2026';
  try {
    const resp = await fetch(`/graph/julia?c=${encodeURIComponent(c)}&res=${res}&iter=${iter}`);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    if (data.error) throw new Error(data.error);
    const pos = data.positions || {};
    cy.batch(() => {
      cy.nodes().forEach(n => {
        const p = pos[n.id()];
        if (p) n.position({ x: p.x, y: p.y });
      });
    });
    cy.fit(undefined, 40);
  } catch (e) {
    console.error('Julia layout error:', e);
    if (statusEl) statusEl.textContent = 'Julia error: ' + e.message;
    return;
  }
  if (statusEl) statusEl.textContent = prev;
}

function _coseRepulsionOpts() {
  return {
    nodeRepulsion: parseInt(el("coseRepulsion")?.value || "55000", 10),
    idealEdgeLength: parseInt(el("coseEdgeLen")?.value || "220", 10),
    gravity: parseInt(el("coseGravity")?.value || "10", 10) / 100,
    numIter: parseInt(el("coseIter")?.value || "1000", 10),
    edgeElasticity: 0.35,
    nodeOverlap: 4,
  };
}

function getLayoutOpts(){
  const presetEl = el("layoutPreset");
  const preset = (presetEl && presetEl.value) ? presetEl.value : "network";

  if (preset === "groups") {
    // CoSE with aggressive compound group separation; fit:false so physics can spread freely.
    let maxGroupRadius = 100;
    if (cy) {
      cy.nodes('[type="registered_domain"]').forEach(p => {
        const n = p.children().filter(':visible').length;
        const r = Math.max(40, n * 22) + 60;
        if (r > maxGroupRadius) maxGroupRadius = r;
      });
    }
    return { animate: false, fit: false, padding: 40, name: "cose",
             ..._coseRepulsionOpts(),
             nestingFactor: 20,
             componentSpacing: Math.max(200, maxGroupRadius * 2),
             minNodeSpacing: 20 };
  }
  if (preset === "campaign") {
    // Concentric centered on selected node; fit:true ensures artist is visible on arrival.
    return { animate: false, fit: true, padding: 60, name: "concentric",
             concentric: (node) => node.degree(), levelWidth: () => 1 };
  }
  if (preset === "network") {
    // Standard force-directed, fits to viewport.
    return { animate: false, fit: true, padding: 40, name: "cose",
             ..._coseRepulsionOpts(),
             nestingFactor: 1.2, componentSpacing: 80 };
  }
  if (preset === "circle") {
    return { animate: false, fit: true, padding: 40, name: "circle" };
  }
  if (preset === "grid") {
    return { animate: false, fit: true, padding: 40, name: "grid" };
  }
  return { animate: false, fit: true, padding: 40, name: "concentric",
           concentric: (node) => node.degree(), levelWidth: () => 1 };
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
  // registered_domain compound parents must be added before their children
  const sortedNodes = [...nodes].sort((a, b) => {
    if (a.type === "registered_domain" && b.type !== "registered_domain") return -1;
    if (b.type === "registered_domain" && a.type !== "registered_domain") return 1;
    return 0;
  });
  for (const n of sortedNodes) {
    const data = {
      id: n.id,
      label: n.label,
      type: n.type,
      degree: n.degree || 0,
      image_url: absoluteImageUrl(fallbackImage(n)),
    };
    if (n.parent) data.parent = n.parent;
    const el = { data };
    if (!n.parent && n.x != null && n.y != null && Number.isFinite(n.x) && Number.isFinite(n.y)) {
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
    if (t === "registered_domain") return "#4a90d9";
    return "rgba(255,255,255,0.35)";
  };
  const bgColor = (t) => {
    if (t === "brand") return "rgba(46, 204, 113, 0.22)";
    if (t === "artist") return "rgba(230, 126, 34, 0.22)";
    if (t === "domain") return "rgba(155, 89, 182, 0.22)";
    if (t === "registered_domain") return "rgba(20, 30, 60, 0.85)";
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
      selector: "node[type='registered_domain']",
      style: {
        "shape": "roundrectangle",
        "background-color": "rgba(20, 30, 60, 0.85)",
        "background-image": "none",
        "border-width": 2,
        "border-color": "#4a90d9",
        "border-style": "dashed",
        "label": "data(label)",
        "text-valign": "top",
        "text-halign": "center",
        "text-margin-y": -6,
        "font-size": 12,
        "color": "#4a90d9",
        "padding": "20px",
      },
    },
    {
      selector: "node.focus-center",
      style: {
        "width": 90,
        "height": 90,
        "border-width": 4,
        "font-size": 14,
      },
    },
    {
      selector: "node.tl-hidden",
      style: { "opacity": 0 },
    },
    {
      selector: "edge.tl-hidden",
      style: { "opacity": 0 },
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
  const presetEl = el("layoutPreset");
  const currentPreset = (presetEl && presetEl.value) ? presetEl.value : "groups";

  if (cy) {
    stop3DRotation();
    if (currentPreset !== '3d') {
      _3d_disable_interaction();
      cy.nodes().removeStyle('width height opacity font-size');
    }
    cy.batch(() => {
      cy.elements().remove();
      cy.add(elements);
    });
    if (currentPreset === "groups") {
      runGroupsLayout();
    } else if (currentPreset === "3d") {
      run3DLayout();
    } else if (currentPreset === "julia") {
      runJuliaLayout();
    } else if (currentPreset === "julia3d") {
      run3DJuliaLayout();
    } else {
      const l = cy.layout(getLayoutOpts());
      l.one('layoutstop', afterGroupsLayout);
      l.run();
    }
    return;
  }

  el("graph").innerHTML = "";
  cy = cytoscape({
    container: el("graph"),
    elements,
    style: cyStyle,
    layout: { name: "preset", positions: () => ({ x: 0, y: 0 }) },
  });
  if (currentPreset === "groups") {
    runGroupsLayout();
  } else if (currentPreset === "3d") {
    run3DLayout();
  } else if (currentPreset === "julia") {
    runJuliaLayout();
  } else if (currentPreset === "julia3d") {
    run3DJuliaLayout();
  } else {
    cy.one('layoutstop', afterGroupsLayout);
    cy.layout(getLayoutOpts()).run();
  }

  cy.on("tap", "node", (evt) => {
    const node = evt.target;
    const nodeId = node.id();
    if (node.data("type") === "registered_domain") {
      const children = node.children();
      if (children.length > 0) {
        if (children.first().hidden()) {
          children.show();
          node.style("border-style", "dashed");
        } else {
          children.hide();
          node.style("border-style", "solid");
        }
        cy.fit(undefined, 40);
      }
      return;
    }
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
    filterMatches(null, null);
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
  if (!state.data) return;
  const n = state.data.nodes.find(x => x.id === nodeId);
  if (n && (n.type === "brand" || n.type === "artist")) filterMatches(n.label, n.type);
}

// ── Time animation ───────────────────────────────────────────────────────────
// Cumulative: nodes appear when playhead passes their first_seen date.
// Works in any layout preset including 3D (opacity handled by _3d_render_frame).
let _tl_times = {};          // node_id → first_seen epoch ms (null = always visible)
let _tl_playhead = 0;        // current playhead epoch ms
let _tl_range  = { min: 0, max: 0 };
let _tl_playing = false;
let _tl_raf_id  = null;
let _tl_last_wall = 0;       // wall-clock ms of last RAF call
let _tl_scrub_pending = false; // RAF gate for slider input — avoids mid-batch pile-up

function _tl_fmt_date(ms) {
  if (!ms) return "—";
  const d = new Date(ms);
  return d.getFullYear() + "-" +
    String(d.getMonth()+1).padStart(2,"0") + "-" +
    String(d.getDate()).padStart(2,"0");
}

function _tl_apply_playhead() {
  if (!cy) return;
  const ph = _tl_playhead;
  const is3d = ((el('layoutPreset') || {}).value === '3d') && Object.keys(_3d_base).length;
  cy.batch(() => {
    cy.nodes().forEach(n => {
      const fs = _tl_times[n.id()];
      const hide = fs != null && fs > ph;
      if (hide) {
        n.addClass('tl-hidden');
        n.style('opacity', 0);        // inline beats any class or chip-click leftover
      } else {
        n.removeClass('tl-hidden');
        if (!is3d) n.removeStyle('opacity'); // let layout / CSS handle non-3D opacity
      }
    });
    cy.edges().forEach(e => {
      const hide = e.source().hasClass('tl-hidden') || e.target().hasClass('tl-hidden');
      if (hide) {
        e.addClass('tl-hidden');
        e.style('opacity', 0);        // must be inline — chip-click may have set inline opacity:1
      } else {
        e.removeClass('tl-hidden');
        e.removeStyle('opacity');     // clear any stale inline opacity so CSS takes over
      }
    });
  });
  // In 3D mode let _3d_render_frame set depth-aware opacity for visible nodes
  if (is3d) _3d_render_frame();

  // Update slider + date label
  const range = _tl_range.max - _tl_range.min;
  const sliderVal = range > 0 ? Math.round((ph - _tl_range.min) / range * 10000) : 0;
  const slider = el('tlSlider');
  if (slider) slider.value = sliderVal;
  const lbl = el('tlDateLabel');
  if (lbl) lbl.textContent = _tl_fmt_date(ph);
}

function _tl_frame(wallNow) {
  if (!_tl_playing) return;
  const dt = _tl_last_wall ? (wallNow - _tl_last_wall) : 0;
  _tl_last_wall = wallNow;
  const speedDays = parseFloat((el('tlSpeed') || {}).value || 30);
  _tl_playhead = Math.min(_tl_range.max, _tl_playhead + dt * speedDays * 86400);
  _tl_apply_playhead();
  if (_tl_playhead >= _tl_range.max) {
    _tl_playing = false;
    const btn = el('tlPlayBtn');
    if (btn) btn.innerHTML = '&#9654;';
    return;
  }
  _tl_raf_id = requestAnimationFrame(_tl_frame);
}

function tlPlay() {
  if (_tl_range.max <= _tl_range.min) return;
  if (_tl_playhead >= _tl_range.max) _tl_playhead = _tl_range.min; // restart if at end
  _tl_playing = true;
  _tl_last_wall = 0;
  const btn = el('tlPlayBtn');
  if (btn) btn.innerHTML = '&#9646;&#9646;';
  _tl_raf_id = requestAnimationFrame(_tl_frame);
}

function tlPause() {
  _tl_playing = false;
  if (_tl_raf_id) { cancelAnimationFrame(_tl_raf_id); _tl_raf_id = null; }
  const btn = el('tlPlayBtn');
  if (btn) btn.innerHTML = '&#9654;';
}

function initTimeline(nodes) {
  tlPause();
  _tl_times = {};
  let minMs = Infinity, maxMs = -Infinity;
  (nodes || []).forEach(n => {
    const fs = n.first_seen ? Date.parse(n.first_seen) : null;
    if (fs && !isNaN(fs)) {
      _tl_times[n.id] = fs;
      if (fs < minMs) minMs = fs;
      if (fs > maxMs) maxMs = fs;
    }
  });
  const bar = el('timelineBar');
  if (!bar) return;
  if (minMs === Infinity) { bar.style.display = 'none'; return; }
  _tl_range = { min: minMs, max: maxMs };
  _tl_playhead = maxMs;   // start with all nodes visible; Play resets to min
  _tl_apply_playhead();   // sets slider position + clears any stale tl-hidden classes
  bar.style.display = 'flex';
}

(function() {
  const playBtn  = el('tlPlayBtn');
  const resetBtn = el('tlResetBtn');
  const slider   = el('tlSlider');
  if (playBtn)  playBtn.addEventListener('click',  () => { _tl_playing ? tlPause() : tlPlay(); });
  if (resetBtn) resetBtn.addEventListener('click', () => {
    tlPause();
    _tl_playhead = _tl_range.min;
    _tl_apply_playhead();
  });
  if (slider) slider.addEventListener('input', () => {
    tlPause();
    const frac = slider.value / 10000;
    _tl_playhead = _tl_range.min + frac * (_tl_range.max - _tl_range.min);
    // Gate apply through RAF — playhead is always current, but the expensive
    // batch + 3D render runs at most once per frame no matter how fast the scrub.
    if (!_tl_scrub_pending) {
      _tl_scrub_pending = true;
      requestAnimationFrame(() => { _tl_scrub_pending = false; _tl_apply_playhead(); });
    }
  });
})();

async function refreshAll(){
  try {
    setError("");
    const statusEl = el("status"); if (statusEl) { statusEl.style.display=""; statusEl.textContent = "Loading…"; }
    const q = buildQuery();
    const meta = await fetchJSON(`/graph/meta?${q}`);
    const data = await fetchJSON(`/graph/data?${q}`);
    const matches = await fetchJSON(`/graph/matches?${q}`);
    state.meta = meta;
    state.data = data;
    state.matches = matches;
    renderMeta(meta);
    renderMatches(matches);
    renderGraph(data);
    initTimeline(data.nodes || []);
    _activeChipId = null;
    if (cy && !Object.keys(_tl_times).length) cy.elements().style("opacity", 1);
    buildNodeChips(data.nodes || []);
    const statusEl2 = el("status"); if (statusEl2) statusEl2.style.display = "none";
  } catch (e) {
    setError(`Failed to load graph data: ${e.message}`);
    const statusEl3 = el("status"); if (statusEl3) { statusEl3.style.display=""; statusEl3.textContent = "Error"; }
  }
}

const panelToggle = el("panelToggle");
if (panelToggle) panelToggle.addEventListener("click", () => {
  const layout = document.querySelector(".layout");
  if (layout) {
    layout.classList.toggle("panel-collapsed");
    if (cy) cy.resize();
  }
});
const refreshBtn = el("refreshBtn");
if (refreshBtn) refreshBtn.addEventListener("click", refreshAll);
initTimePicker(refreshAll);
const downloadPng = el("downloadPng");
if (downloadPng) downloadPng.addEventListener("click", () => {
  if (!cy) return;
  const ts = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const a = document.createElement("a");
  a.href = cy.png({ full: true, scale: 2, bg: "#0d1117" });
  a.download = `phishknot_${ts}.png`;
  a.click();
});
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
function applyCurrentLayout() {
  if (!cy || cy.elements().length === 0) return;
  const presetEl = el("layoutPreset");
  const preset = (presetEl && presetEl.value) ? presetEl.value : "network";
  // Show/hide rotate button; stop rotation when leaving 3D
  const rotateField = el('rotateField');
  if (rotateField) rotateField.style.display = (preset === '3d' || preset === 'julia3d') ? '' : 'none';
  // Show/hide Julia controls
  const juliaDetails = el('juliaDetails');
  if (juliaDetails) juliaDetails.style.display = (preset === 'julia' || preset === 'julia3d') ? '' : 'none';
  if (preset !== '3d' && preset !== 'julia3d') {
    stop3DRotation();
    _3d_disable_interaction();
    cy.nodes().removeStyle('width height opacity font-size');
    cy.edges().removeStyle('opacity');
    _tl_apply_playhead(); // re-sync tl-hidden inline opacity after clearing 3D styles
  }
  if (preset === "groups") {
    runGroupsLayout();
  } else if (preset === "3d") {
    run3DLayout();
  } else if (preset === "julia") {
    runJuliaLayout();
  } else if (preset === "julia3d") {
    run3DJuliaLayout();
  } else {
    const l = cy.layout(getLayoutOpts());
    l.one('layoutstop', afterGroupsLayout);
    l.run();
  }
}
const layoutPresetEl = el("layoutPreset");
if (layoutPresetEl) layoutPresetEl.addEventListener("change", applyCurrentLayout);
const searchBox = el("searchBox");
if (searchBox) searchBox.addEventListener("keydown", (ev) => { if (ev.key === "Enter") applySearch(); });

// CoSE tuning sliders
[
  ["coseRepulsion", "coseRepulsionVal", v => v],
  ["coseEdgeLen",   "coseEdgeLenVal",   v => v],
  ["coseGravity",   "coseGravityVal",   v => (parseInt(v,10)/100).toFixed(2)],
  ["coseIter",      "coseIterVal",      v => v],
  ["juliaRes",      "juliaResVal",      v => v],
  ["juliaIter",     "juliaIterVal",     v => v],
].forEach(([sliderId, valId, fmt]) => {
  const s = el(sliderId);
  if (s) s.addEventListener("input", () => { const v = el(valId); if(v) v.textContent = fmt(s.value); });
});
const rerunLayout = el("rerunLayout");
if (rerunLayout) rerunLayout.addEventListener("click", applyCurrentLayout);
const fitGraph = el("fitGraph");
if (fitGraph) fitGraph.addEventListener("click", () => { if (cy) cy.fit(undefined, 40); });
const toggleEdges = el("toggleEdges");
if (toggleEdges) toggleEdges.addEventListener("click", () => {
  if (!cy) return;
  const hidden = cy.edges().first().hidden();
  if (hidden) { cy.edges().show(); toggleEdges.textContent = "Edges"; }
  else        { cy.edges().hide(); toggleEdges.textContent = "Edges \u25a0"; }
});
const toggleLabels = el("toggleLabels");
let _labelsHidden = false;
if (toggleLabels) toggleLabels.addEventListener("click", () => {
  if (!cy) return;
  _labelsHidden = !_labelsHidden;
  cy.nodes().style('label', _labelsHidden ? '' : 'data(label)');
  toggleLabels.textContent = _labelsHidden ? "Labels \u25a0" : "Labels";
});
const rotate3DBtn = el('rotate3DBtn');
if (rotate3DBtn) rotate3DBtn.addEventListener('click', () => {
  if (_3d_spinning) stop3DRotation(); else start3DRotation();
});


refreshAll().then(() => {
  const params = new URLSearchParams(window.location.search);
  const focusArtist = params.get("focus_artist");
  if (focusArtist) {
    const layoutSel = document.getElementById("layoutPreset");
    if (layoutSel) layoutSel.value = "campaign";
    const chip = [...document.querySelectorAll(".node-chip")].find(
      c => c.textContent.trim().toLowerCase() === focusArtist.toLowerCase()
    );
    if (cy && cy.elements().length > 0) {
      const graphEl = el("graph");
      if (graphEl) graphEl.style.visibility = "hidden";

      // Find the artist node and keep only its neighborhood — strip everything else
      // so the concentric layout radiates cleanly from the artist outward.
      const artistNode = cy.nodes().filter(n =>
        (n.data('label') || '').toLowerCase() === focusArtist.toLowerCase()
      );
      if (artistNode.length > 0) {
        const keep = artistNode.closedNeighborhood();
        cy.elements().not(keep).remove();
        artistNode.addClass('focus-center');
      }

      const l = cy.layout(getLayoutOpts());
      l.one('layoutstop', () => {
        cy.fit(undefined, 60);
        if (chip) chip.click();
        setTimeout(() => {
          cy.fit(undefined, 60);
          if (graphEl) graphEl.style.visibility = "visible";
        }, 350);
      });
      l.run();
    }
  }
});
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
    since = (request.args.get("since") or "").strip()
    until = (request.args.get("until") or "").strip()

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
            # Size: anchors large + readable, registered_domain compound, domain medium, url/other small
            if is_anchor:
                node_size = 80
                node_font_size = 14
            elif n_type == "registered_domain":
                node_size = 60
                node_font_size = 12
            elif n_type == "domain":
                node_size = 44
                node_font_size = 11
            else:
                node_size = 34
                node_font_size = 10
            node_entry = {
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
            }
            parent_id = (data.get("parent_id") or "").strip()
            if parent_id and parent_id in H:
                node_entry["parent"] = parent_id
            nodes.append(node_entry)

        node_ids = {n["id"] for n in nodes}

        # Always attach first_seen/last_seen per node from url_history (used by client animation
        # and date filtering). Single DB connection, one query per node.
        history_db = DATA_DIR / "url_history.db"
        if history_db.is_file():
            try:
                import sqlite3 as _sq3
                with _sq3.connect(str(history_db)) as _conn:
                    filtered_ids = set()
                    for node in nodes:
                        lbl = node["label"]
                        ntype = node["type"]
                        if ntype == "artist":
                            row = _conn.execute(
                                "SELECT MIN(first_seen), MAX(last_seen) FROM url_history WHERE artists LIKE ?",
                                (f'%"{lbl}"%',)).fetchone()
                        elif ntype == "brand":
                            row = _conn.execute(
                                "SELECT MIN(first_seen), MAX(last_seen) FROM url_history WHERE brands LIKE ?",
                                (f'%"{lbl}"%',)).fetchone()
                        elif ntype in ("domain", "registered_domain"):
                            row = _conn.execute(
                                "SELECT MIN(first_seen), MAX(last_seen) FROM url_history WHERE domain LIKE ?",
                                (f"%{lbl}%",)).fetchone()
                        else:
                            row = None
                        if row and row[0]:
                            node["first_seen"] = row[0][:10]
                            node["last_seen"]  = row[1][:10]
                            if since and node["last_seen"] < since:
                                filtered_ids.add(node["id"])
                            elif until and node["first_seen"] > until:
                                filtered_ids.add(node["id"])
                        elif since:
                            filtered_ids.add(node["id"])
                    if since or until:
                        nodes = [n for n in nodes if n["id"] not in filtered_ids]
                        node_ids = {n["id"] for n in nodes}
            except Exception:
                pass

        edges = []
        for u, v, data in H.edges(data=True):
            if str(u) not in node_ids or str(v) not in node_ids:
                continue
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


@app.route("/graph/julia")
def graph_julia():
    """
    Compute Julia set node positions and return {node_id: {x, y}}.
    Query params:
      c        — complex number string, Python notation e.g. -0.7+0.27j  (default -0.7+0.27j)
      res      — grid resolution (default 600, max 1000)
      iter     — max iterations (default 256, max 512)
      seed     — RNG seed (default 42)
      scale    — pixels per complex-plane unit (default 400)
      view     — passed to the subgraph selector (default focus)
      max_nodes— (default 500)
    """
    try:
        import numpy as np
        from phishing_brand_graph import _focus_subgraph, _subgraph_for_display

        c_str = (request.args.get("c") or "-0.7+0.27j").strip()
        try:
            c_val = complex(c_str.replace('i', 'j'))
        except ValueError:
            return jsonify({"error": f"Invalid c value: {c_str!r}"}), 400

        try:
            res = max(200, min(1000, int(request.args.get("res", 600))))
        except Exception:
            res = 600
        try:
            max_iter = max(64, min(512, int(request.args.get("iter", 256))))
        except Exception:
            max_iter = 256
        try:
            seed = int(request.args.get("seed", 42))
        except Exception:
            seed = 42
        try:
            scale = max(100, min(1200, int(request.args.get("scale", 400))))
        except Exception:
            scale = 400
        try:
            max_nodes = max(10, min(5000, int(request.args.get("max_nodes", 500))))
        except Exception:
            max_nodes = 500

        gexf_path = _pick_dataset_gexf(False)
        G = _load_graph_from_gexf(gexf_path)
        if G is None:
            return jsonify({"error": "No graph data available yet."}), 503

        H = _focus_subgraph(G)
        H = _subgraph_for_display(H, max_nodes)
        if H.number_of_nodes() == 0:
            return jsonify({"positions": {}})

        iters = _julia_iter_map(c_val, res=res, max_iter=max_iter)
        rng   = random.Random(seed)
        pools = _julia_build_pools(iters, res, 2.0, max_iter, rng)
        pos   = _julia_assign_positions(H, pools, rng, scale=scale)

        return jsonify({"c": str(c_val), "positions": pos})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


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


@app.route("/campaign-thumb/<filename>")
def serve_campaign_thumb(filename):
    """Serve a rendered campaign subgraph thumbnail PNG."""
    if not SAFE_FILENAME.match(filename):
        abort(404)
    path = IMAGES_DIR / "campaign_thumbs" / filename
    if not path.is_file():
        abort(404)
    return send_from_directory(IMAGES_DIR / "campaign_thumbs", filename, mimetype="image/png")


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
