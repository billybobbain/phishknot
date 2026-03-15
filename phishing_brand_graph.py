#!/usr/bin/env python3
"""
Phishing campaign explorer: brands and celebrities.
Uses OpenPhish (and optional PhishTank) feeds, keeps a local URL history in SQLite
so you get more URLs over time. Fetches pages, extracts text, matches brands/artists,
enriches with Spotify API, and builds a NetworkX graph.

SAFETY (Windows / no infection risk):
- We only DOWNLOAD raw bytes and parse as text. Nothing from the response
  is executed (no eval/exec, no browser, no scripts). So no drive-by or
  malware execution from page content.
- Optional NO_DOWNLOAD: set to True below to never request phishing URLs;
  only the OpenPhish feed is fetched; graph uses URL + domain only (no
  brand/artist from page body).
- When downloading: response size is capped and redirects limited to
  reduce exposure and parser attack surface.
"""

import hashlib
import os
import re
import json
import time
import csv
import sqlite3
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse, parse_qs, unquote
from pathlib import Path

import requests
from bs4 import BeautifulSoup
import networkx as nx

# -----------------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------------
OPENPHISH_FEED = "https://openphish.com/feed.txt"
SPOTIFY_TOKEN_URL = "https://accounts.spotify.com/api/token"
SPOTIFY_API_BASE = "https://api.spotify.com/v1"

# Base directory for all outputs. Set OUTPUT_DIR (e.g. /data on Railway) so data persists across restarts.
_OUTPUT_BASE = Path(os.environ.get("OUTPUT_DIR", "")).resolve() if os.environ.get("OUTPUT_DIR") else Path(__file__).resolve().parent
CACHE_DIR = _OUTPUT_BASE / "cache"
SPOTIFY_CACHE_FILE = CACHE_DIR / "spotify_artists.json"
EDGES_CSV = _OUTPUT_BASE / "graph_edges.csv"
URL_BRANDS_CSV = _OUTPUT_BASE / "url_brands.csv"  # Human-readable: URL, Domain, Brands, Artists
GRAPH_GEXF = _OUTPUT_BASE / "phishing_graph.gexf"
HISTORY_DB = _OUTPUT_BASE / "url_history.db"
CO_OCCURRENCE_GEXF = _OUTPUT_BASE / "co_occurrence.gexf"
CO_OCCURRENCE_CSV = _OUTPUT_BASE / "co_occurrence_urls.csv"
OUTPUT_IMAGES_DIR = _OUTPUT_BASE / "output"  # Rendered graph PNGs (latest.png, graph_*.png)

MAX_GEXF_NODES = 2000   # Cap nodes in GEXF so Gephi can layout; None = export full graph.
MAX_URLS = 50
REQUEST_DELAY = 1.0

# URL history: we keep every URL we've ever seen from feeds and process from this store (more URLs over time).
USE_URL_HISTORY = True
# Process all URLs in history, or only those seen in the last N days (None = all).
PROCESS_LAST_DAYS = None
# Cap how many URLs to process in one run from history (None = no cap).
MAX_URLS_FROM_HISTORY = None
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"

# Safety: skip fetching phishing page content entirely (only use OpenPhish URL list).
# Override with env: NO_DOWNLOAD=0 to fetch page content (e.g. in Docker).
NO_DOWNLOAD = os.environ.get("NO_DOWNLOAD", "true").lower() not in ("0", "false", "no")
MAX_RESPONSE_BYTES = 512 * 1024  # Cap HTML size (512 KB) to limit parser exposure.
MAX_REDIRECTS = 3

# Focus on "obscure" lures: only include URLs where BOTH at least one brand AND at least one artist were found.
# Override with env: CO_OCCURRENCE_ONLY=1 to keep only artist+brand-together cases.
CO_OCCURRENCE_ONLY = os.environ.get("CO_OCCURRENCE_ONLY", "").lower() in ("1", "true", "yes")

# Image export: max nodes to render (smaller = more readable; env MAX_IMAGE_NODES).
MAX_IMAGE_NODES = int(os.environ.get("MAX_IMAGE_NODES", "200"))

# Seed keywords for prototype (expand as needed)
BRAND_KEYWORDS = [
    "apple", "microsoft", "netflix", "amazon", "paypal", "google", "facebook",
    "instagram", "spotify", "adobe", "samsung", "dropbox", "linkedin", "twitter",
    "x.com", "outlook", "office365", "icloud", "amazon prime", "disney", "hbo",
    "chase", "bank of america", "wells fargo", "fedex", "ups", "dhl",
]

ARTIST_KEYWORDS = [
    "taylor swift", "beyonce", "beyoncé", "drake", "ed sheeran", "ariana grande",
    "the weeknd", "justin bieber", "bad bunny", "harry styles", "billie eilish",
    "dua lipa", "coldplay", "adele", "rihanna", "lady gaga", "bruno mars",
    "post malone", "travis scott", "kendrick lamar", "olivia rodrigo",
    "miley cyrus", "katy perry", "shawn mendes", "selena gomez", "nicki minaj",
    "eminem", "kanye", "ye", "bts", "blackpink",
]

# Optional second feed: PhishTank "online-valid". (PhishTank registration is often disabled; use URLhaus instead.)
PHISHTANK_APP_KEY = os.environ.get("PHISHTANK_APP_KEY", "")


def _phishtank_feed_url():
    if PHISHTANK_APP_KEY:
        return f"https://data.phishtank.com/data/{PHISHTANK_APP_KEY}/online-valid.json"
    return "https://data.phishtank.com/data/online-valid.json"

# -----------------------------------------------------------------------------
# URL history (local SQLite: accumulate URLs across runs for more volume)
# -----------------------------------------------------------------------------
def _get_history_conn():
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(HISTORY_DB))
    conn.row_factory = sqlite3.Row
    return conn


def init_history_db():
    """Create url_history table if it doesn't exist."""
    conn = _get_history_conn()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS url_history (
                url TEXT PRIMARY KEY,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                source TEXT NOT NULL
            )
        """)
        conn.commit()
    finally:
        conn.close()


def merge_urls_into_history(urls, source="openphish"):
    """Insert new URLs and update last_seen for existing ones. source = 'openphish' | 'phishtank'."""
    if not urls:
        return 0
    conn = _get_history_conn()
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    try:
        count = 0
        for url in urls:
            u = (url or "").strip()
            if not u:
                continue
            conn.execute(
                "INSERT INTO url_history (url, first_seen, last_seen, source) VALUES (?, ?, ?, ?) ON CONFLICT(url) DO UPDATE SET last_seen = excluded.last_seen, source = excluded.source",
                (u, now, now, source),
            )
            count += 1
        conn.commit()
        return count
    finally:
        conn.close()


def get_urls_from_history(limit=None, since_days=None):
    """Return list of URLs from history. since_days: only URLs with last_seen in last N days. limit: max count."""
    conn = _get_history_conn()
    try:
        if since_days is not None:
            since = (datetime.now(timezone.utc) - timedelta(days=since_days)).isoformat().replace("+00:00", "Z")
            query = "SELECT url FROM url_history WHERE last_seen >= ? ORDER BY last_seen DESC"
            cur = conn.execute(query, (since,))
        else:
            cur = conn.execute("SELECT url FROM url_history ORDER BY last_seen DESC")
        rows = cur.fetchall()
        urls = [r[0] for r in rows]
        if limit is not None:
            urls = urls[:limit]
        return urls
    finally:
        conn.close()


# -----------------------------------------------------------------------------
# OpenPhish & HTML
# -----------------------------------------------------------------------------
def fetch_phishing_urls(limit=None):
    """Fetch list of phishing URLs from OpenPhish feed."""
    r = requests.get(OPENPHISH_FEED, timeout=30, headers={"User-Agent": USER_AGENT})
    r.raise_for_status()
    lines = [line.strip() for line in r.text.strip().splitlines() if line.strip()]
    return lines[:limit] if limit else lines


def fetch_urlhaus_recent(limit=1000):
    """Fetch recent malware/phishing URLs from URLhaus (abuse.ch). Requires URLHAUS_AUTH_KEY from https://auth.abuse.ch/."""
    key = os.environ.get("URLHAUS_AUTH_KEY", "")
    if not key:
        return []
    # GET with optional limit in path (max 1000, past 3 days)
    url = f"https://urlhaus-api.abuse.ch/v1/urls/recent/limit/{min(limit, 1000)}/"
    r = requests.get(url, headers={"Auth-Key": key}, timeout=60)
    r.raise_for_status()
    data = r.json()
    if data.get("query_status") != "ok":
        return []
    urls = []
    for entry in data.get("urls") or []:
        u = entry.get("url") if isinstance(entry, dict) else None
        if u:
            urls.append(u.strip())
    return urls


def fetch_phishtank_urls():
    """Fetch current phishing URLs from PhishTank online-valid JSON. Set PHISHTANK_APP_KEY for unlimited downloads."""
    headers = {"User-Agent": f"phishtank/{os.environ.get('PHISHTANK_USER', 'user')}" if PHISHTANK_APP_KEY else USER_AGENT}
    r = requests.get(_phishtank_feed_url(), timeout=90, headers=headers)
    r.raise_for_status()
    data = r.json()
    # PhishTank JSON: array of {"url": "...", "phish_id": ..., ...}
    urls = []
    for entry in data if isinstance(data, list) else data.get("data", data.get("entries", [])):
        if isinstance(entry, dict) and entry.get("url"):
            urls.append(entry["url"].strip())
        elif isinstance(entry, str):
            urls.append(entry.strip())
    return urls


def download_page(url):
    """Download HTML for a URL; return (status_ok, html_text). Size and redirects limited."""
    try:
        session = requests.Session()
        session.max_redirects = MAX_REDIRECTS
        r = session.get(
            url,
            timeout=15,
            headers={"User-Agent": USER_AGENT},
            allow_redirects=True,
            stream=True,
        )
        r.raise_for_status()
        # Cap bytes read so we never load huge or maliciously large bodies
        chunks = []
        total = 0
        for chunk in r.iter_content(chunk_size=8192):
            if chunk:
                total += len(chunk)
                if total > MAX_RESPONSE_BYTES:
                    break
                chunks.append(chunk)
        body = b"".join(chunks)
        try:
            return True, body.decode("utf-8", errors="replace")
        except Exception:
            return False, ""
    except Exception:
        return False, ""


def extract_visible_text(html):
    """Extract visible text from HTML (strip script/style, normalize spaces)."""
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "meta", "head"]):
        tag.decompose()
    text = soup.get_text(separator=" ", strip=True)
    text = re.sub(r"\s+", " ", text).lower()
    return text


# -----------------------------------------------------------------------------
# Keyword matching
# -----------------------------------------------------------------------------
def find_brands_in_text(text):
    """Return set of brand keywords found in text (lowercase)."""
    found = set()
    for b in BRAND_KEYWORDS:
        if b in text:
            found.add(b)
    return found


def find_artists_in_text(text):
    """Return set of artist keywords found in text (lowercase)."""
    found = set()
    for a in ARTIST_KEYWORDS:
        if a in text:
            found.add(a)
    return found


def _text_chunks_from_url(url):
    """Extract path segments, query values, and domain parts (lowercased) for keyword matching."""
    try:
        parsed = urlparse(url)
        chunks = []
        # Path: split by / and - (e.g. /taylor-swift-tickets/login or /apple/verify)
        if parsed.path:
            for part in re.split(r"[/\-_.]+", unquote(parsed.path)):
                if len(part) > 1:
                    chunks.append(part.lower())
        # Query string values
        if parsed.query:
            for key, values in parse_qs(parsed.query).items():
                for v in values:
                    if v and len(v) < 200:
                        chunks.append(unquote(v).lower())
                if len(key) > 1:
                    chunks.append(unquote(key).lower())
        # Domain: subdomains and name (e.g. apple-login.evil.com -> apple, login, evil, com)
        if parsed.netloc:
            for part in re.split(r"[.\-]+", parsed.netloc):
                if len(part) > 1 and not part.isdigit():
                    chunks.append(part.lower())
        return " ".join(chunks)
    except Exception:
        return ""


def find_brands_in_url(url):
    """Return set of brand keywords found in URL path, query, or domain."""
    text = _text_chunks_from_url(url)
    return find_brands_in_text(text)


def find_artists_in_url(url):
    """Return set of artist keywords found in URL path, query, or domain."""
    text = _text_chunks_from_url(url)
    return find_artists_in_text(text)


# -----------------------------------------------------------------------------
# Spotify API (requests only, no spotipy)
# -----------------------------------------------------------------------------
def load_spotify_cache():
    """Load cached Spotify artist data."""
    if not SPOTIFY_CACHE_FILE.exists():
        return {}
    try:
        with open(SPOTIFY_CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_spotify_cache(cache):
    """Save Spotify cache to disk."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    with open(SPOTIFY_CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2)


def get_spotify_token(client_id, client_secret):
    """Get OAuth2 client credentials token."""
    r = requests.post(
        SPOTIFY_TOKEN_URL,
        data={"grant_type": "client_credentials"},
        auth=(client_id, client_secret),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=10,
    )
    r.raise_for_status()
    return r.json()["access_token"]


def spotify_search_artist(token, artist_name):
    """Search artist by name; return first match (id, name, popularity) or None."""
    r = requests.get(
        f"{SPOTIFY_API_BASE}/search",
        params={"q": artist_name, "type": "artist", "limit": 1},
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    if r.status_code != 200:
        return None
    data = r.json()
    items = data.get("artists", {}).get("items", [])
    if not items:
        return None
    artist = items[0]
    return {
        "id": artist["id"],
        "name": artist["name"],
        "popularity": artist.get("popularity", 0),
    }


def get_artist_popularity(client_id, client_secret, artist_name, cache):
    """
    Get artist popularity from Spotify, using cache.
    Returns dict with name, popularity, spotify_id or None if not found.
    """
    key = artist_name.lower().strip()
    if key in cache:
        return cache[key]
    token = get_spotify_token(client_id, client_secret)
    time.sleep(0.2)
    result = spotify_search_artist(token, artist_name)
    if result is None:
        cache[key] = None
        return None
    out = {
        "name": result["name"],
        "popularity": result["popularity"],
        "spotify_id": result["id"],
    }
    cache[key] = out
    return out


# -----------------------------------------------------------------------------
# Graph
# -----------------------------------------------------------------------------
def domain_from_url(url):
    """Extract registered domain (host) from URL."""
    try:
        parsed = urlparse(url)
        return parsed.netloc or ""
    except Exception:
        return ""


def _safe_gexf_id(prefix, value):
    """Return a string ID safe for GEXF (alphanumeric + underscore only)."""
    raw = f"{prefix}_{value}"
    h = hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:24]
    return f"{prefix}_{h}"


def _short_url_label_for_gexf(url, hostname_total_count=1):
    """
    Return a short, human-readable label for a phishing URL for Gephi visualization.
    Full URL is stored in node attribute 'full_url'. Long URL labels make the graph
    unreadable in Gephi, so we use hostname (and optionally first path segment
    when the same host appears many times) as the displayed label.
    """
    try:
        parsed = urlparse(url)
        host = (parsed.netloc or "").strip() or "unknown"
        path = (parsed.path or "").strip("/")
        segments = [s for s in path.split("/") if s]
        first_seg = ("/" + segments[0][:20]) if segments else ""
        # Add path-derived suffix only when same hostname appears multiple times to avoid identical labels
        if hostname_total_count > 1 and first_seg:
            label = host + first_seg
        else:
            label = host
        return (label[:50] or host).replace("\x00", "")
    except Exception:
        return "unknown"


def build_graph(results):
    """
    results: list of dicts, each:
      url, domain, brands (set), artists (list of dict), optional evidence (url_parse | page_content)
    Uses string-safe node IDs for GEXF; stores type, label (short for visualization), full_url,
    domain, title, popularity on nodes; relationship type and evidence source on edges.
    """
    G = nx.DiGraph()
    node_ids = {}  # (kind, key) -> safe_id

    def get_id(kind, key):
        if key is None or key == "":
            return None
        k = (kind, key)
        if k not in node_ids:
            node_ids[k] = _safe_gexf_id(kind, key)
        return node_ids[k]

    # Count domains so we can add path-derived suffix to URL labels when hostname repeats (readability in Gephi)
    domain_count = {}
    for r in results:
        d = (r.get("domain") or "").strip()
        if d:
            domain_count[d] = domain_count.get(d, 0) + 1

    for r in results:
        url = r["url"]
        domain = r["domain"]
        evidence = r.get("evidence", "url_parse")
        if not url or not domain:
            continue
        u_id = get_id("url", url)
        d_id = get_id("domain", domain)
        # Short label for Gephi (hostname or hostname + path hint); full URL in full_url attribute
        url_short_label = _short_url_label_for_gexf(url, hostname_total_count=domain_count.get(domain, 1))
        if not url_short_label:
            url_short_label = domain or "unknown"
        G.add_node(
            u_id,
            type="phishing_url",
            label=url_short_label,
            full_url=url,
            domain=domain,
            title=url,
            popularity=0,
        )
        G.add_node(
            d_id,
            type="domain",
            label=domain or "unknown",
            full_url="",
            domain=domain or "",
            title=domain or "",
            popularity=0,
        )
        G.add_edge(u_id, d_id, relationship_type="hosted_on", evidence_source=evidence)
        for b in r.get("brands", set()):
            if not b:
                continue
            b_id = get_id("brand", b)
            G.add_node(
                b_id,
                type="brand",
                label=b,
                full_url="",
                domain="",
                title=b,
                popularity=0,
            )
            G.add_edge(b_id, u_id, relationship_type="brand_referenced", evidence_source=evidence)
        artists_this_page = []
        for a in r.get("artists", []):
            if not a:
                continue
            name = (a.get("name") or a.get("artist_keyword", "") or "").strip()
            if not name:
                continue
            pop = a.get("popularity")
            a_id = get_id("artist", name)
            G.add_node(
                a_id,
                type="artist",
                label=name,
                full_url="",
                domain="",
                title=name,
                popularity=pop if pop is not None else 0,
            )
            G.add_edge(a_id, u_id, relationship_type="mentioned_in_lure", evidence_source=evidence)
            artists_this_page.append(a_id)
        for a_id in artists_this_page:
            for b in r.get("brands", set()):
                if b:
                    b_id = get_id("brand", b)
                    G.add_edge(a_id, b_id, relationship_type="co_mentioned", evidence_source=evidence)
    return G


# -----------------------------------------------------------------------------
# Export & stats
# -----------------------------------------------------------------------------
def export_gexf(G, path):
    """Export graph to GEXF (Gephi native format). Node label is short and readable; full_url holds full URL for phishing_url nodes. Normalizes all attributes so no None is exported."""
    path = Path(path)
    G_export = G.copy()
    n_nodes = G_export.number_of_nodes()
    if MAX_GEXF_NODES is not None and n_nodes > MAX_GEXF_NODES:
        # Keep a connected subgraph: largest component, then top-degree nodes up to cap
        if not G_export.is_directed():
            comps = (G_export.subgraph(c) for c in nx.connected_components(G_export))
        else:
            comps = (G_export.subgraph(c) for c in nx.weakly_connected_components(G_export))
        largest = max(comps, key=len)
        if largest.number_of_nodes() > MAX_GEXF_NODES:
            deg = dict(largest.degree())
            top = sorted(deg, key=deg.get, reverse=True)[:MAX_GEXF_NODES]
            G_export = largest.subgraph(top).copy()
        else:
            G_export = largest.copy()
        print(f"Graph has {n_nodes} nodes; exporting {G_export.number_of_nodes()} for GEXF (set MAX_GEXF_NODES=None for full).")
    node_attrs = ("type", "label", "full_url", "domain", "title", "popularity")
    for n, data in list(G_export.nodes(data=True)):
        for attr in node_attrs:
            val = data.get(attr)
            if val is None:
                G_export.nodes[n][attr] = ""
            elif attr == "popularity":
                try:
                    G_export.nodes[n][attr] = int(val)
                except (TypeError, ValueError):
                    G_export.nodes[n][attr] = 0
        if not (G_export.nodes[n].get("label") or "").strip():
            G_export.nodes[n]["label"] = G_export.nodes[n].get("type") or "node"
    for u, v, data in list(G_export.edges(data=True)):
        if data.get("relationship_type") is None:
            G_export.edges[u, v]["relationship_type"] = "unknown"
        if data.get("evidence_source") is None:
            G_export.edges[u, v]["evidence_source"] = ""
    nx.write_gexf(G_export, str(path))
    abs_path = path.resolve()
    print(f"GEXF graph written to: {abs_path} ({G_export.number_of_nodes()} nodes, {G_export.number_of_edges()} edges). In Gephi: Layout > Random Layout (instant), then Force Atlas 2 if you want.")


def _subgraph_for_display(G, max_nodes):
    """Return a subgraph with at most max_nodes nodes (largest component, then top by degree)."""
    if G.number_of_nodes() <= max_nodes:
        return G.copy()
    comps = (G.subgraph(c) for c in nx.weakly_connected_components(G))
    largest = max(comps, key=len)
    if largest.number_of_nodes() <= max_nodes:
        return largest.copy()
    deg = dict(largest.degree())
    top = sorted(deg, key=deg.get, reverse=True)[:max_nodes]
    return largest.subgraph(top).copy()


def render_graph_to_image(G, path, max_nodes=None):
    """Render the graph to a PNG for web display. Uses short labels and colors by node type. Caps nodes for readability."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    max_nodes = max_nodes if max_nodes is not None else MAX_IMAGE_NODES
    H = _subgraph_for_display(G, max_nodes)
    if H.number_of_nodes() == 0:
        return
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    type_colors = {"phishing_url": "#4a90d9", "domain": "#888888", "brand": "#2ecc71", "artist": "#e67e22"}
    node_colors = [type_colors.get(H.nodes[n].get("type"), "#95a5a6") for n in H.nodes()]
    labels = {n: (H.nodes[n].get("label") or H.nodes[n].get("type") or str(n))[:25] for n in H.nodes()}
    try:
        pos = nx.spring_layout(H, k=1.5, seed=42, iterations=50)
    except Exception:
        pos = nx.random_layout(H, seed=42)
    plt.figure(figsize=(12, 10))
    nx.draw_networkx_nodes(H, pos, node_color=node_colors, node_size=80, alpha=0.9)
    nx.draw_networkx_edges(H, pos, edge_color="#cccccc", alpha=0.5, arrows=True, arrowsize=10)
    nx.draw_networkx_labels(H, pos, labels, font_size=6)
    plt.axis("off")
    plt.tight_layout()
    plt.savefig(str(path), dpi=100, bbox_inches="tight")
    plt.close()
    print(f"Rendered graph image to {path} ({H.number_of_nodes()} nodes).")


def export_edges_csv(G, path):
    """Export edges to CSV: Source, Target, Type, Evidence, plus SourceLabel/TargetLabel for readability."""
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Source", "Target", "Type", "Evidence", "SourceLabel", "TargetLabel"])
        for u, v, data in G.edges(data=True):
            u_label = G.nodes[u].get("label") or G.nodes[u].get("type") or u
            v_label = G.nodes[v].get("label") or G.nodes[v].get("type") or v
            w.writerow([
                u, v,
                data.get("relationship_type", data.get("edge_type", "unknown")),
                data.get("evidence_source", ""),
                u_label[:200] if isinstance(u_label, str) else u_label,
                v_label[:200] if isinstance(v_label, str) else v_label,
            ])
    print(f"Exported edges CSV to {path}")


def export_url_brands_csv(results, path):
    """Export a simple list: URL, Domain, Brands (comma-sep), Artists (comma-sep), Evidence. Easy to open in Excel."""
    path = Path(path)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["URL", "Domain", "Brands", "Artists", "Evidence"])
        for r in results:
            url = r.get("url", "")
            domain = r.get("domain", "")
            brands = r.get("brands") or set()
            artists = r.get("artists") or []
            artist_str = ", ".join(
                (a.get("name") or a.get("artist_keyword") or "").strip() for a in artists if (a.get("name") or a.get("artist_keyword"))
            )
            w.writerow([
                url,
                domain,
                ", ".join(sorted(brands)) if brands else "",
                artist_str,
                r.get("evidence", ""),
            ])
    print(f"Exported URL/brands list to {path}")


def print_stats(G, results):
    """Print basic stats."""
    print("\n--- Stats ---")
    artist_mentions = {}
    domain_count = {}
    artist_pop = {}
    brand_mentions = {}
    urls_with_brands = 0
    for r in results:
        brands = r.get("brands") or set()
        if brands:
            urls_with_brands += 1
        for b in brands:
            brand_mentions[b] = brand_mentions.get(b, 0) + 1
        for a in r.get("artists", []):
            name = (a.get("name") or a.get("artist_keyword", "")).strip()
            if not name:
                continue
            artist_mentions[name] = artist_mentions.get(name, 0) + 1
            artist_pop[name] = a.get("popularity")
        d = r.get("domain", "")
        if d:
            domain_count[d] = domain_count.get(d, 0) + 1

    print(f"\nURLs with at least one brand: {urls_with_brands} / {len(results)}")
    if brand_mentions:
        print("\nBrands found (count):")
        for b, count in sorted(brand_mentions.items(), key=lambda x: -x[1])[:25]:
            print(f"  {b}: {count}")
    else:
        print("  (No brands detected. With NO_DOWNLOAD=True we only match from URL path/query/domain; try turning NO_DOWNLOAD=False to scan page content, or add more BRAND_KEYWORDS.)")

    print("\nPhishing URLs mentioning each artist:")
    for name, count in sorted(artist_mentions.items(), key=lambda x: -x[1]):
        print(f"  {name}: {count}")

    print("\nMost reused domains (phishing URLs per domain):")
    for dom, count in sorted(domain_count.items(), key=lambda x: -x[1])[:15]:
        print(f"  {dom}: {count}")

    print("\nArtists by phishing activity relative to popularity (mentions / (1 + popularity)):")
    ratios = []
    for name, mentions in artist_mentions.items():
        pop = artist_pop.get(name)
        if pop is None:
            pop = 0
        ratio = mentions / (1 + pop)
        ratios.append((name, mentions, pop, ratio))
    for name, mentions, pop, ratio in sorted(ratios, key=lambda x: -x[3])[:15]:
        print(f"  {name}: mentions={mentions}, popularity={pop}, ratio={ratio:.3f}")


# -----------------------------------------------------------------------------
# Main pipeline
# -----------------------------------------------------------------------------
def main():
    client_id = os.environ.get("SPOTIFY_CLIENT_ID", "")
    client_secret = os.environ.get("SPOTIFY_CLIENT_SECRET", "")
    use_spotify = bool(client_id and client_secret)
    if not use_spotify:
        print("SPOTIFY_CLIENT_ID / SPOTIFY_CLIENT_SECRET not set; artist popularity will be missing.")

    if NO_DOWNLOAD:
        print("NO_DOWNLOAD=True: will not fetch phishing page content (feed-only, safe mode).")

    if USE_URL_HISTORY:
        init_history_db()
        print("Fetching OpenPhish feed...")
        openphish_urls = fetch_phishing_urls(limit=None)
        n = merge_urls_into_history(openphish_urls, source="openphish")
        print(f"OpenPhish: got {len(openphish_urls)} URLs, history merge touched {n}.")
        if len(openphish_urls) <= 500:
            print("  (OpenPhish public feed is limited. For more URLs set URLHAUS_AUTH_KEY — free key at https://auth.abuse.ch/ )")
        if os.environ.get("URLHAUS_AUTH_KEY"):
            try:
                print("Fetching URLhaus recent...")
                uh_urls = fetch_urlhaus_recent()
                nu = merge_urls_into_history(uh_urls, source="urlhaus")
                print(f"URLhaus: got {len(uh_urls)} URLs, history merge touched {nu}.")
            except Exception as e:
                print(f"URLhaus fetch failed (optional): {e}")
        if PHISHTANK_APP_KEY or os.environ.get("PHISHTANK_FETCH", "").lower() in ("1", "true", "yes"):
            try:
                print("Fetching PhishTank online-valid...")
                pt_urls = fetch_phishtank_urls()
                npt = merge_urls_into_history(pt_urls, source="phishtank")
                print(f"PhishTank: got {len(pt_urls)} URLs, history merge touched {npt}.")
            except Exception as e:
                print(f"PhishTank fetch failed (optional): {e}")
        urls = get_urls_from_history(limit=MAX_URLS_FROM_HISTORY, since_days=PROCESS_LAST_DAYS)
        print(f"URL history: {len(urls)} URLs to process (USE_URL_HISTORY=True).")
    else:
        print("Fetching OpenPhish feed...")
        urls = fetch_phishing_urls(limit=None if NO_DOWNLOAD else MAX_URLS)
        print(f"Got {len(urls)} URLs (processing all)" if NO_DOWNLOAD else f"Got {len(urls)} URLs (processing up to {MAX_URLS})")

    spotify_cache = load_spotify_cache()
    results = []

    to_process = urls if NO_DOWNLOAD else urls[:MAX_URLS]
    n_total = len(to_process)
    step = 10 if n_total > 50 else 1
    for i, url in enumerate(to_process):
        if i == 0 or (i + 1) % step == 0 or i == n_total - 1:
            print(f"[{i+1}/{n_total}] ...")
        domain = domain_from_url(url)
        if NO_DOWNLOAD:
            # Never request phishing URLs; detect brands/artists from URL path, query, domain.
            brands = find_brands_in_url(url)
            artist_keys = find_artists_in_url(url)
            artists = []
            for ak in artist_keys:
                if use_spotify:
                    a = get_artist_popularity(client_id, client_secret, ak, spotify_cache)
                    if a:
                        artists.append(a)
                    else:
                        artists.append({"artist_keyword": ak, "popularity": None})
                else:
                    artists.append({"artist_keyword": ak, "popularity": None})
            results.append({
                "url": url, "domain": domain, "brands": brands, "artists": artists,
                "evidence": "url_parse",
            })
            continue
        ok, html = download_page(url)
        if not ok:
            continue
        text = extract_visible_text(html)
        brands = find_brands_in_text(text) | find_brands_in_url(url)
        artist_keys = find_artists_in_text(text) | find_artists_in_url(url)
        artists = []
        for ak in artist_keys:
            if use_spotify:
                a = get_artist_popularity(client_id, client_secret, ak, spotify_cache)
                if a:
                    artists.append(a)
                else:
                    artists.append({"artist_keyword": ak, "popularity": None})
            else:
                artists.append({"artist_keyword": ak, "popularity": None})
        if brands or artists:
            results.append({
                "url": url,
                "domain": domain,
                "brands": brands,
                "artists": artists,
                "evidence": "page_content",
            })
        time.sleep(REQUEST_DELAY)

    if use_spotify:
        save_spotify_cache(spotify_cache)

    # Optionally restrict to artist+brand co-occurrence only (obscure lures).
    if CO_OCCURRENCE_ONLY:
        results = [r for r in results if (r.get("brands") and r.get("artists"))]
        print(f"\nCO_OCCURRENCE_ONLY: kept {len(results)} URLs that have both at least one brand and one artist.")
        if not results:
            print("No co-occurrences found. Try NO_DOWNLOAD=False (and run in Docker) to scan page content.")
            return
        export_url_brands_csv(results, CO_OCCURRENCE_CSV)
        export_gexf(build_graph(results), CO_OCCURRENCE_GEXF)
        print(f"Wrote co-occurrence graph to {CO_OCCURRENCE_GEXF} and list to {CO_OCCURRENCE_CSV}.")
    else:
        export_url_brands_csv(results, URL_BRANDS_CSV)

    G = build_graph(results)
    export_gexf(G, GRAPH_GEXF)
    export_edges_csv(G, EDGES_CSV)
    if not CO_OCCURRENCE_ONLY:
        export_url_brands_csv(results, URL_BRANDS_CSV)
    print_stats(G, results)
    print(f"\nGraph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges.")

    # Rendered images for web (Railway / stream)
    OUTPUT_IMAGES_DIR.mkdir(parents=True, exist_ok=True)
    render_graph_to_image(G, OUTPUT_IMAGES_DIR / "latest.png")
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M")
    render_graph_to_image(G, OUTPUT_IMAGES_DIR / f"graph_{ts}.png")
    # Keep only last 5 timestamped images
    hist = sorted(OUTPUT_IMAGES_DIR.glob("graph_*.png"), key=lambda p: p.stat().st_mtime, reverse=True)
    for old in hist[5:]:
        try:
            old.unlink()
        except Exception:
            pass


if __name__ == "__main__":
    main()
