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
LASTFM_CACHE_FILE = CACHE_DIR / "lastfm_top_artists.json"
LASTFM_API_KEY = os.environ.get("LASTFM_API_KEY", "").strip()
LASTFM_TOP_ARTISTS_LIMIT = int(os.environ.get("LASTFM_TOP_ARTISTS_LIMIT", "200"))
LASTFM_CACHE_HOURS = float(os.environ.get("LASTFM_CACHE_HOURS", "24"))
LASTFM_API_BASE = "https://ws.audioscrobbler.com/2.0/"
EDGES_CSV = _OUTPUT_BASE / "graph_edges.csv"
URL_BRANDS_CSV = _OUTPUT_BASE / "url_brands.csv"  # Human-readable: URL, Domain, Brands, Artists
GRAPH_GEXF = _OUTPUT_BASE / "phishing_graph.gexf"
HISTORY_DB = _OUTPUT_BASE / "url_history.db"
CO_OCCURRENCE_GEXF = _OUTPUT_BASE / "co_occurrence.gexf"
CO_OCCURRENCE_CSV = _OUTPUT_BASE / "co_occurrence_urls.csv"
OUTPUT_IMAGES_DIR = _OUTPUT_BASE / "output"  # Rendered graph PNGs (latest.png, graph_*.png)
PAGE_IMAGES_DIR = OUTPUT_IMAGES_DIR / "page_images"  # Cached hero images from phishing pages
IMAGE_HASH_JSON = CACHE_DIR / "image_hashes.json"   # perceptual hash index: filename -> phash hex
CAMPAIGN_THUMBS_DIR = OUTPUT_IMAGES_DIR / "campaign_thumbs"  # Per-artist campaign thumbnail PNGs
RUN_META_JSON = OUTPUT_IMAGES_DIR / "run_meta.json"
KEYWORDS_JSON = OUTPUT_IMAGES_DIR / "keywords.json"
MATCHES_JSON = OUTPUT_IMAGES_DIR / "matches.json"

MAX_GEXF_NODES = 2000   # Cap nodes in GEXF so Gephi can layout; None = export full graph.
MAX_URLS = int(os.environ.get("MAX_URLS", "50"))
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
MAX_RESPONSE_BYTES = 2 * 1024 * 1024  # Cap HTML size (2 MB) to limit parser exposure.
MAX_REDIRECTS = 3

# Proxy support (optional).
# WEBSHARE_ROTATING_PROXY: full proxy URL e.g. http://user:pass@p.webshare.io:80/
#   When set, this single rotating endpoint is used for every request (Webshare
#   handles IP rotation automatically). Takes priority over the list-based approach.
# PROXY_API_KEY: Webshare API key to fetch a list of static datacenter proxies.
# PROXY_LIST_URL: fallback plain-text proxy list URL.
_PROXY_LIST: list[str] = []
_PROXY_USER = os.environ.get("PROXY_USERNAME", "").strip()
_PROXY_PASS = os.environ.get("PROXY_PASSWORD", "").strip()
_PROXY_LIST_URL = os.environ.get("PROXY_LIST_URL", "").strip()
_ROTATING_PROXY_URL = os.environ.get("WEBSHARE_ROTATING_PROXY", "").strip()

def _load_proxy_list() -> None:
    """Fetch proxy list from Webshare API and populate _PROXY_LIST.
    If WEBSHARE_ROTATING_PROXY is set, skips list loading (rotation is handled by the endpoint).
    If PROXY_API_KEY is set, uses the v2 list API (paginated JSON).
    Falls back to fetching PROXY_LIST_URL directly (plain-text download URL).
    """
    global _PROXY_LIST
    if _ROTATING_PROXY_URL:
        print("Using rotating residential proxy endpoint (WEBSHARE_ROTATING_PROXY).")
        return
    api_key = os.environ.get("PROXY_API_KEY", "").strip()
    if api_key:
        # Webshare v2 API: GET /api/v2/proxy/list/?mode=direct&page=1&page_size=100
        try:
            headers = {"Authorization": f"Token {api_key}", "User-Agent": "PhishKnot/1.0"}
            resp = requests.get(
                "https://proxy.webshare.io/api/v2/proxy/list/",
                params={"mode": "direct", "page": 1, "page_size": 100},
                headers=headers,
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json()
            results = data.get("results", [])
            entries = []
            for p in results:
                host = p.get("proxy_address", "")
                port = p.get("port", "")
                user = p.get("username", "") or _PROXY_USER
                pw = p.get("password", "") or _PROXY_PASS
                if host and port:
                    entries.append(f"{host}:{port}:{user}:{pw}")
            _PROXY_LIST = entries
            print(f"Loaded {len(_PROXY_LIST)} proxies via Webshare API.")
            return
        except Exception as e:
            print(f"Warning: Webshare API proxy fetch failed: {e}")
    # Fallback: plain-text download URL
    if not _PROXY_LIST_URL:
        return
    try:
        resp = requests.get(_PROXY_LIST_URL, timeout=10, headers={"User-Agent": "PhishKnot/1.0"})
        resp.raise_for_status()
        entries = [line.strip() for line in resp.text.splitlines() if line.strip()]
        _PROXY_LIST = entries
        print(f"Loaded {len(_PROXY_LIST)} proxies from PROXY_LIST_URL.")
    except Exception as e:
        print(f"Warning: could not load proxy list: {e}")

def _pick_proxy() -> dict | None:
    """Return a requests proxy dict, or None if no proxies configured.
    Prefers WEBSHARE_ROTATING_PROXY (single rotating endpoint) over the static list.
    """
    if _ROTATING_PROXY_URL:
        return {"http": _ROTATING_PROXY_URL, "https": _ROTATING_PROXY_URL}
    if not _PROXY_LIST:
        return None
    import random
    entry = random.choice(_PROXY_LIST)
    parts = entry.split(":")
    if len(parts) >= 4:
        host, port, user, password = parts[0], parts[1], parts[2], ":".join(parts[3:])
        proxy_url = f"http://{user}:{password}@{host}:{port}"
    elif len(parts) == 2 and _PROXY_USER and _PROXY_PASS:
        proxy_url = f"http://{_PROXY_USER}:{_PROXY_PASS}@{entry}"
    else:
        proxy_url = f"http://{entry}"
    return {"http": proxy_url, "https": proxy_url}

# Focus on "obscure" lures: only include URLs where BOTH at least one brand AND at least one artist were found.
# Override with env: CO_OCCURRENCE_ONLY=1 to keep only artist+brand-together cases.
CO_OCCURRENCE_ONLY = os.environ.get("CO_OCCURRENCE_ONLY", "").lower() in ("1", "true", "yes")

# Image export: max nodes to render (smaller = more readable; env MAX_IMAGE_NODES).
MAX_IMAGE_NODES = int(os.environ.get("MAX_IMAGE_NODES", "200"))

# Non-bank brands (tech, shipping, etc.)
OTHER_BRAND_KEYWORDS = [
    "apple", "microsoft", "netflix", "amazon", "paypal", "google", "facebook",
    "instagram", "spotify", "adobe", "samsung", "dropbox", "linkedin", "twitter",
    "x.com", "outlook", "office365", "icloud", "amazon prime", "disney", "hbo",
    "fedex", "ups", "dhl",
]

# Bank brands: top global + US banks (by assets) and common abbreviations for phishing detection.
# Sources: Wikipedia "List of largest banks" (global top 100), "List of largest banks in the United States" (top 100).
# Matching is substring; include full names and abbreviations (e.g. bofa, citi, rbc).
BANK_KEYWORDS = [
    # Global top (China, US, EU, UK, Japan, etc.) — full names and abbreviations
    "icbc", "industrial and commercial bank of china",
    "china construction bank", "ccb",
    "agricultural bank of china",
    "bank of china", "boc",
    "jpmorgan chase", "jp morgan", "chase", "jpmorgan",
    "bank of america", "bofa", "bankofamerica",
    "wells fargo", "wellsfargo", "wells",
    "hsbc",
    "bnp paribas", "bnp",
    "credit agricole", "crédit agricole", "credit agricole",
    "mitsubishi ufj", "mufg",
    "postal savings bank of china",
    "citigroup", "citi", "citibank",
    "bank of communications",
    "barclays",
    "smbc", "sumitomo mitsui",
    "santander", "banco santander",
    "mizuho", "mizuho financial",
    "societe generale", "société générale", "socgen",
    "goldman sachs", "goldman",
    "china merchants bank",
    "groupe bpce", "bpce",
    "royal bank of canada", "rbc",
    "deutsche bank",
    "ubs",
    "japan post bank",
    "industrial bank",
    "toronto-dominion", "td bank",
    "china citic bank", "citic",
    "credit mutuel", "crédit mutuel",
    "shanghai pudong",
    "morgan stanley",
    "lloyds", "lloyds banking", "halifax", "tsb",
    "ing group", "ing",
    "intesa sanpaolo", "intesa",
    "china minsheng",
    "bank of montreal", "bmo",
    "scotiabank",
    "china everbright",
    "natwest", "natwest group", "rbs",
    "commonwealth bank", "commbank",
    "standard chartered",
    "state bank of india", "sbi",
    "itau", "itaú unibanco", "itau unibanco",
    "anz", "anz group",
    "unicredit",
    "bbva", "banco bilbao",
    "ping an bank", "ping an",
    "canadian imperial bank", "cibc",
    "la banque postale",
    "westpac",
    "dz bank",
    "national australia bank", "nab",
    "us bancorp", "us bank", "usbank",
    "caixabank", "caixa",
    "rabobank",
    "capital one",
    "nordea",
    "dbs", "dbs bank",
    "huaxia bank",
    "commerzbank",
    "bank of beijing",
    "sberbank",
    "norinchukin",
    "pnc", "pnc financial",
    "bank of jiangsu",
    "truist", "truist financial",
    "danske bank",
    "kb financial", "kb bank", "kookmin",
    "shinhan", "shinhan financial",
    "hdfc", "hdfc bank",
    "nationwide", "nationwide building society",
    "sumitomo mitsui trust",
    "resona",
    "charles schwab", "schwab",
    "ocbc", "oversea-chinese banking",
    "abn amro",
    "bny mellon", "bank of new york mellon",
    "china zheshang",
    "bank of shanghai",
    "hana financial", "hana bank",
    "bank of ningbo",
    "nonghyup",
    "united overseas bank", "uob",
    "banco do brasil",
    "woori", "woori financial",
    "kbc", "kbc group",
    "nomura",
    "landesbank",
    "erste group", "erste bank",
    "national bank of canada",
    "state street",
    "qatar national bank", "qnb",
    "bank of nanjing",
    "seb group", "skandinaviska enskilda",
    "raiffeisen",
    "banco bradesco", "bradesco",
    "vtb", "vtb bank",
    "first abu dhabi", "fab",
    # US top 100 and other major targets
    "first citizens", "first citizens bank",
    "usaa",
    "citizens financial", "citizens bank",
    "fifth third", "fifth third bank",
    "m&t bank", "mt bank",
    "huntington", "huntington bank",
    "ally financial", "ally",
    "keycorp", "key bank",
    "ameriprise",
    "santander bank",
    "northern trust",
    "regions bank", "regions financial",
    "discover", "discover financial",
    "synchrony",
    "flagstar",
    "raymond james",
    "western alliance",
    "first horizon",
    "webster bank",
    "comerica",
    "east west bank",
    "popular inc", "banco popular",
    "umb financial", "umb",
    "wintrust",
    "south state bank",
    "valley bank",
    "synovus",
    "pinnacle financial",
    "old national bank",
    "frost bank", "cullen frost",
    "columbia bank",
    "bok financial", "bok",
    "fnb", "fnb corporation",
    "associated banc-corp",
    "everbank",
    "stifel",
    "midfirst",
    "bank ozk", "ozk",
    "prosperity bancshares",
    "sofi",
    "bankunited",
    "hancock whitney",
    "banc of california",
    "commerce bancshares",
    "first national of nebraska",
    "fulton financial",
    "texas capital bank",
    "first interstate",
    "united community bank",
    "glacier bancorp",
    "wafd bank",
    "wesbanco",
    "arvest",
    "simmons bank",
    "ameris", "ameris bancorp",
    "eastern bank",
    "atlantic union",
    "axos financial",
    "bank of hawaii",
    "first hawaiian",
    "cathay bank",
    "home bancshares",
    "customers bancorp",
    "wsfs bank",
    "busey bank",
    "first bancorp",
    # Additional global / regional (UK, EU, India, etc.)
    "first direct",
    "metropolitan bank",
    "cooperative bank",
    "virgin money",
    "icici", "icici bank",
    "kotak", "kotak mahindra",
    "axis bank",
    "pnb", "punjab national bank",
    "bank of baroda",
    "canara bank",
    "union bank of india",
    "bank of india",
    "indusind",
    "yes bank",
    "idfc first",
    "bandhan bank",
    "au small finance",
    "standard bank",
    "absa",
    "nedbank",
    "firstrand",
    "capitec",
    "banco itau",
    "banco santander brasil",
    "banco safra",
    "btg pactual",
    "nubank",
    "banco inter",
    "banco btg",
    "scotiabank chile",
    "banco de chile",
    "banco estado",
    "banco colombia", "bancolombia",
    "banco de bogota",
    "banco galicia",
    "banco provincia",
    "banco macro",
    "banco nacion",
    "inbursa",
    "banorte",
    "bbva mexico",
    "citibanamex",
    "santander mexico",
    "scotiabank mexico",
    "bank hapoalim",
    "bank leumi",
    "discount bank",
    "qatar islamic",
    "emirates nbd",
    "dubai islamic",
    "abu dhabi commercial",
    "mashreq bank",
    "al rajhi",
    "riyad bank",
    "samba financial",
    "national commercial bank",
    "bank al bilad",
    "kuwait finance house",
    "national bank of kuwait", "nbk",
    "gulf bank",
    "burgan bank",
    "al hilal bank",
    "first gulf bank",
    "bank muscat",
    "national bank of oman",
    "bank of bahrain",
    "ahli united",
    "turkey is bankasi",
    "garanti bbva",
    "akbank",
    "yapi kredi",
    "ziraat bank",
    "qnb finansbank",
    "sberbank europe",
    "alfa-bank", "alfa bank",
    "gazprombank",
    "rosbank",
    "otkritie",
    "raiffeisen russia",
    "unicredit bank",
    "kbc bank",
    "belfius",
    "ing belgium",
    "bpost",
    "akfa bank",
    "bank of ireland",
    "permanent tsb",
    "aib", "allied irish",
    "ulster bank",
    "handelsbanken",
    "swedbank",
    "danske",
    "jyske bank",
    "nordea bank",
    "op financial",
    "aktia",
    "dnb", "dnb norway",
    "sparebank 1",
    "landsbankinn",
    "islandsbanki",
    "arion bank",
    "luminor",
    "seb bank",
    "lansforsakringar",
    "skandiabank",
    "bank polska",
    "pkobp", "pko bp",
    "bank pekao",
    "mbank",
    "santander poland",
    "ing poland",
    "komercni banka",
    "ceska sporitelna",
    "csob",
    "kbc bulgaria",
    "dsk bank",
    "unicredit bulgaria",
    "otp bank",
    "k&h bank",
    "erste hungary",
    "banca transilvania",
    "brd", "brd groupe societe generale",
    "garanti bbva romania",
    "nlb", "nova ljubljanska",
    "nova kbm",
    "addiko bank",
    "zagrebacka banka",
    "prva banka",
    "unicredit croatia",
    "alpha bank",
    "eurobank",
    "piraeus bank",
    "national bank of greece",
    "turkey garanti",
    "bank leumi le israel",
    "bank hapoalim",
    "bank of cyprus",
    "hellenic bank",
    "rcbc", "rizal commercial",
    "bdo", "bdo unibank",
    "metrobank",
    "landbank",
    "development bank of singapore",
    "maybank",
    "cimb", "cimb group",
    "public bank",
    "hong leong bank",
    "rhb bank",
    "bangkok bank",
    "scb", "siam commercial",
    "krung thai",
    "kasikorn", "kbank",
    "tmb", "tmb bank",
    "vietcombank",
    "vietinbank",
    "techcombank",
    "mbbank",
    "vp bank",
    "acb vietnam",
    "bca", "bank central asia",
    "mandiri", "bank mandiri",
    "bni", "bank negara indonesia",
    "bri", "bank rakyat",
    "btpn",
    "cimb indonesia",
    "uob indonesia",
    "maybank indonesia",
    "hdfc india",
    "icici india",
    "sbi india",
    "pnb india",
    "american express", "amex",
    "navy federal", "navy federal credit union",
    "pnc bank",
    "td bank usa",
    "charles schwab corporation",
    # More regional and alternate forms to reach 500+ bank keywords
    "agriculture bank of china",
    "china construction",
    "postal savings bank",
    "bank of communications china",
    "china merchants",
    "china everbright bank",
    "china minsheng bank",
    "china guangfa",
    "china zheshang",
    "china citic",
    "ping an",
    "spd bank", "pudong development",
    "bank of shanghai china",
    "bank of nanjing",
    "bank of beijing china",
    "bank of jiangsu",
    "bank of ningbo",
    "huaxia",
    "industrial bank china",
    "bank of nova scotia",
    "royal bank",
    "toronto dominion",
    "bank of montreal",
    "national bank canada",
    "desjardins",
    "laurentian bank",
    "alterna bank",
    "equitable bank",
    "tangerine bank",
    "simplii financial",
    "bank westpac",
    "bank anz",
    "bank nab",
    "bendigo bank",
    "suncorp bank",
    "bank of melbourne",
    "st george bank",
    "bank sa",
    "adelaide bank",
    "ing australia",
    "macquarie bank",
    "bank of korea",
    "korea development bank",
    "nh bank", "nonghyup bank",
    "korea exchange bank",
    "standard chartered korea",
    "shinhan bank",
    "kb kookmin",
    "hana bank",
    "woori bank",
    "jeju bank",
    "kakaobank",
    "k bank",
    "toss bank",
    "bank of taiwan",
    "ctbc", "chinatrust",
    "cathay united",
    "first bank taiwan",
    "megabank",
    "taiwan cooperative",
    "land bank of taiwan",
    "hong kong bank",
    "hang seng",
    "bank of east asia",
    "dah sing",
    "china construction bank asia",
    "icbc asia",
    "boc hong kong",
    "bank of india",
    "canara bank",
    "indian bank",
    "indian overseas bank",
    "central bank of india",
    "bank of maharashtra",
    "uco bank",
    "iob", "indian overseas",
    "federal bank india",
    "south indian bank",
    "karur vysya",
    "city union bank",
    "tamilnad mercantile",
    "rbl bank",
    "idfc bank",
    "bandhan",
    "au bank",
    "equitas bank",
    "ujjivan bank",
    "janata bank",
    "dhani bank",
]

# Combined brand list for matching (non-bank + bank)
BRAND_KEYWORDS = OTHER_BRAND_KEYWORDS + BANK_KEYWORDS

# Curated brand logo map: keyword -> Wikimedia Commons image URL.
# Used as fallback when no page image was captured from the phishing page.
# Keys must match the keyword strings used in OTHER_BRAND_KEYWORDS / BANK_KEYWORDS.
BRAND_LOGO_MAP = {
    # Tech / shipping
    "apple":        "https://upload.wikimedia.org/wikipedia/commons/f/fa/Apple_logo_black.svg",
    "microsoft":    "https://upload.wikimedia.org/wikipedia/commons/4/44/Microsoft_logo.svg",
    "google":       "https://upload.wikimedia.org/wikipedia/commons/2/2f/Google_2015_logo.svg",
    "amazon":       "https://upload.wikimedia.org/wikipedia/commons/a/a9/Amazon_logo.svg",
    "paypal":       "https://upload.wikimedia.org/wikipedia/commons/b/b5/PayPal.svg",
    "netflix":      "https://upload.wikimedia.org/wikipedia/commons/0/08/Netflix_2015_logo.svg",
    "facebook":     "https://upload.wikimedia.org/wikipedia/commons/5/51/Facebook_f_logo_%282019%29.svg",
    "instagram":    "https://upload.wikimedia.org/wikipedia/commons/e/e7/Instagram_logo_2016.svg",
    "spotify":      "https://upload.wikimedia.org/wikipedia/commons/2/26/Spotify_logo_with_text.svg",
    "adobe":        "https://upload.wikimedia.org/wikipedia/commons/8/8e/Adobe_Corporate_Logo.png",
    "samsung":      "https://upload.wikimedia.org/wikipedia/commons/2/24/Samsung_Logo.svg",
    "linkedin":     "https://upload.wikimedia.org/wikipedia/commons/c/ca/LinkedIn_logo_initials.png",
    "twitter":      "https://upload.wikimedia.org/wikipedia/commons/6/6f/Logo_of_Twitter.svg",
    "dropbox":      "https://upload.wikimedia.org/wikipedia/commons/7/74/Dropbox_logo_%282013%29.svg",
    "fedex":        "https://upload.wikimedia.org/wikipedia/commons/b/b9/FedEx_Corporation_-_2016_Logo.svg",
    "ups":          "https://upload.wikimedia.org/wikipedia/commons/1/1b/UPS_Logo_Shield_2017.svg",
    "dhl":          "https://upload.wikimedia.org/wikipedia/commons/a/ac/DHL_Logo.svg",
    "disney":       "https://upload.wikimedia.org/wikipedia/commons/5/5f/Disney_wordmark_%282010-present%29.svg",
    # US banks
    "jpmorgan":     "https://upload.wikimedia.org/wikipedia/commons/a/af/J_P_Morgan_Logo_2008_1.svg",
    "chase":        "https://upload.wikimedia.org/wikipedia/commons/a/af/J_P_Morgan_Logo_2008_1.svg",
    "bank of america": "https://upload.wikimedia.org/wikipedia/commons/e/e4/Bank_of_America_logo.svg",
    "bofa":         "https://upload.wikimedia.org/wikipedia/commons/e/e4/Bank_of_America_logo.svg",
    "wells fargo":  "https://upload.wikimedia.org/wikipedia/commons/b/b3/Wells_Fargo_Bank.svg",
    "citibank":     "https://upload.wikimedia.org/wikipedia/commons/1/1e/Citi.svg",
    "citi":         "https://upload.wikimedia.org/wikipedia/commons/1/1e/Citi.svg",
    "pnc":          "https://upload.wikimedia.org/wikipedia/commons/4/43/PNC_Financial_Services_logo.svg",
    "us bank":      "https://upload.wikimedia.org/wikipedia/commons/7/7a/US_Bancorp_logo_%282016%29.svg",
    "capital one":  "https://upload.wikimedia.org/wikipedia/commons/9/98/Capital_One_logo.svg",
    "td bank":      "https://upload.wikimedia.org/wikipedia/commons/a/a4/Toronto-Dominion_Bank_logo.svg",
    "truist":       "https://upload.wikimedia.org/wikipedia/commons/5/53/Truist_Financial_Corporation_logo.svg",
    "bmo":          "https://upload.wikimedia.org/wikipedia/commons/b/b8/BMO_Financial_Group_logo.svg",
    # UK / Europe
    "hsbc":         "https://upload.wikimedia.org/wikipedia/commons/a/aa/HSBC_logo_%282018%29.svg",
    "barclays":     "https://upload.wikimedia.org/wikipedia/commons/7/7a/Barclays_Logo.svg",
    "lloyds":       "https://upload.wikimedia.org/wikipedia/commons/1/10/Lloyds_Bank.svg",
    "natwest":      "https://upload.wikimedia.org/wikipedia/commons/6/60/NatWest_logo.svg",
    "rbs":          "https://upload.wikimedia.org/wikipedia/commons/6/60/NatWest_logo.svg",
    "tsb":          "https://upload.wikimedia.org/wikipedia/commons/d/d8/TSB_Bank_logo.svg",
    "santander":    "https://upload.wikimedia.org/wikipedia/commons/b/be/Logo_Banco_Santander.svg",
    "ing":          "https://upload.wikimedia.org/wikipedia/commons/4/49/ING_Group_N.V._Logo.svg",
    "bnp":          "https://upload.wikimedia.org/wikipedia/commons/3/38/BNP_Paribas_logo.svg",
    "deutsche bank":"https://upload.wikimedia.org/wikipedia/commons/7/7b/Deutsche_bank_logo_without_wordmark.svg",
    "ubs":          "https://upload.wikimedia.org/wikipedia/commons/b/bb/UBS_Logo.svg",
    "rbc":          "https://upload.wikimedia.org/wikipedia/commons/8/8b/RBC-Royal-Bank.svg",
    "scotiabank":   "https://upload.wikimedia.org/wikipedia/commons/7/74/Scotiabank_logo.svg",
    # Asia / Pacific
    "dbs":          "https://upload.wikimedia.org/wikipedia/commons/8/8e/DBS_Bank_logo.svg",
    "bdo":          "https://upload.wikimedia.org/wikipedia/commons/2/26/BDO_Unibank_logo.svg",
    "bca":          "https://upload.wikimedia.org/wikipedia/commons/3/35/Bank_Central_Asia.svg",
    "sbi":          "https://upload.wikimedia.org/wikipedia/commons/c/cc/SBI-logo.svg",
    "icici":        "https://upload.wikimedia.org/wikipedia/commons/1/12/ICICI_Bank_Logo.svg",
    "hdfc":         "https://upload.wikimedia.org/wikipedia/commons/2/28/HDFC_Bank_Logo.svg",
    "nab":          "https://upload.wikimedia.org/wikipedia/commons/0/04/National_Australia_Bank_logo.svg",
    "anz":          "https://upload.wikimedia.org/wikipedia/commons/1/13/ANZ_logo_logotype.svg",
    "westpac":      "https://upload.wikimedia.org/wikipedia/commons/5/52/Westpac_logo.svg",
    "commbank":     "https://upload.wikimedia.org/wikipedia/commons/2/29/Commonwealth_Bank_Logo.svg",
    # Middle East / Africa
    "fnb":          "https://upload.wikimedia.org/wikipedia/commons/4/4a/First_National_Bank_Logo.png",
    "standard bank":"https://upload.wikimedia.org/wikipedia/commons/2/29/Standard_Bank_Logo.svg",
    # Other
    "banco inter":  "https://upload.wikimedia.org/wikipedia/commons/8/8e/Banco_Inter_logo.svg",
    "ccb":          "https://upload.wikimedia.org/wikipedia/commons/1/10/China_Construction_Bank_Logo.svg",
    "icbc":         "https://upload.wikimedia.org/wikipedia/commons/d/d8/ICBC_logo.svg",
    "scb":          "https://upload.wikimedia.org/wikipedia/commons/3/3d/Standard_Chartered_%28logo%29.svg",
    "umb":          "https://upload.wikimedia.org/wikipedia/commons/e/e3/UMB_Financial_Corporation_logo.png",
}

ARTIST_KEYWORDS = [
    "taylor swift", "beyonce", "beyoncé", "drake", "ed sheeran", "ariana grande",
    "the weeknd", "justin bieber", "bad bunny", "harry styles", "billie eilish",
    "dua lipa", "coldplay", "adele", "rihanna", "lady gaga", "bruno mars",
    "post malone", "travis scott", "kendrick lamar", "olivia rodrigo",
    "miley cyrus", "katy perry", "shawn mendes", "selena gomez", "nicki minaj",
    "eminem", "kanye", "ye", "yeat", "bts", "blackpink",
]

# Optional second feed: PhishTank "online-valid". (PhishTank registration is often disabled; use URLhaus instead.)
PHISHTANK_APP_KEY = os.environ.get("PHISHTANK_APP_KEY", "")


def _phishtank_feed_url():
    if PHISHTANK_APP_KEY:
        return f"https://data.phishtank.com/data/{PHISHTANK_APP_KEY}/online-valid.json"
    return "https://data.phishtank.com/data/online-valid.json"


# -----------------------------------------------------------------------------
# Last.fm top artists (optional; extends ARTIST_KEYWORDS for matching)
# -----------------------------------------------------------------------------
# Combined artist list (static + Last.fm) set at pipeline start; None = use ARTIST_KEYWORDS only.
_artist_keywords_combined = None


def fetch_lastfm_top_artists(api_key, limit=200):
    """Fetch top artists from Last.fm chart.getTopArtists (paginated). Returns list of {"name": "..."}."""
    if not api_key:
        return []
    out = []
    page = 1
    per_page = 50
    while len(out) < limit:
        r = requests.get(
            LASTFM_API_BASE,
            params={
                "method": "chart.gettopartists",
                "api_key": api_key,
                "format": "json",
                "limit": per_page,
                "page": page,
            },
            headers={"User-Agent": USER_AGENT},
            timeout=15,
        )
        if r.status_code != 200:
            break
        data = r.json()
        artists = data.get("artists", {}).get("artist", [])
        if not artists:
            break
        for a in artists:
            name = (a.get("name") or "").strip()
            if name and len(name) >= 2:
                out.append({"name": name})
        if len(artists) < per_page:
            break
        page += 1
        time.sleep(0.2)
    return out[:limit]


def load_lastfm_cache():
    """Load Last.fm top artists from cache file. Returns list of artist name strings, or None if missing/expired/invalid."""
    if not LASTFM_CACHE_FILE.is_file():
        return None
    try:
        age_hours = (time.time() - LASTFM_CACHE_FILE.stat().st_mtime) / 3600
        if age_hours > LASTFM_CACHE_HOURS:
            return None
        with open(LASTFM_CACHE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        names = data.get("names") if isinstance(data, dict) else data
        if isinstance(names, list):
            return [str(n).strip() for n in names if n and len(str(n).strip()) >= 2]
        return None
    except Exception:
        return None


def refresh_lastfm_cache_if_needed():
    """If LASTFM_API_KEY is set and cache is missing or expired, fetch from Last.fm and write cache."""
    if not LASTFM_API_KEY:
        return
    if load_lastfm_cache() is not None:
        return
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        artists = fetch_lastfm_top_artists(LASTFM_API_KEY, limit=LASTFM_TOP_ARTISTS_LIMIT)
        if not artists:
            return
        names = [a["name"] for a in artists]
        with open(LASTFM_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump({"names": names, "updated": datetime.now(timezone.utc).isoformat()}, f, indent=0)
        print(f"Last.fm: cached {len(names)} top artists (refresh in {LASTFM_CACHE_HOURS}h).")
    except Exception as e:
        print(f"Last.fm fetch failed (optional): {e}")


def build_combined_artist_keywords():
    """Return combined list: ARTIST_KEYWORDS + Last.fm cached names (lowercased, deduped, order preserved)."""
    static = list(ARTIST_KEYWORDS)
    lastfm = load_lastfm_cache()
    if not lastfm:
        return static
    seen = {s.lower() for s in static}
    out = list(static)
    for name in lastfm:
        n = name.strip().lower()
        if n and len(n) >= 2 and n not in seen:
            seen.add(n)
            out.append(n)
    return out


# -----------------------------------------------------------------------------
# URL history (local SQLite: accumulate URLs across runs for more volume)
# -----------------------------------------------------------------------------
def _get_history_conn():
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(HISTORY_DB))
    conn.row_factory = sqlite3.Row
    return conn


def init_history_db():
    """Create url_history table if it doesn't exist; migrate schema for older DBs."""
    conn = _get_history_conn()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS url_history (
                url TEXT PRIMARY KEY,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                source TEXT NOT NULL,
                processed_at TEXT,
                domain TEXT,
                brands TEXT,
                artists TEXT,
                page_image_file TEXT
            )
        """)
        # Migrate existing DBs that predate these columns.
        for col_def in ("processed_at TEXT", "domain TEXT", "brands TEXT", "artists TEXT", "page_image_file TEXT"):
            try:
                conn.execute(f"ALTER TABLE url_history ADD COLUMN {col_def}")
            except Exception:
                pass  # Column already exists
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
                "INSERT INTO url_history (url, first_seen, last_seen, source) VALUES (?, ?, ?, ?) ON CONFLICT(url) DO UPDATE SET last_seen = excluded.last_seen",
                (u, now, now, source),
            )
            count += 1
        conn.commit()
        return count
    finally:
        conn.close()


def get_urls_from_history(limit=None, since_days=None):
    """
    Return list of URLs from history.
    Prioritizes unprocessed URLs first, then least-recently-processed.
    since_days: only URLs with last_seen in last N days.
    limit: max count.
    """
    conn = _get_history_conn()
    try:
        if since_days is not None:
            since = (datetime.now(timezone.utc) - timedelta(days=since_days)).isoformat().replace("+00:00", "Z")
            query = """
                SELECT url FROM url_history
                WHERE last_seen >= ?
                ORDER BY
                    CASE WHEN processed_at IS NULL THEN 0 ELSE 1 END,
                    processed_at ASC,
                    last_seen DESC
            """
            cur = conn.execute(query, (since,))
        else:
            cur = conn.execute("""
                SELECT url FROM url_history
                ORDER BY
                    CASE WHEN processed_at IS NULL THEN 0 ELSE 1 END,
                    processed_at ASC,
                    last_seen DESC
            """)
        rows = cur.fetchall()
        urls = [r[0] for r in rows]
        if limit is not None:
            urls = urls[:limit]
        return urls
    finally:
        conn.close()


def mark_urls_processed(urls):
    """Stamp processed_at = now for a list of URLs that were attempted this run."""
    if not urls:
        return
    conn = _get_history_conn()
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    try:
        conn.executemany(
            "UPDATE url_history SET processed_at = ? WHERE url = ?",
            [(now, u) for u in urls if u],
        )
        conn.commit()
    finally:
        conn.close()


def save_url_matches(results):
    """Persist brand/artist match data for each processed URL into url_history."""
    if not results:
        return
    conn = _get_history_conn()
    try:
        for r in results:
            url = r.get("url", "")
            if not url:
                continue
            brands = sorted(list(r.get("brands") or []))
            artists = [
                {"name": a.get("name", ""), "artist_keyword": a.get("artist_keyword", ""),
                 "popularity": a.get("popularity"), "spotify_id": a.get("spotify_id", ""),
                 "image_url": a.get("image_url", "")}
                for a in (r.get("artists") or []) if isinstance(a, dict)
            ]
            conn.execute(
                """UPDATE url_history SET domain=?, brands=?, artists=?, page_image_file=?
                   WHERE url=?""",
                (
                    r.get("domain", ""),
                    json.dumps(brands),
                    json.dumps(artists),
                    r.get("page_image_file", ""),
                    url,
                ),
            )
        conn.commit()
    finally:
        conn.close()


def load_all_historical_results():
    """Load all URLs with stored match data from url_history to build the cumulative graph."""
    conn = _get_history_conn()
    try:
        cur = conn.execute(
            """SELECT url, domain, brands, artists, page_image_file
               FROM url_history
               WHERE brands IS NOT NULL AND brands != '[]'"""
        )
        results = []
        for row in cur.fetchall():
            try:
                brands = set(json.loads(row[2] or "[]"))
                artists = json.loads(row[3] or "[]")
                if not brands and not artists:
                    continue
                results.append({
                    "url": row[0],
                    "domain": row[1] or "",
                    "brands": brands,
                    "artists": artists,
                    "evidence": "history",
                    "match_detail": {},
                    "page_image_file": row[4] or "",
                })
            except Exception:
                continue
        return results
    finally:
        conn.close()


def get_history_stats():
    """Return a dict of statistics about the URL history database."""
    conn = _get_history_conn()
    try:
        stats = {}
        stats["total"] = conn.execute("SELECT COUNT(*) FROM url_history").fetchone()[0]
        stats["processed"] = conn.execute("SELECT COUNT(*) FROM url_history WHERE processed_at IS NOT NULL").fetchone()[0]
        stats["unprocessed"] = stats["total"] - stats["processed"]
        rows = conn.execute(
            "SELECT source, COUNT(*) as cnt FROM url_history GROUP BY source ORDER BY cnt DESC"
        ).fetchall()
        stats["by_source"] = {r[0]: r[1] for r in rows}
        row = conn.execute("SELECT MIN(first_seen), MAX(first_seen) FROM url_history").fetchone()
        stats["first_seen_min"] = row[0] or ""
        stats["first_seen_max"] = row[1] or ""
        row = conn.execute("SELECT MIN(last_seen), MAX(last_seen) FROM url_history").fetchone()
        stats["last_seen_min"] = row[0] or ""
        stats["last_seen_max"] = row[1] or ""
        row = conn.execute("SELECT MIN(processed_at), MAX(processed_at) FROM url_history WHERE processed_at IS NOT NULL").fetchone()
        stats["processed_at_min"] = row[0] or ""
        stats["processed_at_max"] = row[1] or ""
        # URLs seen in last 24h / 7d
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        since_24h = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat().replace("+00:00", "Z")
        since_7d = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat().replace("+00:00", "Z")
        stats["seen_last_24h"] = conn.execute("SELECT COUNT(*) FROM url_history WHERE last_seen >= ?", (since_24h,)).fetchone()[0]
        stats["seen_last_7d"] = conn.execute("SELECT COUNT(*) FROM url_history WHERE last_seen >= ?", (since_7d,)).fetchone()[0]
        stats["new_last_24h"] = conn.execute("SELECT COUNT(*) FROM url_history WHERE first_seen >= ?", (since_24h,)).fetchone()[0]
        stats["new_last_7d"] = conn.execute("SELECT COUNT(*) FROM url_history WHERE first_seen >= ?", (since_7d,)).fetchone()[0]
        return stats
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
    """Download HTML for a URL; return (status_ok, html_text, truncated). Size and redirects limited."""
    try:
        session = requests.Session()
        session.max_redirects = MAX_REDIRECTS
        proxies = _pick_proxy()
        r = session.get(
            url,
            timeout=15,
            headers={"User-Agent": USER_AGENT},
            allow_redirects=True,
            stream=True,
            proxies=proxies,
        )
        r.raise_for_status()
        # Cap bytes read so we never load huge or maliciously large bodies
        chunks = []
        total = 0
        truncated = False
        for chunk in r.iter_content(chunk_size=8192):
            if chunk:
                total += len(chunk)
                if total > MAX_RESPONSE_BYTES:
                    truncated = True
                    break
                chunks.append(chunk)
        body = b"".join(chunks)
        try:
            return True, body.decode("utf-8", errors="replace"), truncated
        except Exception:
            return False, "", False
    except Exception:
        return False, "", False


def extract_visible_text(html):
    """Extract visible text from HTML (strip script/style, normalize spaces)."""
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "meta", "head"]):
        tag.decompose()
    text = soup.get_text(separator=" ", strip=True)
    text = re.sub(r"\s+", " ", text).lower()
    return text


_TRACKER_PATTERNS = ("pixel", "track", "beacon", "1x1", "spacer", "blank", "transparent")

_CSS_BG_RE = re.compile(r'background(?:-image)?\s*:[^;]*url\(\s*["\']?([^"\')\s]+)["\']?\s*\)', re.IGNORECASE)

def _make_absolute(src, base_scheme, base_netloc, base_path):
    """Resolve a potentially relative image URL to absolute."""
    src = src.strip()
    if src.startswith("//"):
        return base_scheme + ":" + src
    if src.startswith("/"):
        return f"{base_scheme}://{base_netloc}{src}"
    if not src.startswith("http"):
        return f"{base_scheme}://{base_netloc}{base_path}/{src}"
    return src


def extract_page_hero_image(html, base_url):
    """
    Extract the most prominent image URL from a phishing page.
    Tries in order: og:image meta, <img> tags, CSS background-image, favicon.
    Filters out trackers, tiny images, and data URIs.
    Returns an absolute URL or empty string.
    """
    try:
        soup = BeautifulSoup(html, "html.parser")
        parsed_base = urlparse(base_url)
        base_scheme = parsed_base.scheme or "https"
        base_netloc = parsed_base.netloc or ""
        base_path = parsed_base.path.rsplit("/", 1)[0]

        def is_bad(src):
            if not src or src.startswith("data:"):
                return True
            return any(t in src.lower() for t in _TRACKER_PATTERNS)

        # 1. og:image — phishing kits often copy this from the real brand site
        for meta in soup.find_all("meta", property="og:image"):
            src = (meta.get("content") or "").strip()
            if not is_bad(src):
                return _make_absolute(src, base_scheme, base_netloc, base_path)

        # 2. Plain <img> tags — skip tiny/tracker images
        for img in soup.find_all("img", src=True):
            src = (img.get("src") or "").strip()
            if is_bad(src):
                continue
            try:
                w = int(img.get("width") or 0)
                h = int(img.get("height") or 0)
                if (w and w < 50) or (h and h < 50):
                    continue
            except (ValueError, TypeError):
                pass
            return _make_absolute(src, base_scheme, base_netloc, base_path)

        # 3. CSS background-image in style attributes and <style> blocks
        style_text = " ".join(
            (tag.string or "") for tag in soup.find_all("style")
        )
        for el in soup.find_all(style=True):
            style_text += " " + (el.get("style") or "")
        for match in _CSS_BG_RE.finditer(style_text):
            src = match.group(1).strip()
            if not is_bad(src):
                return _make_absolute(src, base_scheme, base_netloc, base_path)

        # 4. Favicon as last resort — still visually identifies the spoofed brand
        for link in soup.find_all("link", rel=True):
            rels = [r.lower() for r in (link.get("rel") or [])]
            if "icon" in rels or "shortcut icon" in rels:
                src = (link.get("href") or "").strip()
                if not is_bad(src):
                    return _make_absolute(src, base_scheme, base_netloc, base_path)

    except Exception:
        pass
    return ""


_IMAGE_MAGIC = [
    (b"\xff\xd8\xff", ".jpg"),
    (b"\x89PNG\r\n\x1a\n", ".png"),
    (b"GIF87a", ".gif"),
    (b"GIF89a", ".gif"),
    (b"RIFF", ".webp"),  # WebP: RIFF....WEBP — verified below
]

def _detect_image_ext(data: bytes):
    """
    Validate file magic bytes and return the correct extension.
    Returns empty string if the data doesn't match a known safe image format.
    """
    if data[:3] == b"\xff\xd8\xff":
        return ".jpg"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return ".png"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return ".gif"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return ".webp"
    return ""


def download_and_cache_image(img_url, cache_dir):
    """
    Fetch an image URL and save it to cache_dir.
    Uses a hash of the URL as the filename so it's deterministic and safe.
    Validates magic bytes — does not trust Content-Type from the server.
    Returns the filename (not full path) on success, or empty string on failure.
    """
    try:
        url_hash = hashlib.sha256(img_url.encode("utf-8")).hexdigest()[:16]
        cache_dir = Path(cache_dir)
        cache_dir.mkdir(parents=True, exist_ok=True)
        # Check cache with any known extension before fetching
        for ext in (".jpg", ".png", ".gif", ".webp"):
            candidate = cache_dir / f"page_{url_hash}{ext}"
            if candidate.exists():
                return candidate.name
        r = requests.get(
            img_url,
            timeout=10,
            headers={"User-Agent": USER_AGENT},
            stream=True,
        )
        r.raise_for_status()
        chunks = []
        total = 0
        for chunk in r.iter_content(8192):
            if chunk:
                total += len(chunk)
                if total > 2_000_000:
                    break
                chunks.append(chunk)
        data = b"".join(chunks)
        ext = _detect_image_ext(data)
        if not ext:
            return ""  # Not a recognized image format — discard
        filename = f"page_{url_hash}{ext}"
        (cache_dir / filename).write_bytes(data)
        compute_and_store_image_hash(filename)
        return filename
    except Exception:
        return ""


# -----------------------------------------------------------------------------
# Perceptual image hashing (kit fingerprinting)
# -----------------------------------------------------------------------------

def _load_image_hash_index() -> dict:
    """Load filename -> phash hex mapping from cache."""
    if IMAGE_HASH_JSON.exists():
        try:
            return json.loads(IMAGE_HASH_JSON.read_text("utf-8"))
        except Exception:
            pass
    return {}


def _save_image_hash_index(index: dict) -> None:
    IMAGE_HASH_JSON.parent.mkdir(parents=True, exist_ok=True)
    IMAGE_HASH_JSON.write_text(json.dumps(index, indent=2), encoding="utf-8")


def _phash_file(path) -> str:
    """Compute perceptual hash of an image file. Returns hex string or ''."""
    try:
        import imagehash
        from PIL import Image
        return str(imagehash.phash(Image.open(path)))
    except Exception:
        return ""


def compute_and_store_image_hash(filename: str) -> str:
    """Compute pHash for a cached page image and persist it. Returns phash hex or ''."""
    if not filename:
        return ""
    path = PAGE_IMAGES_DIR / filename
    if not path.exists():
        return ""
    index = _load_image_hash_index()
    if filename in index:
        return index[filename]
    ph = _phash_file(path)
    if ph:
        index[filename] = ph
        _save_image_hash_index(index)
    return ph


def backfill_image_hashes() -> None:
    """Hash all existing cached page images that are not yet in the index."""
    if not PAGE_IMAGES_DIR.exists():
        return
    index = _load_image_hash_index()
    updated = 0
    for img_path in PAGE_IMAGES_DIR.iterdir():
        if img_path.suffix.lower() not in (".jpg", ".jpeg", ".png", ".gif", ".webp"):
            continue
        if img_path.name not in index:
            ph = _phash_file(img_path)
            if ph:
                index[img_path.name] = ph
                updated += 1
    if updated:
        _save_image_hash_index(index)
        print(f"Image hash backfill: hashed {updated} cached images.")
    else:
        print("Image hash backfill: nothing new to hash.")


def get_kit_families(hamming_threshold: int = 6) -> dict:
    """
    Group cached images into kit families by perceptual hash similarity.
    Returns dict: representative_phash -> list of filenames in that family.
    Hamming distance <= threshold = same kit template.
    """
    try:
        import imagehash
    except ImportError:
        return {}
    index = _load_image_hash_index()
    if not index:
        return {}
    hashes = {fname: imagehash.hex_to_hash(ph) for fname, ph in index.items() if ph}
    families = {}   # rep_phash_str -> [filenames]
    assigned = {}   # filename -> rep_phash_str
    for fname, ph in hashes.items():
        matched = None
        for rep_str, members in families.items():
            rep_ph = imagehash.hex_to_hash(rep_str)
            if (ph - rep_ph) <= hamming_threshold:
                matched = rep_str
                break
        if matched:
            families[matched].append(fname)
            assigned[fname] = matched
        else:
            rep_str = str(ph)
            families[rep_str] = [fname]
            assigned[fname] = rep_str
    return families


# -----------------------------------------------------------------------------
# Keyword matching
# -----------------------------------------------------------------------------
def _whole_word_match(keyword, text):
    """Return True if keyword appears as a whole word in text (word-boundary match)."""
    try:
        return bool(re.search(r'(?<![a-z0-9])' + re.escape(keyword) + r'(?![a-z0-9])', text))
    except Exception:
        return keyword in text


def find_brands_in_text(text):
    """Return set of brand keywords found in text (lowercase) using whole-word matching.
    Whole-word prevents 'ing' matching 'phishing', 'nab' matching 'unable', etc."""
    found = set()
    for b in BRAND_KEYWORDS:
        if _whole_word_match(b, text):
            found.add(b)
    return found


def find_artists_in_text(text):
    """Return set of artist keywords found in text (lowercase) using whole-word matching.
    Uses static + Last.fm combined list if set."""
    artist_list = _artist_keywords_combined if _artist_keywords_combined is not None else ARTIST_KEYWORDS
    found = set()
    for a in artist_list:
        if _whole_word_match(a, text):
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

def _sha256_list(values):
    try:
        s = "\n".join(str(v) for v in values)
        return hashlib.sha256(s.encode("utf-8", errors="replace")).hexdigest()
    except Exception:
        return ""


def _write_json(path, data):
    try:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=0)
    except Exception:
        pass


def _compute_match_details(url, text=None):
    """
    Return per-source match provenance for a URL.
    - url matches are derived from parsed URL chunks
    - text matches are derived from visible page text (if provided)
    """
    url_text = _text_chunks_from_url(url)
    brands_in_url = find_brands_in_text(url_text)
    artists_in_url = find_artists_in_text(url_text)
    brands_in_text = set()
    artists_in_text = set()
    if text:
        brands_in_text = find_brands_in_text(text)
        artists_in_text = find_artists_in_text(text)
    return {
        "brands_in_url": sorted(brands_in_url),
        "artists_in_url": sorted(artists_in_url),
        "brands_in_text": sorted(brands_in_text),
        "artists_in_text": sorted(artists_in_text),
    }


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
    images = artist.get("images") if isinstance(artist, dict) else None
    image_url = ""
    if isinstance(images, list) and images:
        first = images[0]
        if isinstance(first, dict):
            image_url = first.get("url") or ""
    return {
        "id": artist["id"],
        "name": artist["name"],
        "popularity": artist.get("popularity", 0),
        "image_url": image_url,
    }


def get_artist_popularity(token, artist_name, cache):
    """
    Get artist popularity from Spotify, using cache.
    token: already-fetched OAuth token (fetch once per pipeline run, not per artist).
    Returns dict with name, popularity, spotify_id or None if not found.
    """
    key = artist_name.lower().strip()
    if key in cache:
        entry = cache[key]
        # None means artist was searched and not found — don't retry.
        # A dict with no image_url is a stale entry; fall through to re-fetch.
        if entry is None:
            return None
        if isinstance(entry, dict) and entry.get("image_url"):
            return entry
    time.sleep(0.2)
    result = spotify_search_artist(token, artist_name)
    if result is None:
        cache[key] = None
        return None
    out = {
        "name": result["name"],
        "popularity": result["popularity"],
        "spotify_id": result["id"],
        "image_url": result.get("image_url") or "",
    }
    cache[key] = out
    return out


# -----------------------------------------------------------------------------
# Graph
# -----------------------------------------------------------------------------
def domain_from_url(url):
    """Extract full hostname (netloc) from URL."""
    try:
        parsed = urlparse(url)
        return parsed.netloc or ""
    except Exception:
        return ""


def registered_domain_from_url(url):
    """Extract the registered domain (e.g. evil.com from sub.evil.com) using tldextract.
    Returns (registered_domain, is_subdomain) where is_subdomain is True when the
    hostname has a subdomain prefix beyond the registered domain.
    Returns (netloc, False) as fallback if tldextract is unavailable.
    """
    try:
        import tldextract
        ext = tldextract.extract(url)
        if ext.domain and ext.suffix:
            reg = f"{ext.domain}.{ext.suffix}"
            netloc = domain_from_url(url)
            is_sub = bool(ext.subdomain) and netloc != reg
            return reg, is_sub
    except Exception:
        pass
    return domain_from_url(url), False


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


def build_graph(results, brand_images=None):
    """
    results: list of dicts, each:
      url, domain, brands (set), artists (list of dict), optional evidence (url_parse | page_content)
    Uses string-safe node IDs for GEXF; stores type, label (short for visualization), full_url,
    domain, title, popularity, image_url on nodes; relationship type and evidence source on edges.
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
        reg_domain, is_sub = registered_domain_from_url(url)
        rd_id = get_id("registered_domain", reg_domain) if (reg_domain and is_sub) else None

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
            parent_id=rd_id or "",
        )
        if rd_id:
            # Create or update the registered_domain compound parent node
            if rd_id not in G:
                G.add_node(
                    rd_id,
                    type="registered_domain",
                    label=reg_domain,
                    full_url="",
                    domain=reg_domain,
                    title=reg_domain,
                    popularity=0,
                )
        G.add_edge(u_id, d_id, relationship_type="hosted_on", evidence_source=evidence)
        for b in r.get("brands", set()):
            if not b:
                continue
            b_id = get_id("brand", b)
            page_img = (brand_images or {}).get(b, "")
            if page_img:
                brand_image_url = f"/page-images/{page_img}"
            elif b in BRAND_LOGO_MAP:
                brand_image_url = BRAND_LOGO_MAP[b]
            else:
                brand_image_url = f"/avatar/brand/{b_id}.svg"
            G.add_node(
                b_id,
                type="brand",
                label=b,
                full_url="",
                domain="",
                title=b,
                popularity=0,
                image_url=brand_image_url,
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
            img = (a.get("image_url") or "").strip()
            a_id = get_id("artist", name)
            G.add_node(
                a_id,
                type="artist",
                label=name,
                full_url="",
                domain="",
                title=name,
                popularity=pop if pop is not None else 0,
                image_url=img or f"/avatar/artist/{a_id}.svg",
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
    node_attrs = ("type", "label", "full_url", "domain", "title", "popularity", "image_url")
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


def _focus_subgraph(G):
    """Return a subgraph with only domain, registered_domain, brand, artist nodes (no phishing_url). Edges: brand-domain, artist-domain (via shared URL), artist-brand (co_mentioned). Used for GEXF/CSV; not for web display."""
    focus_types = {"domain", "registered_domain", "brand", "artist"}
    nodes = [n for n in G.nodes() if G.nodes[n].get("type") in focus_types]
    if not nodes:
        return G.subgraph(nodes).copy()
    H = nx.DiGraph()
    for n in nodes:
        H.add_node(n, **{k: v for k, v in G.nodes[n].items()})
    # For each phishing_url u: u -> d (domain), b -> u (brand), a -> u (artist). Add (b,d), (a,d) and keep (a,b) from co_mentioned.
    for u in G.nodes():
        if G.nodes[u].get("type") != "phishing_url":
            continue
        succ = list(G.successors(u))
        pred = list(G.predecessors(u))
        d_ids = [v for v in succ if G.nodes[v].get("type") in ("domain", "registered_domain")]
        b_ids = [v for v in pred if G.nodes[v].get("type") == "brand"]
        a_ids = [v for v in pred if G.nodes[v].get("type") == "artist"]
        for d in d_ids:
            for b in b_ids:
                if H.has_node(b) and H.has_node(d):
                    H.add_edge(b, d, relationship_type="brand_referenced_on_domain", evidence_source=G.nodes[u].get("full_url", ""))
            for a in a_ids:
                if H.has_node(a) and H.has_node(d):
                    H.add_edge(a, d, relationship_type="mentioned_on_domain", evidence_source=G.nodes[u].get("full_url", ""))
    for u, v, data in G.edges(data=True):
        if data.get("relationship_type") == "co_mentioned" and H.has_node(u) and H.has_node(v):
            H.add_edge(u, v, relationship_type="co_mentioned", evidence_source=data.get("evidence_source", ""))
    return H


def _brand_artist_subgraph(G, max_nodes=None):
    """Return subgraph with only brand and artist nodes; edges = co_mentioned (same URL). Used for web/PNG/interactive display."""
    focus_types = {"brand", "artist"}
    nodes = [n for n in G.nodes() if G.nodes[n].get("type") in focus_types]
    if not nodes:
        return G.subgraph([]).copy()
    H = nx.DiGraph()
    for n in nodes:
        H.add_node(n, **{k: v for k, v in G.nodes[n].items()})
    for u, v, data in G.edges(data=True):
        if data.get("relationship_type") == "co_mentioned" and H.has_node(u) and H.has_node(v):
            H.add_edge(u, v, relationship_type="co_mentioned", evidence_source=data.get("evidence_source", ""))
    if max_nodes and H.number_of_nodes() > max_nodes:
        deg = dict(H.degree())
        top = sorted(deg, key=deg.get, reverse=True)[:max_nodes]
        H = H.subgraph(top).copy()
    return H


def _fetch_node_image_arr(url, size=80):
    """Fetch an image URL and return a circular-cropped numpy array, or None."""
    try:
        import io
        import numpy as np
        from PIL import Image, ImageDraw
        resp = requests.get(url, timeout=6, headers={"User-Agent": USER_AGENT})
        resp.raise_for_status()
        img = Image.open(io.BytesIO(resp.content)).convert("RGBA")
        img = img.resize((size, size), Image.LANCZOS)
        mask = Image.new("L", (size, size), 0)
        ImageDraw.Draw(mask).ellipse([0, 0, size - 1, size - 1], fill=255)
        img.putalpha(mask)
        return np.array(img)
    except Exception:
        return None


def render_campaign_thumbnail(G, artist_node_id, path, spotify_cache=None):
    """
    Render a small PNG thumbnail for one artist's campaign subgraph.
    Shows artist node (with Spotify photo) + connected brand nodes (with logos).
    Saves to path.
    """
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.patheffects as pe
    from matplotlib.offsetbox import OffsetImage, AnnotationBbox
    import numpy as np

    if artist_node_id not in G:
        return

    # Build ego subgraph: artist + directly connected brand nodes
    data = G.nodes[artist_node_id] or {}
    artist_label = data.get("label") or str(artist_node_id)
    neighbors = [nb for nb in (G.successors(artist_node_id) if G.is_directed() else G.neighbors(artist_node_id))
                 if (G.nodes[nb] or {}).get("type") == "brand"]
    nodes = [artist_node_id] + neighbors
    H = G.subgraph(nodes).copy()
    if H.number_of_nodes() == 0:
        return

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    try:
        pos = nx.spring_layout(H, k=2.0, seed=42, iterations=80)
    except Exception:
        pos = nx.random_layout(H, seed=42)

    # Compute axis limits with generous padding so outer nodes + labels don't clip
    xs = [p[0] for p in pos.values()]
    ys = [p[1] for p in pos.values()]
    xpad = max(0.35, (max(xs) - min(xs)) * 0.28)
    ypad = max(0.35, (max(ys) - min(ys)) * 0.28)
    xlim = (min(xs) - xpad, max(xs) + xpad)
    ylim = (min(ys) - ypad, max(ys) + ypad)

    fig, ax = plt.subplots(figsize=(5, 4))
    fig.patch.set_facecolor("#0b1020")
    ax.set_facecolor("#0b1020")
    ax.axis("off")
    ax.set_xlim(xlim)
    ax.set_ylim(ylim)

    # Draw edges first
    for u, v in H.edges():
        if u in pos and v in pos:
            x0, y0 = pos[u]
            x1, y1 = pos[v]
            ax.plot([x0, x1], [y0, y1], color="#ffffff", alpha=0.15, linewidth=0.8, zorder=1)

    # Draw nodes with images where available
    for node in H.nodes():
        ndata = H.nodes[node] or {}
        ntype = ndata.get("type", "")
        label = (ndata.get("label") or str(node))[:20]
        img_url = ndata.get("image_url") or ""
        x, y = pos[node]
        is_artist = ntype == "artist"

        # Try to get image for artist nodes
        arr = None
        if is_artist and not img_url and spotify_cache:
            s = _spotify_image_for_label(spotify_cache, label) if spotify_cache else ""
            if s:
                img_url = s
        if img_url and is_artist:
            arr = _fetch_node_image_arr(img_url, size=90)

        if arr is not None:
            oi = OffsetImage(arr, zoom=0.55, zorder=3)
            ab = AnnotationBbox(oi, (x, y), frameon=False, zorder=3)
            ax.add_artist(ab)
        else:
            color = "#e67e22" if is_artist else "#2ecc71"
            size = 220 if is_artist else 80
            ax.scatter(x, y, s=size, c=color, zorder=2, alpha=0.92, linewidths=0)

        # Label
        color = "#e67e22" if is_artist else "#aab4de"
        fontsize = 7 if not is_artist else 9
        fontweight = "bold" if is_artist else "normal"
        txt = ax.text(x, y - 0.08, label, ha="center", va="top", fontsize=fontsize,
                      color=color, fontweight=fontweight, zorder=4)
        txt.set_path_effects([pe.withStroke(linewidth=2, foreground="#0b1020")])

    plt.tight_layout(pad=0.2)
    plt.savefig(str(path), dpi=90, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()


def render_all_campaign_thumbnails(G, spotify_cache=None):
    """Render a thumbnail PNG for each artist node in G."""
    rendered = 0
    for node in G.nodes():
        data = G.nodes[node] or {}
        if data.get("type") != "artist":
            continue
        safe_id = re.sub(r"[^a-zA-Z0-9_-]", "_", str(node))
        out_path = CAMPAIGN_THUMBS_DIR / f"{safe_id}.png"
        try:
            render_campaign_thumbnail(G, node, out_path, spotify_cache=spotify_cache)
            rendered += 1
        except Exception as e:
            print(f"  Thumbnail failed for {node}: {e}")
    if rendered:
        print(f"Rendered {rendered} campaign thumbnails to {CAMPAIGN_THUMBS_DIR}.")


def render_graph_to_image(G, path, max_nodes=None):
    """Render the graph to a PNG for web display. Shows only brands and artists (co-mentioned); URLs/domains omitted."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    max_nodes = max_nodes if max_nodes is not None else MAX_IMAGE_NODES
    H = _brand_artist_subgraph(G, max_nodes)
    if H.number_of_nodes() == 0:
        return
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    type_colors = {"brand": "#2ecc71", "artist": "#e67e22"}
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
    from matplotlib.patches import Patch
    legend_handles = [
        Patch(facecolor="#2ecc71", label="brand"),
        Patch(facecolor="#e67e22", label="artist"),
    ]
    plt.legend(handles=legend_handles, loc="upper left", fontsize=8)
    plt.tight_layout()
    plt.savefig(str(path), dpi=100, bbox_inches="tight")
    plt.close()
    print(f"Rendered graph image to {path} ({H.number_of_nodes()} nodes).")


def export_interactive_html(G, path, max_nodes=None):
    """Export an interactive Plotly HTML graph (zoom, pan, hover). Shows only brands and artists (co-mentioned)."""
    try:
        import plotly.graph_objects as go
    except ImportError:
        print("Plotly not installed; skipping interactive HTML export.")
        return
    max_nodes = max_nodes if max_nodes is not None else MAX_IMAGE_NODES
    H = _brand_artist_subgraph(G, max_nodes)
    if H.number_of_nodes() == 0:
        return
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        # Slightly larger k spreads nodes out a bit more, which helps tapping on mobile.
        pos = nx.spring_layout(H, k=1.8, seed=42, iterations=50)
    except Exception:
        pos = nx.random_layout(H, seed=42)
    node_list = list(H.nodes())
    type_colors = {"brand": "#2ecc71", "artist": "#e67e22"}
    x = [pos[n][0] for n in node_list]
    y = [pos[n][1] for n in node_list]

    # Degree-based sizing and label selection
    deg = dict(H.degree())
    base_size = 8
    size_multiplier = 2
    degree_cap = 10
    marker_sizes = []
    text_labels = []
    hover_labels = []
    node_types = []
    full_urls = []
    for n in node_list:
        d = deg.get(n, 0)
        marker_sizes.append(base_size + size_multiplier * min(d, degree_cap))
        lbl = str((H.nodes[n].get("label") or H.nodes[n].get("type") or n)).strip()
        short_label = lbl[:40]
        # Only show text label for nodes with degree > 1 to reduce clutter; all nodes still have hover.
        text_labels.append(short_label if d > 1 else "")
        hover_labels.append(short_label or H.nodes[n].get("type") or str(n))
        node_types.append(H.nodes[n].get("type", ""))
        full_urls.append(H.nodes[n].get("full_url", "") or "")

    hover_text = [
        f"<b>{lb}</b><br>type: {t}<br>connections: {deg.get(n, 0)}"
        f"<br>{u[:80]}{'...' if len(u) > 80 else ''}"
        for n, lb, t, u in zip(node_list, hover_labels, node_types, full_urls)
    ]
    colors = [type_colors.get(t, "#95a5a6") for t in node_types]
    edge_x, edge_y = [], []
    for u, v in H.edges():
        if u in pos and v in pos:
            edge_x.extend([pos[u][0], pos[v][0], None])
            edge_y.extend([pos[u][1], pos[v][1], None])
    edge_trace = go.Scatter(x=edge_x, y=edge_y, line=dict(width=0.5, color="#cccccc"), hoverinfo="none", mode="lines")
    node_trace = go.Scatter(
        x=x,
        y=y,
        text=text_labels,
        mode="markers+text",
        textposition="top center",
        textfont=dict(size=11),
        marker=dict(size=marker_sizes, color=colors, line=dict(width=0.5)),
        hovertext=hover_text,
        hoverinfo="text",
        name="",
    )
    fig = go.Figure(data=[edge_trace, node_trace])
    fig.update_layout(
        showlegend=False,
        title="Phishing graph (interactive)",
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        margin=dict(b=20, l=20, r=20, t=40),
        autosize=True,
        height=700,
        dragmode="pan",
        hovermode="closest",
    )
    fig.write_html(str(path), config={"responsive": True})
    print(f"Exported interactive graph to {path} ({H.number_of_nodes()} nodes).")


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
    global _artist_keywords_combined
    _load_proxy_list()
    backfill_image_hashes()
    # Refresh Last.fm top-artists cache if configured, then build combined artist list for matching.
    refresh_lastfm_cache_if_needed()
    _artist_keywords_combined = build_combined_artist_keywords()
    if LASTFM_API_KEY and _artist_keywords_combined != ARTIST_KEYWORDS:
        print(f"Artist keywords: {len(ARTIST_KEYWORDS)} static + Last.fm = {len(_artist_keywords_combined)} total.")

    client_id = os.environ.get("SPOTIFY_CLIENT_ID", "")
    client_secret = os.environ.get("SPOTIFY_CLIENT_SECRET", "")
    use_spotify = bool(client_id and client_secret)
    spotify_token = None
    if not use_spotify:
        print("SPOTIFY_CLIENT_ID / SPOTIFY_CLIENT_SECRET not set; artist popularity will be missing.")
    else:
        try:
            spotify_token = get_spotify_token(client_id, client_secret)
            print("Spotify token obtained.")
        except Exception as e:
            print(f"Spotify token fetch failed: {e}; artist images will be missing.")
            use_spotify = False

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
    run_started = datetime.now(timezone.utc)
    counts = {
        "urls_total_candidate": 0,
        "urls_processed": 0,
        "download_failed": 0,
        "kept_any_match": 0,
        "kept_brand": 0,
        "kept_artist": 0,
        "kept_both": 0,
        "dropped_no_brand_no_artist": 0,
        "dropped_no_brand": 0,
        "dropped_no_artist": 0,
    }

    to_process = urls if NO_DOWNLOAD else urls[:MAX_URLS]
    n_total = len(to_process)
    counts["urls_total_candidate"] = len(urls)
    counts["urls_processed"] = n_total
    step = 10 if n_total > 50 else 1
    for i, url in enumerate(to_process):
        if i == 0 or (i + 1) % step == 0 or i == n_total - 1:
            print(f"[{i+1}/{n_total}] ...")
        domain = domain_from_url(url)
        if NO_DOWNLOAD:
            # Never request phishing URLs; detect brands/artists from URL path, query, domain.
            match_detail = _compute_match_details(url, text=None)
            brands = set(match_detail["brands_in_url"])
            artist_keys = set(match_detail["artists_in_url"])
            artists = []
            for ak in artist_keys:
                if use_spotify:
                    a = get_artist_popularity(spotify_token, ak, spotify_cache)
                    if a:
                        artists.append(a)
                    else:
                        artists.append({"artist_keyword": ak, "popularity": None})
                else:
                    artists.append({"artist_keyword": ak, "popularity": None})
            has_brand = bool(brands)
            has_artist = bool(artists)
            if not has_brand and not has_artist:
                counts["dropped_no_brand_no_artist"] += 1
            else:
                counts["kept_any_match"] += 1
                if has_brand:
                    counts["kept_brand"] += 1
                if has_artist:
                    counts["kept_artist"] += 1
                if has_brand and has_artist:
                    counts["kept_both"] += 1
                results.append({
                    "url": url,
                    "domain": domain,
                    "brands": brands,
                    "artists": artists,
                    "evidence": "url_parse",
                    "match_detail": match_detail,
                })
            continue
        ok, html, truncated = download_page(url)
        if not ok:
            counts["download_failed"] += 1
            continue
        if truncated:
            print(f"  response truncated at {MAX_RESPONSE_BYTES // 1024}KB: {url[:80]}")
        text = extract_visible_text(html)
        match_detail = _compute_match_details(url, text=text)
        match_detail["response_truncated"] = truncated
        match_detail["response_bytes"] = len(html.encode("utf-8", errors="replace"))
        hero_img_url = extract_page_hero_image(html, url)
        page_image_file = ""
        if hero_img_url:
            page_image_file = download_and_cache_image(hero_img_url, PAGE_IMAGES_DIR)
        brands = set(match_detail["brands_in_url"]) | set(match_detail["brands_in_text"])
        artist_keys = set(match_detail["artists_in_url"]) | set(match_detail["artists_in_text"])
        artists = []
        for ak in artist_keys:
            if use_spotify:
                a = get_artist_popularity(spotify_token, ak, spotify_cache)
                if a:
                    artists.append(a)
                else:
                    artists.append({"artist_keyword": ak, "popularity": None})
            else:
                artists.append({"artist_keyword": ak, "popularity": None})
        has_brand = bool(brands)
        has_artist = bool(artists)
        if not has_brand and not has_artist:
            counts["dropped_no_brand_no_artist"] += 1
        else:
            counts["kept_any_match"] += 1
            if has_brand:
                counts["kept_brand"] += 1
            else:
                counts["dropped_no_brand"] += 1
            if has_artist:
                counts["kept_artist"] += 1
            else:
                counts["dropped_no_artist"] += 1
            if has_brand and has_artist:
                counts["kept_both"] += 1
            results.append({
                "url": url,
                "domain": domain,
                "brands": brands,
                "artists": artists,
                "evidence": "page_content",
                "match_detail": match_detail,
                "page_image_file": page_image_file,
            })
        time.sleep(REQUEST_DELAY)

    if use_spotify:
        save_spotify_cache(spotify_cache)

    if USE_URL_HISTORY:
        mark_urls_processed(to_process)
        print(f"Marked {len(to_process)} URLs as processed in history.")
        save_url_matches(results)
        print(f"Saved match data for {len(results)} URLs to history DB.")
        all_results = load_all_historical_results()
        print(f"Loaded {len(all_results)} cumulative URL matches from history for graph build.")
    else:
        all_results = results

    # Build brand_images from full history (first cached page image per brand).
    brand_images = {}
    for r in all_results:
        pf = r.get("page_image_file", "")
        if not pf:
            continue
        for b in r.get("brands", set()):
            if b and b not in brand_images:
                brand_images[b] = pf
    if brand_images:
        print(f"Brand images cached: {len(brand_images)} brands have page images.")

    # Always write the co-occurrence subset (URLs with BOTH brand AND artist) so the UI dropdown works.
    co_results = [r for r in all_results if (r.get("brands") and r.get("artists"))]
    if co_results:
        export_url_brands_csv(co_results, CO_OCCURRENCE_CSV)
        export_gexf(build_graph(co_results, brand_images=brand_images), CO_OCCURRENCE_GEXF)
        print(f"Co-occurrence subset: {len(co_results)} URLs. Wrote {CO_OCCURRENCE_GEXF}.")
    else:
        print("No co-occurrences found (no URLs with both brand and artist).")

    # Optionally restrict pipeline output to co-occurrence only.
    if CO_OCCURRENCE_ONLY:
        all_results = co_results
        print(f"CO_OCCURRENCE_ONLY: keeping only the {len(all_results)} co-occurrence URLs.")
        if not all_results:
            print("Try NO_DOWNLOAD=False (and run in Docker) to scan page content.")
            return
    else:
        export_url_brands_csv(all_results, URL_BRANDS_CSV)

    G = build_graph(all_results, brand_images=brand_images)
    export_gexf(G, GRAPH_GEXF)
    export_edges_csv(G, EDGES_CSV)
    if not CO_OCCURRENCE_ONLY:
        export_url_brands_csv(all_results, URL_BRANDS_CSV)
    print_stats(G, all_results)
    print(f"\nGraph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges.")

    # Rendered images for web (Railway / stream)
    OUTPUT_IMAGES_DIR.mkdir(parents=True, exist_ok=True)
    render_graph_to_image(G, OUTPUT_IMAGES_DIR / "latest.png")
    export_interactive_html(G, OUTPUT_IMAGES_DIR / "graph_interactive.html")
    H = _brand_artist_subgraph(G)
    brands_count = sum(1 for n in H.nodes() if H.nodes[n].get("type") == "brand")
    artists_count = sum(1 for n in H.nodes() if H.nodes[n].get("type") == "artist")
    stats = {
        "display_nodes": H.number_of_nodes(),
        "full_nodes": G.number_of_nodes(),
        "full_edges": G.number_of_edges(),
        "brands_count": brands_count,
        "artists_count": artists_count,
    }
    try:
        with open(OUTPUT_IMAGES_DIR / "stats.json", "w", encoding="utf-8") as f:
            json.dump(stats, f, indent=0)
    except Exception:
        pass
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M")
    render_graph_to_image(G, OUTPUT_IMAGES_DIR / f"graph_{ts}.png")

    # Persist rich metadata for the interactive UI (Option B) to consume.
    artist_list = _artist_keywords_combined if _artist_keywords_combined is not None else ARTIST_KEYWORDS
    keywords_payload = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "brands": {
            "bank_keywords": BANK_KEYWORDS,
            "other_brand_keywords": OTHER_BRAND_KEYWORDS,
            "total": len(BRAND_KEYWORDS),
            "sha256": _sha256_list(BRAND_KEYWORDS),
        },
        "artists": {
            "static_keywords": ARTIST_KEYWORDS,
            "combined_keywords": list(artist_list) if isinstance(artist_list, list) else ARTIST_KEYWORDS,
            "static_count": len(ARTIST_KEYWORDS),
            "combined_count": len(artist_list) if isinstance(artist_list, list) else len(ARTIST_KEYWORDS),
            "sha256": _sha256_list(artist_list if isinstance(artist_list, list) else ARTIST_KEYWORDS),
            "lastfm_enabled": bool(LASTFM_API_KEY),
            "lastfm_cache_file": str(LASTFM_CACHE_FILE),
        },
    }
    _write_json(KEYWORDS_JSON, keywords_payload)

    # Keep match records fairly small; UI can paginate on client side.
    matches_payload = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "note": "Per-URL match provenance. brands/artists may be from url_parse and/or page_content.",
        "results": [
            {
                "url": r.get("url", ""),
                "domain": r.get("domain", ""),
                "evidence": r.get("evidence", ""),
                "brands": sorted(list(r.get("brands") or [])),
                "artists": [
                    {
                        "name": (a.get("name") or "").strip(),
                        "artist_keyword": (a.get("artist_keyword") or "").strip(),
                        "popularity": a.get("popularity"),
                        "spotify_id": a.get("spotify_id"),
                        "image_url": (a.get("image_url") or "").strip(),
                    }
                    for a in (r.get("artists") or [])
                    if isinstance(a, dict)
                ],
                "match_detail": r.get("match_detail") or {},
            }
            for r in results
        ],
    }
    _write_json(MATCHES_JSON, matches_payload)

    run_meta = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "run_started_utc": run_started.isoformat().replace("+00:00", "Z"),
        "config": {
            "NO_DOWNLOAD": NO_DOWNLOAD,
            "USE_URL_HISTORY": USE_URL_HISTORY,
            "PROCESS_LAST_DAYS": PROCESS_LAST_DAYS,
            "MAX_URLS_FROM_HISTORY": MAX_URLS_FROM_HISTORY,
            "MAX_URLS": MAX_URLS,
            "REQUEST_DELAY": REQUEST_DELAY,
            "CO_OCCURRENCE_ONLY": CO_OCCURRENCE_ONLY,
            "MAX_IMAGE_NODES": MAX_IMAGE_NODES,
            "MAX_GEXF_NODES": MAX_GEXF_NODES,
            "LASTFM_ENABLED": bool(LASTFM_API_KEY),
            "SPOTIFY_ENABLED": use_spotify,
        },
        "counts": counts,
        "files": {
            "graph_gexf": str(GRAPH_GEXF.resolve()),
            "co_occurrence_gexf": str(CO_OCCURRENCE_GEXF.resolve()),
            "edges_csv": str(EDGES_CSV.resolve()),
            "url_brands_csv": str(URL_BRANDS_CSV.resolve()),
            "co_occurrence_urls_csv": str(CO_OCCURRENCE_CSV.resolve()),
            "latest_png": str((OUTPUT_IMAGES_DIR / "latest.png").resolve()),
            "stats_json": str((OUTPUT_IMAGES_DIR / "stats.json").resolve()),
            "run_meta_json": str(RUN_META_JSON.resolve()),
            "keywords_json": str(KEYWORDS_JSON.resolve()),
            "matches_json": str(MATCHES_JSON.resolve()),
        },
        "graph_stats": {
            "full_nodes": G.number_of_nodes(),
            "full_edges": G.number_of_edges(),
            "display_nodes": H.number_of_nodes(),
            "display_brands": brands_count,
            "display_artists": artists_count,
        },
    }
    _write_json(RUN_META_JSON, run_meta)
    # Campaign thumbnails: render a small graph PNG per artist
    try:
        CAMPAIGN_THUMBS_DIR.mkdir(parents=True, exist_ok=True)
        render_all_campaign_thumbnails(G, spotify_cache=spotify_cache)
    except Exception as e:
        print(f"Campaign thumbnail rendering failed (non-fatal): {e}")

    # Keep only last 5 timestamped images
    hist = sorted(OUTPUT_IMAGES_DIR.glob("graph_*.png"), key=lambda p: p.stat().st_mtime, reverse=True)
    for old in hist[5:]:
        try:
            old.unlink()
        except Exception:
            pass


if __name__ == "__main__":
    main()
