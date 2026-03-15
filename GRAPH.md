# Graph node types and structure

The graph has **four node types**, all created in `build_graph()` in `phishing_brand_graph.py`:

| Type | What it is | Label shows | Why there are many |
|------|------------|-------------|---------------------|
| **phishing_url** | One node per phishing URL from the feed | Short form: hostname or hostname + path (e.g. `ipfs.io`, `roblox.com.ge`, `45.61.49.78`) | 300 URLs → up to 300 nodes; these are the "URL or IP" nodes. |
| **domain** | One node per unique hostname | Domain (same as hostname) | One per unique domain; can look like URLs or IPs. |
| **brand** | One node per matched brand keyword | Brand name (e.g. amazon, netflix, apple) | Only created when a URL/path matches `BRAND_KEYWORDS`. |
| **artist** | One node per matched artist | Artist name (e.g. ye, taylor swift) | Only created when a URL/path matches `ARTIST_KEYWORDS`. |

**Edges:** `phishing_url → domain` (hosted_on), `brand → phishing_url` (brand_referenced), `artist → phishing_url` (mentioned_in_lure), `artist → brand` (co_mentioned).

**Static image colors:** phishing_url = blue, domain = gray, brand = green, artist = orange (see legend on the PNG).

**Focus view:** A "semantic" view omits `phishing_url` nodes and shows only domain, brand, and artist (e.g. `latest_focus.png`) to reduce noise.
