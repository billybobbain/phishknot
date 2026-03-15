# Graph node types and structure

The **full graph** (GEXF, CSV) has **four node types**, all created in `build_graph()` in `phishing_brand_graph.py`:

| Type | What it is | Label shows |
|------|------------|-------------|
| **phishing_url** | One node per phishing URL from the feed | Short form: hostname or hostname + path |
| **domain** | One node per unique hostname | Domain (same as hostname) |
| **brand** | One node per matched brand keyword | Brand name (e.g. amazon, netflix, apple) |
| **artist** | One node per matched artist | Artist name (e.g. ye, taylor swift) |

**Edges:** `phishing_url → domain` (hosted_on), `brand → phishing_url` (brand_referenced), `artist → phishing_url` (mentioned_in_lure), `artist → brand` (co_mentioned).

**Web display (PNG + interactive):** Only **brands** and **artists** are shown; URLs and domains are omitted. Edges are **co_mentioned** (same phishing URL). Colors: brand = green, artist = orange. This keeps the visualization focused on what lures pair which brands with which artists.
