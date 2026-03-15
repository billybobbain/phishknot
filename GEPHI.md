# Viewing the graph in Gephi

**Yes — brands (and URLs, domains, artists) are in the GEXF.** Node IDs are hashes for stability; the human-readable text is in the **Label** and in node attributes.

## What’s in the GEXF

- **Each node has**
  - `id` — internal hash (e.g. `brand_a1b2c3...`). Ignore this for reading.
  - **`label`** — the text you care about: brand name (e.g. `apple`), artist name, URL snippet, or domain.
  - Attributes: **`type`** (brand | artist | phishing_url | domain), **`domain`**, **`title`**, **`popularity`** (artists).
- **Each edge has**
  - **`relationship_type`** — e.g. `brand_referenced`, `hosted_on`, `mentioned_in_lure`.
  - **`evidence_source`** — `url_parse` or `page_content`.

## How to see it in Gephi

1. **Open the file**  
   File → Open → choose `phishing_graph.gexf`.

2. **See labels on the graph**  
   In the **Overview** tab, the text next to nodes is the **Label** (brand/artist/URL/domain).  
   If you don’t see text: bottom left **Preview** settings → **Show Labels** (and optionally **Shorten labels**).

3. **See all columns (including brand/type)**  
   Switch to the **Data Laboratory** tab. You’ll see a table of nodes with columns such as **Id**, **Label**, **type**, **domain**, **title**, **popularity**.  
   - **Label** = the name (e.g. `apple`, `paypal`, or the URL).  
   - **type** = `brand` | `artist` | `phishing_url` | `domain`.

4. **Color by node type**  
   Back in **Overview**: left panel **Appearance** → **Nodes** → **Partition** → choose **type**.  
   Then you can give one color to “brand”, another to “phishing_url”, etc.

5. **Filter to only brands**  
   In **Data Laboratory**: use **Filters** (right panel) and filter by **type** = `brand`, or in **Overview** use the **Filters** tab to restrict the graph to a node attribute (e.g. `type` = brand).

So: the GEXF does contain the brand (and other) info; in Gephi you see it as **Label** and in the **type** (and other) columns in the Data Laboratory.
