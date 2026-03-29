"""
Julia Set Graph Layout Prototype
=================================
Fetches live graph data from Railway (or reads local GEXF), maps nodes to
Julia set regions, outputs a self-contained julia_layout.html.

Node → region mapping:
  artist            → boundary (low escape iter) — edge of chaos, most visually rich
  brand             → near band, high-degree brands pulled toward boundary
  domain            → mid/far band
  registered_domain → interior (non-escaping) — captured infrastructure
  phishing_url      → outermost band

Usage:
  python julia_layout.py                              # fetch live from Railway
  python julia_layout.py --gexf phishing_graph.gexf  # use local file instead
  python julia_layout.py --c "-0.4+0.6j"             # Douady's rabbit
  python julia_layout.py --c "-0.835-0.2321j"        # fine filaments
  python julia_layout.py --c "-2.1"                  # Cantor dust
  python julia_layout.py --all                        # render all presets
  python julia_layout.py --res 1200 --iter 512
"""

import argparse
import json
import math
import random
import sys
import urllib.request
from pathlib import Path

import networkx as nx
import numpy as np

# matplotlib for Julia set image rendering
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import base64, io

RAILWAY_URL = "https://phishknot-production.up.railway.app"


def load_graph_from_api(base_url: str, max_nodes: int = 500) -> nx.DiGraph:
    """Fetch /graph/data JSON and build a NetworkX DiGraph."""
    url = f"{base_url}/graph/data?view=focus&max_nodes={max_nodes}"
    print(f"Fetching {url} …")
    with urllib.request.urlopen(url, timeout=30) as r:
        data = json.load(r)
    G = nx.DiGraph()
    for n in data["nodes"]:
        G.add_node(n["id"], **{k: v for k, v in n.items() if k != "id"})
    for e in data["edges"]:
        G.add_edge(e["source"], e["target"])
    print(f"  {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
    return G


# ---------------------------------------------------------------------------
# Julia set computation
# ---------------------------------------------------------------------------

def julia_iter_map(c, res=800, max_iter=256, extent=2.0):
    """
    Compute escape-time iteration map for f(z) = z^2 + c.
    Returns 2D int32 array shaped (res, res).
    Value == max_iter  → non-escaping (interior / on the set)
    Value <  max_iter  → escaped at that iteration (lower = faster escape)
    Axes: row 0 = top (imag +extent), col 0 = left (real -extent).
    """
    re = np.linspace(-extent, extent, res, dtype=np.float64)
    im = np.linspace( extent,-extent, res, dtype=np.float64)  # flip so +imag = up
    Z  = re[np.newaxis, :] + 1j * im[:, np.newaxis]
    iters   = np.full(Z.shape, max_iter, dtype=np.int32)
    escaped = np.zeros(Z.shape, dtype=bool)
    for i in range(1, max_iter + 1):
        mask     = ~escaped
        Z[mask]  = Z[mask] ** 2 + c
        new_esc  = mask & (np.abs(Z) > 2.0)
        iters[new_esc] = i
        escaped |= new_esc
    return iters


def build_pools(iters, res, extent, max_iter, rng, downsample=4):
    """
    Sample (x, y) points in complex-plane coords from each region.
    downsample: only keep every Nth pixel to avoid adjacent-pixel clustering.
    """
    re = np.linspace(-extent, extent, res)
    im = np.linspace( extent,-extent, res)

    def mask_to_pts(mask):
        rows, cols = np.where(mask)
        # Thin out — keep rows/cols where both are multiples of downsample
        keep = (rows % downsample == 0) & (cols % downsample == 0)
        rows, cols = rows[keep], cols[keep]
        pts = list(zip(re[cols].tolist(), im[rows].tolist()))
        rng.shuffle(pts)
        return pts

    b_lo, b_hi = 1, max(2, max_iter // 30)   # boundary: very thin escape band
    n_lo, n_hi = b_hi, max_iter // 6          # near:     moderate orbit
    m_lo, m_hi = n_hi, max_iter // 2          # mid:      half-way out
    f_lo       = m_hi                          # far:      quick escape

    pools = {
        'interior': mask_to_pts(iters == max_iter),
        'boundary': mask_to_pts((iters >= b_lo) & (iters < b_hi)),
        'near':     mask_to_pts((iters >= n_lo) & (iters < n_hi)),
        'mid':      mask_to_pts((iters >= m_lo) & (iters < m_hi)),
        'far':      mask_to_pts(iters >= f_lo),
    }
    return pools


# ---------------------------------------------------------------------------
# Julia set image rendering
# ---------------------------------------------------------------------------

def render_julia_b64(iters, max_iter, img_res=400):
    """
    Render the Julia set as a PNG and return a base64 string.
    Interior (non-escaping) → near-black.
    Exterior colored by escape speed via 'inferno' colormap:
      slow escape (near boundary) → bright; fast escape → dark.
    """
    # Smooth escape-time value: 0 = interior, 0→1 = exterior (higher = nearer boundary)
    exterior = iters < max_iter
    smooth = np.where(exterior, iters.astype(np.float32) / max_iter, 0.0)

    cmap = plt.get_cmap('inferno')
    rgba = cmap(smooth)                              # (H, W, 4) float32
    rgb  = (rgba[:, :, :3] * 255).astype(np.uint8)
    # Interior: match the app background colour
    rgb[~exterior] = [10, 15, 31]

    # Downsample to img_res × img_res for embedding
    h, w = iters.shape
    step = max(1, h // img_res)
    rgb_small = rgb[::step, ::step]

    fig, ax = plt.subplots(figsize=(3, 3), dpi=100)
    fig.patch.set_facecolor('#0a0f1f')
    ax.set_facecolor('#0a0f1f')
    ax.imshow(rgb_small, aspect='equal', interpolation='bilinear')
    ax.axis('off')
    plt.tight_layout(pad=0)

    buf = io.BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight', pad_inches=0,
                facecolor='#0a0f1f', dpi=100)
    plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode('ascii')


# ---------------------------------------------------------------------------
# Node assignment
# ---------------------------------------------------------------------------

TYPE_POOL_ORDER = {
    'artist':           ['boundary', 'near'],
    'brand':            ['near', 'boundary', 'mid'],
    'domain':           ['mid', 'near', 'far'],
    'registered_domain':['interior', 'mid'],
    'phishing_url':     ['far', 'mid'],
}

def assign_positions(G, pools, rng, scale=380):
    """
    Assign each node a (px, py) screen position from the Julia set pools.
    Higher-degree nodes get first pick within their preferred pool.
    scale: complex-plane unit → screen pixels (extent=2 → ±scale px from center)
    """
    deg = dict(G.degree())
    nodes_by_type = {}
    for n, d in G.nodes(data=True):
        t = d.get('type', 'domain')
        nodes_by_type.setdefault(t, []).append((n, d))

    # Sort each type by degree descending so hubs get the best spots
    for t in nodes_by_type:
        nodes_by_type[t].sort(key=lambda x: -deg.get(x[0], 0))

    pool_iters = {k: iter(v) for k, v in pools.items()}

    def next_pt(pool_order):
        for pname in pool_order:
            try:
                return next(pool_iters[pname])
            except StopIteration:
                continue
        # Absolute fallback: random in unit disk
        angle = rng.uniform(0, 2 * math.pi)
        r = rng.uniform(0, 1.5)
        return (r * math.cos(angle), r * math.sin(angle))

    positions = {}
    for t, node_list in nodes_by_type.items():
        pool_order = TYPE_POOL_ORDER.get(t, ['mid', 'far'])
        for n, _ in node_list:
            cx, cy = next_pt(pool_order)
            positions[n] = (cx * scale, cy * scale)

    return positions


# ---------------------------------------------------------------------------
# HTML generation
# ---------------------------------------------------------------------------

NODE_COLORS = {
    'artist':            {'border': '#e67e22', 'bg': 'rgba(230,126,34,0.22)'},
    'brand':             {'border': '#2ecc71', 'bg': 'rgba(46,204,113,0.22)'},
    'domain':            {'border': '#9b59b6', 'bg': 'rgba(155,89,182,0.22)'},
    'registered_domain': {'border': '#4a90d9', 'bg': 'rgba(20,30,60,0.85)'},
    'phishing_url':      {'border': '#e74c3c', 'bg': 'rgba(231,76,60,0.18)'},
}
NODE_SIZES = {
    'artist': 70, 'brand': 50, 'domain': 38,
    'registered_domain': 55, 'phishing_url': 28,
}


def build_elements(G, positions):
    elements = []
    for n, d in G.nodes(data=True):
        t  = d.get('type', 'domain')
        lbl = d.get('label') or d.get('title') or str(n)
        col = NODE_COLORS.get(t, {'border':'#aaa','bg':'rgba(255,255,255,0.1)'})
        px, py = positions.get(n, (0, 0))
        elements.append({
            'data': {
                'id':     str(n),
                'label':  lbl,
                'type':   t,
                'border': col['border'],
                'bg':     col['bg'],
                'size':   NODE_SIZES.get(t, 34),
            },
            'position': {'x': round(px, 2), 'y': round(py, 2)},
        })
    for u, v, d in G.edges(data=True):
        elements.append({'data': {
            'id':     f'{u}__{v}',
            'source': str(u),
            'target': str(v),
        }})
    return elements


C_PRESETS = [
    ('-0.7+0.27j',    'Classic dendrite'),
    ('-0.4+0.6j',     "Douady's rabbit"),
    ('0.285+0.01j',   'Cauliflower'),
    ('-0.835-0.2321j','Fine filaments'),
    ('-1.755+0j',     'Airplane'),
    ('-2.1+0j',       'Cantor dust'),
    ('0+1j',          'Unit circle'),
    ('-1+0j',         'Basilica'),
]

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Julia Set Graph Layout — PhishKnot</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.28.1/cytoscape.min.js"></script>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#0a0f1f;color:#e7ecff;font-family:system-ui,sans-serif;display:flex;flex-direction:column;height:100vh}}
  header{{display:flex;align-items:center;gap:12px;padding:8px 16px;background:rgba(11,16,32,0.96);
          border-bottom:1px solid rgba(255,255,255,0.1);flex-shrink:0}}
  header h1{{font-size:15px;font-weight:700;letter-spacing:-.01em}}
  header h1 span{{color:#7aa2ff}}
  .ctrl{{display:flex;align-items:center;gap:6px;font-size:12px;color:#aab4de}}
  select,input{{background:#111a33;color:#e7ecff;border:1px solid rgba(255,255,255,0.15);
               border-radius:6px;padding:4px 8px;font-size:12px}}
  button{{cursor:pointer;border:1px solid rgba(255,255,255,0.15);background:rgba(255,255,255,0.06);
          color:#e7ecff;padding:5px 12px;border-radius:6px;font-size:12px}}
  button:hover{{background:rgba(255,255,255,0.1)}}
  #main{{display:flex;flex:1;overflow:hidden}}
  #cy{{flex:1;background:#0a0f1f}}
  #juliaPanel{{width:220px;flex-shrink:0;background:#0b1020;border-left:1px solid rgba(255,255,255,0.1);
               padding:12px;display:flex;flex-direction:column;gap:10px;overflow-y:auto}}
  #juliaPanel h3{{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:#aab4de;margin:0}}
  #juliaImg{{width:100%;border-radius:6px;display:block;image-rendering:pixelated;transform:scaleX(-1)}}
  .region-row{{display:flex;align-items:center;gap:6px;font-size:11px;color:#aab4de}}
  .region-dot{{width:10px;height:10px;border-radius:50%;flex-shrink:0}}
  #info{{position:fixed;bottom:12px;left:50%;transform:translateX(-50%);
         font-size:11px;color:#aab4de;pointer-events:none}}
</style>
</head>
<body>
<header>
  <h1>Phish<span>Knot</span> — Julia Set Layout</h1>
  <div class="ctrl">
    <label>c =</label>
    <select id="cPreset" onchange="onPresetChange()">
      {preset_options}
      <option value="custom">Custom…</option>
    </select>
  </div>
  <div class="ctrl" id="customCtrl" style="display:none">
    <input id="cReal" type="number" step="0.001" value="-0.7" style="width:80px" placeholder="real">
    <span>+</span>
    <input id="cImag" type="number" step="0.001" value="0.27" style="width:80px" placeholder="imag">
    <span>i</span>
    <button onclick="applyCustomC()">Apply</button>
  </div>
  <div class="ctrl">
    <label>max iter</label>
    <input id="maxIter" type="number" min="64" max="1024" step="64" value="{max_iter}" style="width:70px">
  </div>
  <button onclick="recompute()">Re-layout</button>
  <button onclick="cy && cy.fit(undefined,40)">Fit</button>
  <div class="ctrl" style="margin-left:auto">
    <span style="color:#e67e22">■</span> artist &nbsp;
    <span style="color:#2ecc71">■</span> brand &nbsp;
    <span style="color:#9b59b6">■</span> domain &nbsp;
    <span style="color:#e74c3c">■</span> url
  </div>
</header>
<div id="main">
  <div id="cy"></div>
  <div id="juliaPanel">
    <h3>Julia Set</h3>
    <img id="juliaImg" alt="Julia set for current c">
    <div id="cLabel" style="font-size:11px;color:#7aa2ff;word-break:break-all"></div>
    <h3 style="margin-top:4px">Node regions</h3>
    <div class="region-row"><div class="region-dot" style="background:#e67e22"></div>Artist — boundary</div>
    <div class="region-row"><div class="region-dot" style="background:#2ecc71"></div>Brand — near orbit</div>
    <div class="region-row"><div class="region-dot" style="background:#9b59b6"></div>Domain — mid/far</div>
    <div class="region-row"><div class="region-dot" style="background:#4a90d9;border-radius:2px"></div>Reg. domain — interior</div>
    <div class="region-row"><div class="region-dot" style="background:#e74c3c"></div>URL — outer</div>
    <p style="font-size:10px;color:#556;margin-top:8px;line-height:1.5">
      Interior (filled) = non-escaping orbits.<br>
      Boundary = onset of chaos.<br>
      Outer bands = fast escape.
    </p>
  </div>
</div>
<div id="info">Julia set layout &mdash; each c value is a unique topology</div>

<script>
const ALL_DATA   = {all_data_json};
const JULIA_IMGS = {julia_imgs_json};
let cy = null;

function currentC() {{
  const sel = document.getElementById('cPreset').value;
  if (sel === 'custom') {{
    const r = parseFloat(document.getElementById('cReal').value) || 0;
    const i = parseFloat(document.getElementById('cImag').value) || 0;
    return r + ',' + i;
  }}
  return sel;
}}

function onPresetChange() {{
  const sel = document.getElementById('cPreset').value;
  const cc = document.getElementById('customCtrl');
  cc.style.display = sel === 'custom' ? 'flex' : 'none';
  if (sel !== 'custom') renderElements(sel);
}}

function applyCustomC() {{
  renderElements(currentC());
}}

function updateJuliaImage(cKey) {{
  const img = document.getElementById('juliaImg');
  const lbl = document.getElementById('cLabel');
  const b64 = JULIA_IMGS[cKey];
  if (b64) {{
    img.src = 'data:image/png;base64,' + b64;
    img.style.display = 'block';
  }} else {{
    img.style.display = 'none';
  }}
  lbl.textContent = 'c = ' + cKey;
}}

function renderElements(cKey) {{
  const data = ALL_DATA[cKey];
  if (!data) {{ alert('No data for c=' + cKey); return; }}
  updateJuliaImage(cKey);
  const elements = data.elements;
  if (!cy) {{
    cy = cytoscape({{
      container: document.getElementById('cy'),
      elements,
      style: cyStyle(),
      layout: {{ name: 'preset' }},
    }});
    cy.on('tap', 'node', e => {{
      const d = e.target.data();
      document.getElementById('info').textContent =
        d.type + ' · ' + d.label;
    }});
  }} else {{
    cy.batch(() => {{
      cy.elements().remove();
      cy.add(elements);
    }});
    cy.layout({{ name: 'preset' }}).run();
  }}
  cy.fit(undefined, 40);
}}

function recompute() {{
  cy && cy.fit(undefined, 40);
}}

function cyStyle() {{
  return [
    {{ selector: 'node', style: {{
        shape: 'ellipse',
        width: 'data(size)', height: 'data(size)',
        'background-color': 'data(bg)',
        'border-color': 'data(border)',
        'border-width': 2,
        label: 'data(label)',
        color: 'rgba(231,236,255,0.9)',
        'font-size': 10,
        'text-valign': 'bottom',
        'text-halign': 'center',
        'text-margin-y': 8,
        'text-outline-width': 2,
        'text-outline-color': '#0a0f1f',
        'text-wrap': 'ellipsis',
        'text-max-width': 100,
    }}}},
    {{ selector: "node[type='artist']", style: {{
        width: 70, height: 70,
        'border-width': 3, 'font-size': 13,
    }}}},
    {{ selector: 'edge', style: {{
        'curve-style': 'unbundled-bezier',
        width: 1,
        'line-color': 'rgba(255,255,255,0.15)',
        'target-arrow-shape': 'triangle',
        'target-arrow-color': 'rgba(255,255,255,0.15)',
        'arrow-scale': 0.7,
    }}}},
  ];
}}

// Render initial preset
window.addEventListener('load', () => {{
  const first = document.getElementById('cPreset').value;
  renderElements(first);
}});
</script>
</body>
</html>
"""


def generate_html(all_data: dict, julia_imgs: dict, initial_c: str, max_iter: int, out_path: Path):
    preset_options = "\n      ".join(
        f'<option value="{c.replace("j","i")}" {"selected" if c.replace("j","i") == initial_c else ""}>{label} ({c.replace("j","i")})</option>'
        for c, label in C_PRESETS
        if c.replace('j','i') in all_data
    )
    html = HTML_TEMPLATE.format(
        preset_options=preset_options,
        all_data_json=json.dumps(all_data),
        julia_imgs_json=json.dumps(julia_imgs),
        max_iter=max_iter,
    )
    out_path.write_text(html, encoding='utf-8')
    print(f"Written: {out_path}  ({out_path.stat().st_size // 1024} KB)")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description='Julia Set Graph Layout')
    parser.add_argument('--gexf',    default=None,  help='Use local GEXF instead of fetching from Railway')
    parser.add_argument('--url',     default=RAILWAY_URL, help='Railway base URL')
    parser.add_argument('--out',     default='julia_layout.html')
    parser.add_argument('--c',       default=None,  help='Single c value (overrides --all)')
    parser.add_argument('--all',     action='store_true', help='Compute all presets (slower)')
    parser.add_argument('--res',     type=int, default=800)
    parser.add_argument('--iter',    type=int, default=256)
    parser.add_argument('--seed',    type=int, default=42)
    parser.add_argument('--scale',   type=int, default=420)
    parser.add_argument('--max-nodes', type=int, default=500)
    args = parser.parse_args()

    if args.gexf:
        gexf_path = Path(args.gexf)
        if not gexf_path.exists():
            print(f"GEXF not found: {gexf_path}", file=sys.stderr)
            sys.exit(1)
        print(f"Loading {gexf_path}…")
        G = nx.read_gexf(str(gexf_path))
        print(f"  {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
    else:
        G = load_graph_from_api(args.url, max_nodes=args.max_nodes)

    # Decide which c values to compute
    if args.c:
        try:
            c_val = complex(args.c.replace('i','j'))
        except ValueError:
            print(f"Bad c value: {args.c!r}  (use python complex notation, e.g. -0.7+0.27j)", file=sys.stderr)
            sys.exit(1)
        c_list = [(args.c.replace('j','i'), c_val)]
    elif args.all:
        c_list = []
        for cstr, _ in C_PRESETS:
            try:
                c_list.append((cstr, complex(cstr.replace('i','j'))))
            except ValueError:
                pass
    else:
        # Default: compute the 3 most visually distinct presets
        defaults = ['-0.7+0.27j', '-0.4+0.6j', '-2.1+0j']
        c_list = [(s, complex(s)) for s in defaults]

    all_data   = {}
    julia_imgs = {}
    initial_c  = None

    for cstr, c_val in c_list:
        ckey = cstr.replace('j', 'i')   # display key uses 'i' not 'j'
        print(f"  Computing Julia set for c = {c_val}  (res={args.res}, iter={args.iter})…", end=' ', flush=True)
        iters = julia_iter_map(c_val, res=args.res, max_iter=args.iter)
        print(f"boundary pts: {int(np.sum((iters >= 1) & (iters < max(2, args.iter//30))))}", flush=True)

        rng   = random.Random(args.seed)
        pools = build_pools(iters, args.res, 2.0, args.iter, rng)
        pos   = assign_positions(G, pools, rng, scale=args.scale)
        elems = build_elements(G, pos)

        print(f"  Rendering Julia image for {ckey}…", end=' ', flush=True)
        julia_imgs[ckey] = render_julia_b64(iters, args.iter)
        print("done", flush=True)

        all_data[ckey] = {'c': str(c_val), 'elements': elems}
        if initial_c is None:
            initial_c = ckey

    out_path = Path(args.out)
    generate_html(all_data, julia_imgs, initial_c, args.iter, out_path)
    print(f"\nOpen in browser:  {out_path.resolve()}")


if __name__ == '__main__':
    main()
