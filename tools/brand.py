"""Opsidious Auth — the brand files, generated from one place.

The identity of Opsidious Auth: an A whose crossbar is a keyhole. The A is
mist on ink (#E3E7EE) or ink on light (#0B0D12); the keyhole is the
Opsidious violet, #8A6CFF on ink and #6A4BE0 on light (the light value is the
one that holds its contrast on paper). The wordmark is "opsidious auth" in
Space Grotesk, "opsidious" at 600, "auth" at 500 in the keyhole's violet.

Writes:
  public/mark.svg, public/emblem.svg, public/emblem-mark.svg, public/logo.svg,
  public/favicon.svg, and the identity pack under logo/ (svg, icones).
PNG exports are rendered from these by tools/brand-png.mjs.

Requires fontTools (pip install fonttools brotli). Run from the repository
root: python tools/brand.py
"""

import os
from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.boundsPen import BoundsPen
from fontTools.pens.transformPen import TransformPen

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

INK, MIST, PANEL_LINE = '#0B0D12', '#E3E7EE', '#232833'
VIOLET, VIOLET_ON_LIGHT = '#8A6CFF', '#6A4BE0'

A = 'M60 6 L114 108 L86 108 L60 46 L34 108 L6 108 Z'
# The keyhole, at mark size and, slightly smaller, inside the app icon.
KEY = 'M60 66 A10 10 0 0 1 65.8 84.14 L69.5 101 L50.5 101 L54.2 84.14 A10 10 0 0 1 60 66 Z'
KEY_ICON = 'M60 67 A9 9 0 0 1 65.2 83.35 L68.5 100 L51.5 100 L54.8 83.35 A9 9 0 0 1 60 67 Z'

# The symbol's own box inside its 120-unit square.
SYM_BOX = (6, 6, 108, 102)


def symbol_paths(a_fill, key_fill, key=KEY, transform=''):
    t = f' transform="{transform}"' if transform else ''
    return f'<g{t}><path d="{A}" fill="{a_fill}"/><path d="{key}" fill="{key_fill}"/></g>'


def svg(view, w, h, body, label):
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{view}" width="{w}" height="{h}" '
        f'role="img" aria-label="{label}"><title>{label}</title>{body}</svg>\n'
    )


def symbol(a_fill, key_fill, label='Opsidious Auth'):
    x, y, w, h = SYM_BOX
    return svg(f'{x} {y} {w} {h}', w, h, symbol_paths(a_fill, key_fill), label)


def tile(size, round_, label, key=KEY_ICON, ratio=0.61, border=True):
    """The app icon (round_=False → rounded square) or avatar (round_=True)."""
    if round_:
        shape = f'<circle cx="{size/2}" cy="{size/2}" r="{size/2 - 0.5}" fill="{INK}"'
    else:
        r = size * 28 / 124
        shape = f'<rect x="0.5" y="0.5" width="{size-1}" height="{size-1}" rx="{r:.2f}" fill="{INK}"'
    shape += f' stroke="{PANEL_LINE}" stroke-width="{max(1, size/124):.2f}"/>' if border else '/>'
    s = size * ratio / 120
    off = (size - 120 * s) / 2
    body = shape + symbol_paths(MIST, VIOLET, key, f'translate({off:.3f} {off:.3f}) scale({s:.5f})')
    return svg(f'0 0 {size} {size}', size, size, body, label)


# ── The wordmark, as outlines ───────────────────────────────────────────────

FONT = os.path.join(ROOT, 'public', 'fonts', 'space-grotesk-var-latin.woff2')


def face(weight):
    f = TTFont(FONT)
    return instantiateVariableFont(f, {'wght': weight})


def run(font, text, size, x, baseline, tracking_em):
    """Outline `text` at `size` px from (x, baseline). Returns (path, x_end, bounds)."""
    upm = font['head'].unitsPerEm
    cmap = font.getBestCmap()
    gs = font.getGlyphSet()
    hmtx = font['hmtx']
    k = size / upm
    pen = SVGPathPen(gs)
    bp = BoundsPen(gs)
    for ch in text:
        g = cmap[ord(ch)]
        m = (k, 0, 0, -k, x, baseline)
        gs[g].draw(TransformPen(pen, m))
        gs[g].draw(TransformPen(bp, m))
        x += hmtx[g][0] * k + tracking_em * size
    return pen.getCommands(), x, bp.bounds


def horizontal(word_fill, auth_fill, a_fill, key_fill, label='Opsidious Auth'):
    F = 100.0
    sym = F * 1.54  # the symbol's square, as in the identity (40 px at 26 px)
    gap = F * 0.385
    semi, med = face(600), face(500)
    hhea = semi['hhea']
    upm = semi['head'].unitsPerEm
    # Line box of one font size, centred on the symbol's square.
    content = (hhea.ascent - hhea.descent) / upm * F
    baseline = sym / 2 - F / 2 + (F - content) / 2 + hhea.ascent / upm * F
    x0 = sym + gap
    p1, x1, b1 = run(semi, 'opsidious', F, x0, baseline, -0.025)
    p2, x2, b2 = run(med, 'auth', F, x1 + 0.3 * F - (-0.025 * F), baseline, -0.025)
    top = min(SYM_BOX[1] * sym / 120, b1[1], b2[1])
    bottom = max((SYM_BOX[1] + SYM_BOX[3]) * sym / 120, b1[3], b2[3])
    left = SYM_BOX[0] * sym / 120
    right = b2[2]
    w, h = right - left, bottom - top
    body = (
        symbol_paths(a_fill, key_fill, KEY, f'scale({sym / 120:.5f})')
        + f'<path d="{p1}" fill="{word_fill}"/><path d="{p2}" fill="{auth_fill}"/>'
    )
    return svg(f'{left:.2f} {top:.2f} {w:.2f} {h:.2f}', round(w), round(h), body, label)


def favicon():
    # Small sizes keep the larger keyhole, as the identity's favicon does.
    return tile(32, False, 'Opsidious Auth', key=KEY, ratio=0.72, border=False).replace(
        f'rx="{32 * 28 / 124:.2f}"', 'rx="7"'
    )


def write(rel, text):
    p = os.path.join(ROOT, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, 'w', encoding='utf-8', newline='\n') as f:
        f.write(text)
    print('wrote', rel)


if __name__ == '__main__':
    light = symbol(INK, VIOLET_ON_LIGHT)
    dark = symbol(MIST, VIOLET)
    logo_light = horizontal(INK, VIOLET_ON_LIGHT, INK, VIOLET_ON_LIGHT)
    logo_dark = horizontal(MIST, VIOLET, MIST, VIOLET)

    # The service's own pages are light.
    write('public/mark.svg', light)
    write('public/emblem.svg', light)
    write('public/emblem-mark.svg', dark)
    write('public/logo.svg', logo_light)
    write('public/favicon.svg', favicon())

    # The identity pack.
    write('logo/svg/opsidious-auth-symbole-noir.svg', light)
    write('logo/svg/opsidious-auth-symbole-blanc.svg', dark)
    write('logo/svg/opsidious-auth-horizontal-noir.svg', logo_light)
    write('logo/svg/opsidious-auth-horizontal-blanc.svg', logo_dark)
    write('logo/icones/app-icon.svg', tile(1024, False, 'Opsidious Auth'))
    write('logo/icones/avatar.svg', tile(1024, True, 'Opsidious Auth'))
    write('logo/icones/favicon.svg', favicon())
