"""Build every Ricevanta brand asset from the masters in source/.

source/ricevanta-symbol-master.svg holds the symbol; source/ricevanta-wordmark-master.svg and
source/ricevanta-tagline-master.svg hold Be Vietnam Pro outlines made by outline_wordmark.py.

Run from anywhere: python3 branding/scripts/build.py
Requires ImageMagick 7 with the librsvg delegate (`magick`) and Pillow.
Never edit files under dist/ by hand; change the master and rerun.
"""
import json, re, subprocess, sys, xml.etree.ElementTree as ET
from pathlib import Path
from PIL import Image

if sys.flags.optimize:
    sys.exit('run without -O: the validation uses assert')

ROOT = Path(__file__).resolve().parents[1]
MASTER = ROOT / 'source/ricevanta-symbol-master.svg'
SVG, PNG, WEB, PREVIEW = (ROOT / 'dist' / d for d in ('svg', 'png', 'web', 'preview'))
IND, GOLD, IVORY = '#173B54', '#DDB85C', '#F6F2E7'
ORDER = ['arc', 'grain-1', 'grain-2', 'grain-3']

root = ET.parse(MASTER).getroot()
VW, VH = (float(v) for v in root.attrib['viewBox'].split()[2:])
D = {el.attrib['id']: el.attrib['d'] for el in root.iter() if el.tag.endswith('path')}
assert list(D) == ORDER, f'master path IDs must be {ORDER}, got {list(D)}'


def text_master(name):
    r = ET.parse(ROOT / 'source' / name).getroot()
    x, y, w, h = (float(v) for v in r.attrib['viewBox'].split())
    d = next(el.attrib['d'] for el in r.iter() if el.tag.endswith('path'))
    return d, x, y, w, h, float(r.attrib.get('data-cap-height', h))


WORD = text_master('ricevanta-wordmark-master.svg')
TAG = text_master('ricevanta-tagline-master.svg')

MICRO_SCALE = 0.82  # symbol-micro: each grain shrunk about its own centre so the gaps stay open at 16-24 px


def scaled(d, k):
    """Scale an absolute M/C/Z path about the centre of its points' bounding box."""
    tokens = re.findall(r'[MCZ]|-?\d+\.?\d*', d)
    v = [float(t) for t in tokens if t not in 'MCZ']
    cx = (min(v[0::2]) + max(v[0::2])) / 2
    cy = (min(v[1::2]) + max(v[1::2])) / 2
    out, i = [], 0
    for t in tokens:
        if t in 'MCZ':
            out.append(t)
            continue
        c = cx if i % 2 == 0 else cy
        out.append(f'{c + (float(t) - c) * k:.1f}')
        i += 1
    return ' '.join(out)


D_MICRO = {k: (D[k] if k == 'arc' else scaled(D[k], MICRO_SCALE)) for k in ORDER}
COLOR = dict(zip(ORDER, [IND, GOLD, GOLD, GOLD]))   # light backgrounds
DARK = dict(zip(ORDER, [IVORY, GOLD, GOLD, GOLD]))   # dark backgrounds
mono = lambda c: dict.fromkeys(ORDER, c)
HEAD = 'role="img" aria-label="Ricevanta"><title>Ricevanta</title>\n'
HEAD_TAG = ('role="img" aria-label="Ricevanta: Lightweight by Nature. Powerful by Design.">'
            '<title>Ricevanta: Lightweight by Nature. Powerful by Design.</title>\n')
PNG_OPTS = ['-define', 'png:exclude-chunk=date,time']  # keep PNG bytes reproducible


def write(name, text):
    (SVG / name).write_text(text, encoding='utf-8', newline='\n')


def paths(fills, ind='  ', geom=None):
    # Output paths carry no IDs: unprefixed IDs would collide when several SVGs are inlined in one page.
    geom = geom or D
    return '\n'.join(f'{ind}<path fill="{fills[k]}" d="{geom[k]}"/>' for k in ORDER) + '\n'


def symbol(name, fills, geom=None):
    write(name, f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {VW:g} {VH:g}" {HEAD}' + paths(fills, geom=geom) + '</svg>\n')


def tile(name, bg, fills, art_h, radius, geom=None):
    """Square tile; art_h is the symbol viewBox height as a share of the tile (viewBox keeps a 10% pad)."""
    s = 1024; k = s * art_h / VH; tx = (s - VW * k) / 2; ty = (s - VH * k) / 2
    rx = f' rx="{round(s * radius)}"' if radius else ''
    write(name, f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {s} {s}" {HEAD}'
                + f'<rect width="{s}" height="{s}"{rx} fill="{bg}"/>\n'
                + f'<g transform="translate({tx:.2f} {ty:.2f}) scale({k:.5f})">\n' + paths(fills, '    ', geom) + '</g>\n</svg>\n')


def art_box():
    """Symbol art box inside the master viewBox: the viewBox keeps a 10%-of-width pad on every side."""
    pad = VW / 12  # art width w, pad 0.1w on each side: VW = 1.2w
    return pad, pad, VW - 2 * pad, VH - 2 * pad


def lockup(name, fills, text_fill, layout, tagline=False, bg=None):
    """Compose symbol and outlined type in wordmark font units (cap height C)."""
    wd, wx, wy, ww, wh, C = WORD
    ax, ay, aw, ah = art_box()
    parts = []
    if layout == 'horizontal':
        k = 2.9 * C / ah                       # symbol art height = 2.9 x cap height
        sx, sy = 0, -0.4 * C - ah * k / 2      # art centred just below the cap-height middle
        tx = aw * k + 0.3 * C - wx             # gap 0.3 C between art and type
        parts.append((sx - ax * k, sy - ay * k, k))
        text = [(tx, 0, 1, wd)]
        x1 = tx + wx + ww; y0 = min(sy, wy); y1 = max(sy + ah * k, wy + wh)
        if tagline:
            td, tgx, tgy, tgw, tgh, _ = TAG
            t = ww / tgw                       # tagline spans the wordmark width
            ty = 0.36 * C - tgy * t
            text.append((tx + wx - tgx * t, ty, t, td))
            y1 = max(y1, ty + (tgy + tgh) * t)
        x0 = 0
    else:                                      # stacked
        k = 3.6 * C / ah
        x0, x1 = wx, wx + ww
        sx = wx + ww / 2 - aw * k / 2; sy = -C - 0.5 * C - ah * k
        parts.append((sx - ax * k, sy - ay * k, k))
        text = [(0, 0, 1, wd)]
        x0 = min(x0, sx); x1 = max(x1, sx + aw * k); y0 = sy; y1 = wy + wh
    m = 0.35 * C                               # outer margin
    vb = (x0 - m, y0 - m, x1 - x0 + 2 * m, y1 - y0 + 2 * m)
    body = ''.join(f'<g transform="translate({px:.1f} {py:.1f}) scale({pk:.5f})">\n' + paths(fills, '    ') + '</g>\n' for px, py, pk in parts)
    body += ''.join(f'<path fill="{text_fill}" transform="translate({tx:.1f} {ty:.1f}) scale({tk:.5f})" d="{d}"/>\n' for tx, ty, tk, d in text)
    rect = f'<rect x="{vb[0]:.1f}" y="{vb[1]:.1f}" width="{vb[2]:.1f}" height="{vb[3]:.1f}" fill="{bg}"/>\n' if bg else ''
    write(name, f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{" ".join(f"{v:.1f}" for v in vb)}" {HEAD_TAG if tagline else HEAD}'
                + rect + body + '</svg>\n')


def render(svg, px, out, bg=None):
    cmd = ['magick', '-background', 'none', '-density', '600', str(svg), '-resize', f'{px}x{px}',
           '-gravity', 'center', '-extent', f'{px}x{px}']
    cmd += ['-background', bg, '-flatten', '-alpha', 'off'] if bg else []
    subprocess.run(cmd + PNG_OPTS + [f'PNG32:{out}' if not bg else f'PNG24:{out}'], check=True)


def main():
    for d in (SVG, PNG, WEB):
        d.mkdir(parents=True, exist_ok=True)
    symbol('symbol-color.svg', COLOR)
    symbol('symbol-dark.svg', DARK)
    symbol('symbol-mono-indigo.svg', mono(IND))
    symbol('symbol-mono-ivory.svg', mono(IVORY))
    symbol('symbol-micro.svg', COLOR, D_MICRO)                  # 16-24 px only
    tile('appicon-light.svg', IVORY, COLOR, 0.86, 0.22)         # rounded: previews, docs, Android "any"
    tile('appicon-dark.svg', IND, DARK, 0.86, 0.22)
    tile('appicon-light-square.svg', IVORY, COLOR, 0.86, 0)     # full-bleed: platforms that apply their own mask
    tile('appicon-dark-square.svg', IND, DARK, 0.86, 0)
    tile('appicon-maskable.svg', IVORY, COLOR, 0.72, 0)         # art stays inside the 80% maskable safe zone
    tile('favicon.svg', IVORY, COLOR, 0.96, 0.22, D_MICRO)      # favicons render at 16-48 px
    lockup('horizontal-color.svg', COLOR, IND, 'horizontal')
    lockup('horizontal-with-tagline.svg', COLOR, IND, 'horizontal', tagline=True)
    lockup('horizontal-with-tagline-on-dark.svg', DARK, IVORY, 'horizontal', tagline=True)  # transparent, for dark pages
    lockup('horizontal-dark.svg', DARK, IVORY, 'horizontal', bg=IND)
    lockup('horizontal-mono-indigo.svg', mono(IND), IND, 'horizontal')
    lockup('horizontal-mono-ivory.svg', mono(IVORY), IVORY, 'horizontal')
    lockup('stacked-color.svg', COLOR, IND, 'stacked')
    lockup('stacked-dark.svg', DARK, IVORY, 'stacked', bg=IND)
    tile('github-avatar.svg', IVORY, COLOR, 0.84, 0)            # square; GitHub applies its own mask

    for px in (16, 24, 32, 48, 64, 128, 256, 512):
        render(SVG / ('symbol-micro.svg' if px <= 24 else 'symbol-color.svg'), px, PNG / f'symbol-transparent-{px}.png')
    for mode, bg in (('light', IVORY), ('dark', IND)):
        for px in (64, 128, 180, 192, 256, 512, 1024):
            render(SVG / f'appicon-{mode}-square.svg', px, PNG / f'appicon-{mode}-{px}.png', bg=bg)
    for px in (500, 1024):
        render(SVG / 'github-avatar.svg', px, PNG / f'github-avatar-{px}.png', bg=IVORY)

    for name in ('horizontal-color', 'horizontal-with-tagline', 'stacked-color'):
        subprocess.run(['magick', '-background', 'none', '-density', '96', str(SVG / f'{name}.svg'), '-resize', '1600x',
                        *PNG_OPTS, f'PNG32:{PNG / f"{name}-1600w.png"}'], check=True)
    # GitHub social preview: 1280 x 640, opaque, under 1 MB; lockup 1040 px wide keeps margins for cropping platforms.
    subprocess.run(['magick', '-size', '1280x640', f'xc:{IVORY}', '(', '-background', 'none', '-density', '300',
                    str(SVG / 'horizontal-with-tagline.svg'), '-resize', '1040x', ')', '-gravity', 'center', '-composite',
                    '-alpha', 'off', *PNG_OPTS, f'PNG24:{PNG / "social-preview-1280x640.png"}'], check=True)
    render(SVG / 'favicon.svg', 16, WEB / 'favicon-16x16.png')
    render(SVG / 'favicon.svg', 32, WEB / 'favicon-32x32.png')
    render(SVG / 'appicon-light-square.svg', 180, WEB / 'apple-touch-icon.png', bg=IVORY)
    for px in (192, 512):
        render(SVG / 'appicon-light.svg', px, WEB / f'android-chrome-{px}x{px}.png')
        render(SVG / 'appicon-maskable.svg', px, WEB / f'maskable-{px}x{px}.png', bg=IVORY)
    (WEB / 'favicon.svg').write_text((SVG / 'favicon.svg').read_text(encoding='utf-8'), encoding='utf-8', newline='\n')
    render(SVG / 'favicon.svg', 48, WEB / '_48.png')
    # Each ICO frame is rendered from the SVG at its own size, never downscaled from a larger raster.
    subprocess.run(['magick', str(WEB / 'favicon-16x16.png'), str(WEB / 'favicon-32x32.png'), str(WEB / '_48.png'),
                    str(WEB / 'favicon.ico')], check=True)
    (WEB / '_48.png').unlink()
    icons = [{'src': f'/brand/android-chrome-{p}x{p}.png', 'sizes': f'{p}x{p}', 'type': 'image/png', 'purpose': 'any'} for p in (192, 512)]
    icons += [{'src': f'/brand/maskable-{p}x{p}.png', 'sizes': f'{p}x{p}', 'type': 'image/png', 'purpose': 'maskable'} for p in (192, 512)]
    (WEB / 'site.webmanifest').write_text(json.dumps({
        'name': 'Ricevanta', 'short_name': 'Ricevanta', 'description': 'Open-source endpoint security and management',
        'start_url': '/', 'display': 'standalone', 'background_color': IVORY, 'theme_color': IND, 'icons': icons}, indent=2) + '\n', encoding='utf-8', newline='\n')
    size_test()
    validate()


def size_test():
    """Contact sheet for human review at 16 to 64 px, each shown 1:1. Rows: favicon, dark tile, symbol on white
    (micro geometry up to 24 px), dark symbol on indigo."""
    PREVIEW.mkdir(parents=True, exist_ok=True)
    rows = []
    for svg, bg in (('favicon.svg', '#FFFFFF'), ('appicon-dark.svg', '#FFFFFF'), ('symbol-color.svg', '#FFFFFF'), ('symbol-dark.svg', IND)):
        cells = []
        for px in (16, 24, 32, 48, 64):
            out = PREVIEW / f'_{Path(svg).stem}-{px}.png'
            src = 'symbol-micro.svg' if svg == 'symbol-color.svg' and px <= 24 else svg
            render(SVG / src, px, out)
            cells.append(str(out))
        row = PREVIEW / f'_{Path(svg).stem}.png'
        subprocess.run(['magick', '-background', bg, *sum([[c, '-gravity', 'center', '-extent', '96x96'] for c in cells], []),
                        '+append', str(row)], check=True)
        rows.append(str(row))
    subprocess.run(['magick', *rows, '-append', *PNG_OPTS, str(PREVIEW / 'size-test.png')], check=True)
    for f in PREVIEW.glob('_*.png'):
        f.unlink()


EXPECTED = {
    'svg': {f'{n}.svg' for n in ('symbol-color', 'symbol-dark', 'symbol-mono-indigo', 'symbol-mono-ivory', 'symbol-micro',
                                 'appicon-light', 'appicon-dark', 'appicon-light-square', 'appicon-dark-square',
                                 'appicon-maskable', 'favicon', 'github-avatar', 'horizontal-color', 'horizontal-with-tagline',
                                 'horizontal-with-tagline-on-dark', 'horizontal-dark', 'horizontal-mono-indigo', 'horizontal-mono-ivory', 'stacked-color', 'stacked-dark')},
    'png': {f'symbol-transparent-{p}.png' for p in (16, 24, 32, 48, 64, 128, 256, 512)}
           | {f'appicon-{m}-{p}.png' for m in ('light', 'dark') for p in (64, 128, 180, 192, 256, 512, 1024)}
           | {'github-avatar-500.png', 'github-avatar-1024.png'}
           | {f'{n}-1600w.png' for n in ('horizontal-color', 'horizontal-with-tagline', 'stacked-color')}
           | {'social-preview-1280x640.png'},
    'web': {'favicon.svg', 'favicon.ico', 'favicon-16x16.png', 'favicon-32x32.png', 'apple-touch-icon.png',
            'android-chrome-192x192.png', 'android-chrome-512x512.png', 'maskable-192x192.png', 'maskable-512x512.png',
            'site.webmanifest'},
    'preview': {'size-test.png'},
}


def validate():
    for d, names in EXPECTED.items():
        found = {f.name for f in (ROOT / 'dist' / d).iterdir()}
        assert found == names, f'dist/{d}: unexpected {sorted(found - names)}, missing {sorted(names - found)}'
    for f in [*SVG.glob('*.svg'), WEB / 'favicon.svg']:
        text = f.read_text(); r = ET.fromstring(text)
        assert '<image' not in text and '<script' not in text and not re.search(r'https?://(?!www\.w3\.org/2000/svg)', text), f
        assert len(r.attrib.get('viewBox', '').split()) == 4 and r.attrib.get('aria-label'), f'{f.name}: viewBox and label'
        ids = [el.attrib['id'] for el in r.iter() if 'id' in el.attrib]
        assert not ids, f'{f.name}: generated SVGs carry no IDs, found {ids}'
    for f in PNG.glob('*.png'):
        if f.name.startswith('social-preview-'):
            with Image.open(f) as im:
                assert im.size == (1280, 640) and im.mode == 'RGB', f'{f.name}: {im.size} {im.mode}'
            assert f.stat().st_size < 1_000_000, 'GitHub social preview must be under 1 MB'
            continue
        if f.name.endswith('w.png'):  # lockups: fixed width, natural height
            with Image.open(f) as im:
                assert im.size[0] == 1600 and im.mode == 'RGBA', f
            continue
        px = int(re.search(r'-(\d+)\.png$', f.name).group(1))
        with Image.open(f) as im:
            assert im.size == (px, px), f
            if f.name.startswith('symbol-'):
                assert im.mode == 'RGBA', f'{f.name} must have alpha'
                corners = [im.getpixel(c)[3] for c in ((0, 0), (px - 1, 0), (0, px - 1), (px - 1, px - 1))]
                assert max(corners) == 0, f'{f.name} background must be transparent'
                l, t, r, b = im.getchannel('A').getbbox()
                lo, hi = px * 0.05 - 1, px * 0.95 + 1  # viewBox pad is ~6.1% of height; allow 1 px antialiasing
                assert (b - t) >= px * 0.7 and l >= lo and t >= lo and r <= hi and b <= hi, f'{f.name} art outside safe area {l, t, r, b}'
            else:  # appicon-* and github-avatar-*
                assert im.mode == 'RGB', f'{f.name} must be opaque'
    for name, px, mode in (('favicon-16x16.png', 16, 'RGBA'), ('favicon-32x32.png', 32, 'RGBA'), ('apple-touch-icon.png', 180, 'RGB'),
                           ('android-chrome-192x192.png', 192, 'RGBA'), ('android-chrome-512x512.png', 512, 'RGBA'),
                           ('maskable-192x192.png', 192, 'RGB'), ('maskable-512x512.png', 512, 'RGB')):
        with Image.open(WEB / name) as im:
            assert im.size == (px, px) and im.mode == mode, f'{name}: {im.size} {im.mode}'
    with Image.open(WEB / 'favicon.ico') as im:
        assert {(16, 16), (32, 32), (48, 48)} <= set(im.info['sizes']), 'favicon.ico frames'
    manifest = json.loads((WEB / 'site.webmanifest').read_text())
    for icon in manifest['icons']:
        f = WEB / icon['src'].removeprefix('/brand/')
        with Image.open(f) as im:
            assert f'{im.size[0]}x{im.size[1]}' == icon['sizes'], f'manifest size mismatch: {f.name}'
    assert (PREVIEW / 'size-test.png').is_file(), 'size-test contact sheet missing'
    assert (PNG / 'github-avatar-500.png').stat().st_size < 1_000_000, 'GitHub avatar must be under 1 MB'
    print('PASS: exact dist file set; SVG hygiene, viewBox, labels and IDs; PNG sizes, alpha and opacity; symbol safe area; '
          'web icons, ICO frames and manifest; avatar and social preview size; size-test sheet present')


if __name__ == '__main__':
    main()
