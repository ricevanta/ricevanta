"""Outline the Ricevanta wordmark and tagline from Be Vietnam Pro into source/*.svg.

Run once when the type changes: python3 branding/scripts/outline_wordmark.py <font-dir>
<font-dir> holds BeVietnamPro-ExtraBold.ttf and BeVietnamPro-Medium.ttf from
https://github.com/bettergui/BeVietnamPro (SIL OFL 1.1, see source/OFL-BeVietnamPro.txt).
Requires fonttools and uharfbuzz. Font binaries are not committed; the outlined SVGs are.
"""
import sys
from pathlib import Path
import uharfbuzz as hb
from fontTools.ttLib import TTFont
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.pens.boundsPen import BoundsPen

ROOT = Path(__file__).resolve().parents[1]
if len(sys.argv) != 2:
    sys.exit(__doc__)
FONTS = Path(sys.argv[1])


def outline(font_file, text, tracking_em, out, label):
    """Shape with HarfBuzz (kerning on), apply tracking in em, write one filled path, y-down, baseline at 0."""
    blob = hb.Blob.from_file_path(str(font_file))
    face = hb.Face(blob); font = hb.Font(face)
    buf = hb.Buffer(); buf.add_str(text); buf.guess_segment_properties()
    hb.shape(font, buf, {'kern': True, 'liga': True})
    tt = TTFont(font_file); gs = tt.getGlyphSet(); order = tt.getGlyphOrder()
    upm = tt['head'].unitsPerEm; track = tracking_em * upm
    pen = SVGPathPen(gs, ntos=lambda v: f'{v:.1f}'.rstrip('0').rstrip('.'))
    bounds = BoundsPen(gs)
    x = 0
    for info, pos in zip(buf.glyph_infos, buf.glyph_positions):
        name = order[info.codepoint]
        t = (1, 0, 0, -1, x + pos.x_offset, -pos.y_offset)  # flip y so the SVG is y-down
        gs[name].draw(TransformPen(pen, t)); gs[name].draw(TransformPen(bounds, t))
        x += pos.x_advance + track
    x0, y0, x1, y1 = bounds.bounds
    out.write_text(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{x0:.0f} {y0:.0f} {x1 - x0:.0f} {y1 - y0:.0f}" '
                   f'data-font="Be Vietnam Pro" data-cap-height="{tt["OS/2"].sCapHeight}" role="img" aria-label="{label}">'
                   f'<title>{label}</title>\n  <path id="text" fill="#173B54" d="{pen.getCommands()}"/>\n</svg>\n', encoding='utf-8', newline='\n')


outline(FONTS / 'BeVietnamPro-ExtraBold.ttf', 'Ricevanta', -0.025, ROOT / 'source/ricevanta-wordmark-master.svg', 'Ricevanta')
outline(FONTS / 'BeVietnamPro-Medium.ttf', 'Lightweight by Nature. Powerful by Design.', 0.0,
        ROOT / 'source/ricevanta-tagline-master.svg', 'Lightweight by Nature. Powerful by Design.')
print('wrote wordmark and tagline masters')
