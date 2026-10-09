# Ricevanta brand assets

`BRAND_SPEC.md` defines the identity. `reference/approved-concept-board.png` holds the approved RECOMMENDED rice-ear mark; BRAND_SPEC.md §2 lists where the master departs from it (fuller, shorter rice grains).

## Source and build

- `source/ricevanta-symbol-master.svg`: the only editable symbol vector. Four filled paths (`arc`, `grain-1`, `grain-2`, `grain-3`), flat fills, viewBox `0 0 668 922` with a 10% safe area.
- `source/ricevanta-wordmark-master.svg`, `source/ricevanta-tagline-master.svg`: Be Vietnam Pro ExtraBold and Medium, outlined. License notice: `source/OFL-BeVietnamPro.txt`.
- `scripts/build.py`: generates every file under `dist/` from the masters and validates the output. Output is byte-identical across runs. Requires ImageMagick 7 with librsvg and Pillow. Run `python3 branding/scripts/build.py`; never edit `dist/` by hand.
- `scripts/outline_wordmark.py <font-dir>`: regenerates the type masters. Requires fonttools, uharfbuzz and the Be Vietnam Pro TTF files from https://github.com/bettergui/BeVietnamPro.

## Outputs

`build.py` writes every file below into `dist/`. Git tracks only the files in use, listed in `.gitignore`: `symbol-color.svg`, `symbol-dark.svg`, `horizontal-color.svg`, `horizontal-dark.svg`, `horizontal-with-tagline.svg`, `github-avatar-500.png`, `horizontal-with-tagline-1600w.png`, and the web icons and manifest in `dist/web/` except the 16 and 32 px favicon PNGs. Run the build for the rest.

| Path | Content |
|---|---|
| `dist/svg/symbol-color.svg` | Indigo arc, gold grains, for light backgrounds. |
| `dist/svg/symbol-dark.svg` | Ivory arc, gold grains, for dark backgrounds. |
| `dist/svg/symbol-micro.svg` | Grains scaled to 82% so gaps stay open at 16 to 24 px; also used by the favicons. |
| `dist/svg/symbol-mono-indigo.svg`, `symbol-mono-ivory.svg` | One-color symbol. |
| `dist/svg/horizontal-*.svg`, `stacked-*.svg` | Lockups: color, with tagline, dark, one-color. |
| `dist/svg/appicon-light.svg`, `appicon-dark.svg` | Rounded tiles, ivory and indigo: previews and Android `any` icons. |
| `dist/svg/appicon-light-square.svg`, `appicon-dark-square.svg` | Full-bleed tiles for platforms that apply their own mask (iOS, macOS). |
| `dist/svg/appicon-maskable.svg` | Square tile with art inside the PWA maskable safe zone. |
| `dist/svg/github-avatar.svg`, `dist/png/github-avatar-500.png` | GitHub organization avatar: square, opaque ivory, full color. |
| `dist/png/` | Transparent symbol PNGs 16 to 512 px, opaque full-bleed app icons 64 to 1024 px, lockup PNGs 1600 px wide. |
| `dist/preview/size-test.png` | Contact sheet at 16, 24, 32, 48 and 64 px, shown 1:1, for review. |
| `dist/web/` | `favicon.svg`, `favicon.ico` (16, 32, 48), Apple touch icon, Android and maskable PNGs, `site.webmanifest`. |

## Open items

- Trademark clearance: not done. Search Vietnam IP Office and WIPO records in Nice classes 9 and 42 before registering.
- Owner sign-off on the master before it replaces live assets.
