# Ricevanta — Logo, Visual Identity & Asset Implementation Specification

> **Status:** Symbol master, Be Vietnam Pro wordmark, lockups and exports are built. Owner sign-off on the final vector is pending.
> **Owner:** Ricevanta project
> **Audience:** Codex, Claude Code, design engineers, frontend agents, maintainers.
> **Primary instruction:** **Implement the approved “RECOMMENDED” rice-ear logo with the refinement in §2. Do not propose or silently substitute a new logo.**

## 0. Agent mission (read first)

Recreate, refine, and deliver a production-quality, **emoji-first** visual identity for **Ricevanta**, an open-source, self-hosted unified endpoint security and management platform. Work from the **approved source board** in `reference/approved-concept-board.png` (the large **RECOMMENDED** hero mark). The vector master is `source/ricevanta-symbol-master.svg`, hand-fitted to the reference by overlay. Treat the raster moodboard as the primary *visual reference* and the master as the only editable vector source.

**Success:** The mark is instantly recognizable at emoji/app-icon sizes, elegant at web sizes, and functions as a distinctive sign for a growing suite of endpoint and data-security products. The design should read as a rice ear under protection rather than a flower, shield, padlock, wheat ear, generic leaf, or diagram.

**Deliver:** A vector source of truth, approved lockups and color variants, raster export sets, usage rules, reproducible build instructions, and automated checks. No need to build or rename any actual Ricevanta security product as part of this task.

## 1. Brand fundamentals

| Property | Decision |
|---|---|
| Name | **Ricevanta** (capital R, rest lowercase; never RiceVanta or Rice Vanta) |
| Official tagline | **Lightweight by Nature. Powerful by Design.** |
| Optional closing line | **One Agent. Unified Protection. Open to Everyone.** |
| Inspiration | Rice as an essential daily source of energy; natural Vietnamese/ASEAN roots; unified technology |
| Brand personality | Simple, quietly confident, approachable, efficient, trustworthy, enduring |
| Audience | Engineers, security professionals, organizations, open-source contributors |
| Design approach | **Emoji-first, vector-first, seamless, compact, organic with disciplined geometry** |
| Market | Global; origins in Vietnam visible through restrained colors and symbolism, not national flag imagery |

**Platform context:** Ricevanta combines MDM, EDR, DLP, data lineage, certificate/PKI management, network/RADIUS/VPN authentication, unified policies, logging to external SIEMs, and administration. A single lightweight Rust endpoint agent connects to a Go backend with a Vue console, supporting Windows/macOS/Linux, x64/ARM64. The symbol represents their shared foundation. **Do not map one grain permanently to one individual module**; modules can grow/change without needing a rebrand.

## 2. Exact visual direction — what is approved

The approved mark is a **rice ear held by a protective arc**, with:

1. **One indigo arc** on the left: a tall crescent, broad in the middle and tapering to a point at both ends. It reads as protection and as the stalk the grains grow from.
2. **Three gold rice grains** stacked on the right, rising toward the upper right. Each grain has a pointed outer tip, a full body and a short curved tail that points back toward the arc.
3. **Ivory negative space** between the arc and the grains and between the grains themselves.

### Refinements over the concept board

The master departs from the board in one place, to make the grains read as rice (lúa) rather than wheat or laurel leaves:

- **Rice-grain proportions.** Each grain is 8 to 12% wider than on the board and 6 to 9% shorter, with a shorter curled tail, so it reads as a plump rice grain (hạt thóc). The bottom grain's tail sits further from the arc than on the board so that gap stays open. The tips, angles and stacking follow the board.

The board shows a ™ symbol, a jade gradient inside the header wordmark, and taglines under ALT 1 and ALT 2. None of these are part of the identity. ALT 1 and ALT 2 show lockup layouts of the same mark.

### Silhouette constraints

- Upright, opening toward the upper right; taller than wide.
- **Asymmetric**: the arc carries the left side, the grains the right; no radial symmetry.
- The middle grain is the longest and the bottom grain the shortest; the three keep a parallel rhythm.
- Each form has tapered or softly pointed ends; **no sharp angular polygon joints**.
- Keep the gaps between arc and grains and between grains open from 32 px up with the master geometry, and at 16 to 24 px with `symbol-micro` (§6).
- **Never** redraw this as petals around a center, a hexagon, shield, V monogram, wreath, literal bowl of rice, or sheaf-of-rice emoji copy. Do not add grains, leaves or a visible stem.

### Reference priority

1. **Highest:** `reference/approved-concept-board.png`, hero **RECOMMENDED** area.
2. `source/ricevanta-symbol-master.svg` (vector master, flat fills).
3. `dist/svg/*` (variants generated by `scripts/build.py`).

The reference art is **AI-generated raster concept art**. Agents reconstruct and visually verify; do not claim exact pixel-for-pixel replication.

## 3. Colors and tokens

### Mandatory brand palette

| Token | Hex | Role |
|---|---|---|
| `--rv-indigo` | `#173B54` | Arc and wordmark; security, trust, technical seriousness |
| `--rv-harvest-gold` | `#DDB85C` | Rice grains; energy, harvest |
| `--rv-rice-ivory` | `#F6F2E7` | Warm background; arc and wordmark color on dark surfaces |

### Color use

- **Full color, light:** indigo arc and gold grains on ivory or white.
- **Full color, dark:** ivory arc and gold grains on indigo.
- **Monochrome:** every shape in indigo on light backgrounds, or in ivory on dark backgrounds.
- Flat fills only: no gradients, noise, blur, shadows, outlines or strokes.
- Gold on ivory has low contrast (about 1.7:1). It is acceptable for the logo, which is decorative, but never use gold for text or UI controls on light backgrounds.
- **Do not add red to the logo**. In the application UI, reserve red for critical security severity and alerts.

### Example design tokens

```css
:root {
  --rv-indigo: #173B54;
  --rv-harvest-gold: #DDB85C;
  --rv-rice-ivory: #F6F2E7;
}
```

The brand palette is **not** a complete WCAG semantic UI palette. Agents must define separate accessible foreground/background and status colors for application interfaces.

## 4. Source vector and geometry

- Source: `.svg` with a fixed, documented `viewBox`, editable paths, no embedded raster.
- The master uses `viewBox="0 0 668 922"` and **four named filled paths**: `arc`, `grain-1` (top), `grain-2`, `grain-3` (bottom).
- Proportions: a tall mark, approximately **0.69:1 bounding-box width-to-height** (master art 556 × 810); do not stretch to a circle or square.
- Safe area: at least **10% of the artwork's bounding-box width** around the standalone symbol; use more where needed for app-icon rounding.
- Preserve true transparent backgrounds in `symbol*.svg`; backgrounds belong in explicit app-icon / social-card assets only.
- Use **filled paths** as final source geometry rather than CSS strokes, path effects, external filters or embedded fonts.
- Preserve smooth tangents and avoid cusps at joining curves.

### Editing guide for the master geometry

| SVG path ID | Function | Priority |
|---|---|---|
| `arc` | Protective crescent on the left | Strong dark mass that anchors the mark |
| `grain-1` | Top rice grain | Sets the upward direction |
| `grain-2` | Middle rice grain, longest | Keeps the rhythm between top and bottom |
| `grain-3` | Bottom rice grain, shortest | Its tail stays at least 40 units from the arc |

**Agent constraint:** Each change must improve fidelity to the recommended reference, the rice reading, or legibility at small sizes. Record every intentional deviation from the board in "Refinements over the concept board" (§2) and preview it at 16, 32, 64 and 256 px. Change the master only through version control.

### SVG hygiene

- Standalone assets must not depend on externally referenced filters/images/fonts.
- Use IDs with `rv-` prefixes where multiple assets may be embedded in one HTML page; avoid duplicate global ID conflicts. Only the master carries path IDs; generated SVGs carry none.
- Provide `<title>` or appropriate ARIA labeling when a logo is the only accessible name; use `aria-hidden="true"` when adjacent text already names Ricevanta.
- Do not use text converted into image data or SVG `<image href="data:...">`.
- Use an SVG optimizer (e.g., SVGO) *after* checking that it preserves the paths, proportions, and palette.

## 5. Typography and lockups

**Wordmark:** `Ricevanta` set in **Be Vietnam Pro ExtraBold (800)** with -0.025 em tracking and HarfBuzz kerning, in indigo, to the **right** of the symbol. The tagline is set in **Be Vietnam Pro Medium (500)**.

- Be Vietnam Pro is designed by Lâm Bảo, licensed under SIL OFL 1.1 (https://github.com/bettergui/BeVietnamPro) and served by Google Fonts. It was drawn for Vietnamese diacritics, so the same family serves a Vietnamese console UI.
- The license notice is `source/OFL-BeVietnamPro.txt`. Font binaries are not committed.
- `scripts/outline_wordmark.py` converts the wordmark and tagline to paths in `source/ricevanta-wordmark-master.svg` and `source/ricevanta-tagline-master.svg`. Lockups use only these outlines, never live text.
- Preserve title case exactly. Exclude ™/® unless the owner explicitly requests it.
- Do not force the tagline into favicon or app icons; it is illegible there.

### Required lockups

| Variant | Arrangement | Use |
|---|---|---|
| `horizontal-color` | Mark left, wordmark right | Site header, GitHub/org headers, docs |
| `horizontal-with-tagline` | Mark left, wordmark with tagline below | Hero, announcement, README banner |
| `horizontal-dark` | Ivory mark and wordmark on indigo | Dark headers and slides |
| `stacked-color`, `stacked-dark` | Mark centered above wordmark | Social shares, talks and slides |
| `symbol-*` | Mark without type | App launcher, favicon, avatar |
| `horizontal-mono-indigo`, `horizontal-mono-ivory` | One color | Printing, badges, constrained media |

Lockup geometry, in wordmark cap heights (C): horizontal symbol art height 2.9 C, centred 0.4 C above the baseline, 0.3 C gap to the wordmark; tagline spans the wordmark width, 0.36 C below the baseline; stacked symbol art height 3.6 C, 0.5 C above the cap line; outer margin 0.35 C. `scripts/build.py` holds these values.

## 6. Emoji-first & app icon rules

The symbol must look good **before** the wordmark. This is a brand constraint, not a request to copy a Unicode emoji.

### Icon exports

| Size | Use | Treatment |
|---:|---|---|
| 16×16 | Browser favicon, tiny nav | Flatten colors; simplify if necessary; test distinct silhouette |
| 24×24 | Toolbar | Minimal detail; no hairlines |
| 32×32 | Favicon, menus | Full silhouette; all three grains separate |
| 48×48 | Desktop/taskbar | Flat full-color |
| 64×64 | Extension/launcher | Flat full-color |
| 128×128 | App icon / previews | Flat full-color |
| 192×192 | PWA icon | Background tile, padded |
| 256×256 | High-resolution app icon | Vector-derived |
| 512×512 | PWA / marketing | Vector-derived |
| 1024×1024 | Store / master icon | Vector-derived |

### App tile rules

- Square asset with **warm rice ivory** background for light icon, **deep indigo** background for dark icon.
- Use proportional central icon, generous margins. Recommended artwork occupies around **70–80% tile height** and **55–70% tile width**, with optical corrections.
- Tile corner radius may be 20–24% of tile width for design previews. For iOS/macOS icon upload pipelines, check platform requirements and avoid baking unwanted corner radius when the system masks the image itself.
- Provide both **opaque app-icon PNGs** and **transparent symbol PNGs**. Never mix those in naming.
- PNGs must be rendered **from SVG**, never resized successively from a small PNG.
- Add PWA `maskable` safe-zone variant as a separate deliverable; verify essential parts of mark lie inside maskable safe zone.
- Do not add words, multiple icons, decorative rings, shadows, or a background gradient in favicon assets.

### 16 px simplification decision

At 16 and 24 px the master's gaps (about 40 units) fall below one pixel and the grains merge. `scripts/build.py` therefore derives `symbol-micro.svg`: the arc is unchanged and each grain is scaled to 82% about its own centre, which opens every gap. `favicon.svg`, the favicon PNGs and ICO, and `symbol-transparent-16.png` and `-24.png` use the micro geometry; every other asset uses the master. Never edit the micro variant by hand.

## 7. Product-family design system

Ricevanta is a **single brand** with multiple product capabilities. Keep **one unchanged master logo** across products.

Examples of product labels:
- Ricevanta Endpoint
- Ricevanta Data
- Ricevanta Identity
- Ricevanta Network
- Ricevanta PKI
- Ricevanta Console

Use product-specific **secondary pictograms** (device, data flow, identity, network, key/certificate, settings). Do not alter grain positions or invent distinct Ricevanta logos per module. Secondary product icons may share the parent palette, stroke philosophy and rounded geometry; they should remain visually separate from the **brand logo**.

## 8. Mandatory deliverables and recommended layout

```text
branding/
  README.md
  BRAND_SPEC.md
  reference/
    approved-concept-board.png
  source/
    ricevanta-symbol-master.svg
    ricevanta-wordmark-master.svg
    ricevanta-tagline-master.svg
    OFL-BeVietnamPro.txt
  dist/
    svg/
      symbol-{color,dark,mono-indigo,mono-ivory,micro}.svg
      horizontal-{color,with-tagline,dark,mono-indigo,mono-ivory}.svg
      stacked-{color,dark}.svg
      appicon-{light,dark}.svg            rounded tiles
      appicon-{light,dark}-square.svg     full-bleed tiles for system-masked platforms
      appicon-maskable.svg
      favicon.svg
      github-avatar.svg
    png/
      symbol-transparent-{16,24,32,48,64,128,256,512}.png
      appicon-{light,dark}-{64,128,180,192,256,512,1024}.png
      github-avatar-{500,1024}.png
      {horizontal-color,horizontal-with-tagline,stacked-color}-1600w.png
    preview/
      size-test.png
    web/
      favicon.svg, favicon.ico, favicon-{16x16,32x32}.png
      apple-touch-icon.png
      android-chrome-{192x192,512x512}.png
      maskable-{192x192,512x512}.png
      site.webmanifest
  scripts/
    build.py
    outline_wordmark.py
```

`scripts/build.py` generates and validates everything under `dist/`. A 16 px micro variant does not exist; see §12.

## 9. Web integration

- Use `favicon.svg` for supporting browsers, `favicon.ico` as fallback.
- Include 180×180 Apple touch PNG and a PWA manifest with 192/512 standard and maskable images.
- In the Vue console, centralize brand assets in a consistent `src/assets/brand` or `public/brand` folder; do not duplicate rasterized logos in individual components.
- Provide a reusable `RicevantaLogo` component with controlled variants: `symbol`, `horizontal`, `withTagline`; `theme` = `light` | `dark` | `mono`; a predictable accessible label. Do not inline many divergent path copies.
- Set correct SVG intrinsic size/viewBox to avoid layout shifts.
- For UI, let a separate theme system handle light/dark color tokens; the logo's palette does not replace accessible severity/action colors.

Example HTML integration:

```html
<link rel="icon" href="/brand/favicon.svg" type="image/svg+xml" />
<link rel="alternate icon" href="/brand/favicon.ico" />
<link rel="apple-touch-icon" href="/brand/apple-touch-icon.png" />
<link rel="manifest" href="/brand/site.webmanifest" />
```

## 10. Review and acceptance criteria

An agent's work is **not accepted** unless:

1. **Fidelity**: side-by-side check against the selected RECOMMENDED hero mark; no drift into alternative logos.
2. **Small sizes**: recognizable at 16, 24, 32, 64 px on actual light/dark UI backgrounds; no merged negative-space channels or disappearing core silhouette.
3. **Silhouette**: clearly a rice ear held by a protective arc, not a wheat ear, flower, shield, spinner, or disconnected set of abstract petals.
4. **Color**: exact approved core hex values; no extra colors, red or gradients.
5. **Monochrome**: one-color versions remain clear without relying on color coding.
6. **Dark mode**: dark-background app icon works without low-contrast details.
7. **Technical quality**: standalone optimized SVG; no raster embedding; no unwanted external requests; reproducible exports with alpha handled correctly.
8. **Accessibility**: sensible names/alt text, adequate contrast for surrounding UI, do not rely on logo alone to communicate security state.
9. **Assets**: PNG set, favicon, PWA assets and manifest exported from one master source and correctly sized.
10. **Consistency**: README, documentation, web console, GitHub avatar and social cards all use same mark.
11. **Typography**: wordmark verified by visual review; font redistribution compliant; final outlined master available.
12. **Change control**: deviations logged; comparisons documented; owner signs off on final vector before replacing all existing assets.

### Automated tests (minimum)

- SVG parse passes; expected path IDs exist; SVG `viewBox` is valid; no external URL references.
- Production icons and favicons render successfully at every requested size.
- PNG sizes and alpha/opaque conventions match the file name's contract.
- Pixel-data bounding box sits within intended safe area and is neither cropped nor excessively small.
- Size-test contact sheet is generated automatically for human review.
- Visual regression compares the committed vector exports against prior **approved vector baseline** (once one exists), not directly against generative moodboard pixels.
- If a test flags visual failures, fix the source SVG and regenerate *all* derivatives, instead of hand-editing exported PNGs.

## 11. Implementation plan for coding/design agents

### Phase A — Audit

1. Inspect `reference/approved-concept-board.png` and `source/ricevanta-symbol-master.svg`.
2. Confirm that the reference is the large RECOMMENDED rice ear, not a lockup variant.
3. Identify differences between the master and the concept art (arc taper, grain tips and tails, gaps, grain size, proportions) beyond the refinements listed in §2.
4. Record those differences before modifying paths.

### Phase B — Production master

5. Refine SVG Béziers by hand in vector editor or code; avoid automated bitmap tracing as sole method.
6. Normalize a clean viewBox and consistent negative space.
7. Create full-color light, full-color dark, monochrome and inverted sources.
8. Build wordmark using vetted open-source font and tune spacing/optical alignment.
9. Produce horizontal, tagline and stacked lockups.

### Phase C — App & web exports

10. Make light/dark square app icons, PWA maskable and micro variant only if needed.
11. Write a deterministic export script (version-controlled) that creates all PNGs, favicon and manifest.
12. Build size-test and context previews: 16px favicon, 32px sidebar, GitHub avatar, README header, UI header, desktop dock/taskbar.

### Phase D — Integration and QA

13. Add reusable Vue component and CSS tokens without inlining different shapes per usage.
14. Run automated SVG/PNG validation and visual checks.
15. Show owner a side-by-side reference vs refined vector + 16px and 32px icon tests, **then ask for approval**.
16. Only after sign-off, roll out replacement assets in website, docs, console, repositories and social image templates.

### Agent instruction block (paste directly into a coding-agent task)

> Implement the Ricevanta logo and branding defined in `BRAND_SPEC.md`. Use `reference/approved-concept-board.png` and its large **RECOMMENDED** rice-ear logo as the approved visual source, with `source/ricevanta-symbol-master.svg` as the editable vector master. Do not redesign the logo into a flower, shield or symmetrical arrangement. Produce a cleaned, production-ready vector master; verified color/mono/light/dark lockups; reproducible favicon/PWA/app exports; a reusable Vue logo component; a validation script; and visual previews at 16, 32, 64 and 256 px. Preserve the exact brand name, tagline and palette. Before replacing existing live assets, present a comparison showing fidelity, scale tests and documented deviations, and request owner approval.

## 12. Non-goals and unresolved decisions

- **Not a trademark clearance** or confirmation of domain / GitHub handle availability.
- **Not an approved final production SVG** until the owner signs off on the master and its §2 refinements.
- No font binaries are included; the outlined wordmark and tagline are the production type.
- Actual product module pictograms are future work; the main symbol should not be altered to encode a fixed number of modules.
- This spec does not dictate the entire application UI; it governs visual identity and implementation of brand assets.

---

**North star:** *Looks good as a tiny emoji first, then scales effortlessly into an enterprise-grade security identity.*
