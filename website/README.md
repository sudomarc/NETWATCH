# NETWATCH NG showcase site

Static product site for NETWATCH NG, rebuilt from the presentation experience observed on a developer product reference page (www.claude.com/product/claude-code) analyzed by reverse engineering with [REA](https://github.com/morluto/rea/) (`inspect-web-page`, `capture-web-screenshot`, `analyze-web-bundle`), then adapted to a proper identity: network operations console, signal green accent, editorial serif + monospace typography.

## Overview

```bash
cd website
python3 -m http.server 8765
# http://127.0.0.1:8765
```

## Structure

| File | Role |
|---|---|
| `index.html` | Single page: hero + animated TUI, installation, changelog, tabbed demonstration, terminal adaptation, security principles, FAQ, resources, CTA, footer |
| `css/style.css` | Design system (tokens, buttons, cards, terminal, 3 responsive breakpoints) |
| `js/main.js` | Navigation, scroll reveals (IntersectionObserver), TUI typer, tabs, command copy, FAQ |

## Verified content

All texts come from the actual repository: `README.md`, `CHANGELOG.md`, `docs/NETWATCH_DESIGN_SYSTEM.md`, `docs/apt-repository.md`, `netwatch_ng/tui/app.py`, and the verified state of the published APT repository (`dists/stable/Release`, `Packages`, `InRelease`, `Release.gpg`, `netwatch-ng_2.0.0-1_all.deb`). No invented features; unimplemented capabilities are explicitly described as such (no HTB, no SNMP/firmware fingerprinting).

## Accessibility and performance

- Semantic HTML (`nav`, `main`, `section`, `details/summary`), breadcrumb, skip link, `aria-*` on tabs and mobile menu.
- Contrast validated on dark background and dark terminal.
- `prefers-reduced-motion` respected: animations are disabled.
- No external dependency: vanilla HTML/CSS/JS, no network request, no third-party font (system serif + `system-ui`).
