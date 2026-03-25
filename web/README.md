# SkezMod Web

Client-side self-service patcher for `MANAGPRE.EXE`.

## Local development

```bash
npm install
npm run dev
```

Optional counter API setup:

```bash
cp .env.example .env.local
```

Set `VITE_COUNTER_API_BASE` to your Cloudflare Worker URL.
For GitHub Pages deploys, define repo variable `VITE_COUNTER_API_BASE` so the workflow injects it at build time.

## Checks

```bash
npm run test
npm run build
```

## Behavior

- Runs entirely in browser (no backend upload required).
- Applies the stable Stars Patch flow from `skezmod.py`.
- Performs signature-based compatibility preflight before apply.
- Downloads `MANAGPRE.skezmod.exe` automatically on success.
- Provides optional JSON patch report download.
- Displays a global patch counter and increments it after successful patch apply.

## Branding Asset

- For the hero logo background, place your cover art at `web/public/keegan-cover.png`.

