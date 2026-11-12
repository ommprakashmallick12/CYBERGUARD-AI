# CyberGuard AI

Four scanners (Photo, Deepfake/AI-image, Phishing link, Emoji/hidden Unicode). Pure Python standard library - **no pip install needed**.

## Run on Windows
Double-click `run.bat` (uses installed Python, or downloads a portable copy once). Opens http://localhost:8000.
Linux/Mac: `python3 server.py`.

## Deploy on Render
Entry point is `server.py` (it is a built-in `http.server` app, so the start command is `python server.py` - not gunicorn). Build: `python -m py_compile server.py`, Health check: `/health`. See `DEPLOY-RENDER.md`. Render's `PORT` is used and the server binds to `0.0.0.0`.

Optional environment variables: `VIRUSTOTAL_API_KEY`, `GOOGLE_SAFE_BROWSING_API_KEY`, `URLHAUS_API_KEY` (phishing threat intel; shown as "unavailable" when not set), `CYBERGUARD_THREAT_INTEL=0` to disable external lookups, plus the existing `MAX_UPLOAD_MB`, `RATE_LIMIT_PER_MIN`, `MAX_CONCURRENT_SCANS`.

## What the scanners do
- **Photo**: real pixel-level steganography extraction. Supported: PNG (8-bit gray/RGB/RGBA, non-interlaced) and BMP (24/32-bit); channels RGB, RGBA, R, G, B, A; bit-planes 0-1; MSB/LSB-first; payloads = 32-bit length-prefixed UTF-8, null-terminated UTF-8, or plain UTF-8. Not supported (reported honestly): encrypted/password-seeded/random-order embedding, JPEG-domain methods. Output heading: `STEGANOGRAPHIC HIDDEN TEXT OUTPUT`. OCR is separate and only runs if Tesseract is installed (otherwise "OCR engine unavailable").
- **Deepfake**: metadata/provenance/pixel-statistics heuristics. No trained model is bundled: result states "Deepfake detection model unavailable." Face detection runs only if OpenCV is installed (optional). Video is not supported.
- **Phishing**: 8 local heuristic layers (kept separate) + external threat intelligence (URLhaus, VirusTotal, Google Safe Browsing when keys are set). SSRF guard unchanged.
- **Emoji**: original layers + exact input, per-character position / code point / UTF-8 hex / name / explanation, mixed-script flag.

## Tests
`python tests/test_scanners.py` (39 checks, standard library only).
