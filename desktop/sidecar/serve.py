"""PyInstaller-entry för backend-sidecaren. Kör Serrier-API:t på en fast loopback-port
(default 8788) — Tauri startar/dödar den. Byggs till en binär av serrier-backend.spec
(se desktop/README). Loopback-only; samma app som `uvicorn serrier.api.app:app`."""

import os

import uvicorn

from serrier.api.app import app

if __name__ == "__main__":
    port = int(os.environ.get("SERRIER_PORT", "8788"))
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
