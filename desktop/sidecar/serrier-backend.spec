# -*- mode: python ; coding: utf-8 -*-
# PyInstaller-spec: bundlar sidecar/serve.py + hela serrier-paketet till EN self-contained
# binär (`serrier-backend`) som Tauri kör. Kör FRÅN backend/:
#   uv run pyinstaller ../desktop/sidecar/serrier-backend.spec --distpath ../desktop/src-tauri/binaries
# Döp sedan om till serrier-backend-<target-triple> (se desktop/README).
#
# NOTE (TODO, se desktop/README): scanner-binärerna (gitleaks/semgrep/osv) bundlas INTE här.
# Utan dem degraderar backenden till den inbyggda hemlighets-skannern (graceful degradation).

from PyInstaller.utils.hooks import collect_submodules, collect_data_files

hidden = (
    collect_submodules("serrier")
    + collect_submodules("uvicorn")
    + ["anthropic", "fastapi", "pydantic", "sqlalchemy", "starlette", "httpx"]
)
datas = collect_data_files("serrier")   # t.ex. semgrep_rules/*.yaml

a = Analysis(
    ["../desktop/sidecar/serve.py"],
    pathex=["."],
    binaries=[],
    datas=datas,
    hiddenimports=hidden,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="serrier-backend",
    debug=False,
    strip=False,
    upx=False,
    console=True,            # sidecar har ingen egen GUI; Tauri äger fönstret
    disable_windowed_traceback=False,
)
