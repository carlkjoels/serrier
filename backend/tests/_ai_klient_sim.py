"""Simulerad AI-klient för CLI-wrapper-integrationstest. Beter sig som en SDK: läser sin
base_url ur ANTHROPIC_BASE_URL (satt av `serrier run`) och postar SIM_BODY dit. trust_env=True
så NO_PROXY respekteras (loopback går direkt, ej via ambient proxy). Exit 0 vid 200, annars 3.
Körs som ett RIKTIGT barn-process i testet — ingen testimport."""

import os
import sys

import httpx

base = os.environ["ANTHROPIC_BASE_URL"]
body = os.environ["SIM_BODY"].encode()
try:
    r = httpx.post(base + "/v1/messages", content=body, trust_env=True, timeout=10)
    print(r.status_code)
    sys.exit(0 if r.status_code == 200 else 3)
except Exception as e:
    print(f"ERR {e}")
    sys.exit(4)
