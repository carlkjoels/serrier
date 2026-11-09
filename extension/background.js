// Serrier Pre-Send Guardian — background service worker (0005 steg 2, scaffold).
//
// Enda uppgift: ta emot text från content-scriptet, fråga den LOKALA daemonen
// (POST http://127.0.0.1:PORT/inspect med token) och lämna tillbaka verdiktet.
// Detektionen lever i daemonen (samma beslutskärna som proxyn) — vi kör ingen
// egen detektion i browsern.
//
// Säkerhet (0005 §4): ENDA utgående anrop går till loopback. Ingen phone-home,
// ingen analytics, ingen fjärr-config. Rå text skickas bara till 127.0.0.1 och
// lagras/loggas aldrig här.

const STANDARD = { port: 8788, token: "", failMode: "balanced", failClosed: false };

async function config() {
  const v = await chrome.storage.local.get(STANDARD);
  return { ...STANDARD, ...v };
}

// Fråga daemonen. Returnerar antingen {ok:true, decision} eller
// {ok:false, reason} där reason ∈ {"no-token","unreachable","http-<kod>"}.
async function inspektera(text) {
  const c = await config();
  if (!c.token) return { ok: false, reason: "no-token" };
  const url = `http://127.0.0.1:${c.port}/inspect`;
  try {
    const r = await fetch(url, {
      method: "POST",
      headers: { "content-type": "text/plain", "x-serrier-token": c.token },
      body: text,
    });
    if (!r.ok) return { ok: false, reason: `http-${r.status}` };
    return { ok: true, decision: await r.json() };
  } catch (_e) {
    // Nätfel = daemonen är inte igång / inte nåbar. Aldrig "tyst allow" — content-
    // scriptet gör om detta till UNKNOWN och låter fel-läget avgöra.
    return { ok: false, reason: "unreachable" };
  }
}

chrome.runtime.onMessage.addListener((msg, _sender, svara) => {
  if (msg && msg.type === "inspect") {
    inspektera(msg.text).then(svara);
    return true; // async-svar
  }
  if (msg && msg.type === "config") {
    config().then((c) => svara({ port: c.port, hasToken: !!c.token, failMode: c.failMode, failClosed: c.failClosed }));
    return true;
  }
  return false;
});
