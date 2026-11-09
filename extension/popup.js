// Serrier Pre-Send Guardian — popup (0005 steg 2, scaffold).
// Visar daemon-status + fel-läge och kan göra ett ofarligt test-anrop till loopback.

const $ = (id) => document.getElementById(id);

async function visa() {
  const c = await chrome.runtime.sendMessage({ type: "config" }).catch(() => null);
  if (!c) { $("daemon").textContent = "okänt"; return; }
  $("mode").textContent = c.failMode + (c.failClosed ? " (fail-closed)" : "");
  if (!c.hasToken) {
    $("daemon").innerHTML = '<span class="err">ingen token</span>';
    return;
  }
  $("daemon").textContent = `konfigurerad: 127.0.0.1:${c.port}`;
}

async function test() {
  $("daemon").textContent = "testar…";
  // Ofarlig text → daemonen svarar med ett verdikt om den är nåbar.
  const r = await chrome.runtime.sendMessage({ type: "inspect", text: "serrier connection test" }).catch(() => null);
  if (r && r.ok) $("daemon").innerHTML = '<span class="ok">nåbar ✓</span>';
  else if (r && r.reason === "no-token") $("daemon").innerHTML = '<span class="err">ingen token</span>';
  else $("daemon").innerHTML = '<span class="err">ej nåbar (kör `serrier up`)</span>';
}

document.addEventListener("DOMContentLoaded", visa);
document.getElementById("test").addEventListener("click", test);
document.getElementById("opts").addEventListener("click", (e) => { e.preventDefault(); chrome.runtime.openOptionsPage(); });
