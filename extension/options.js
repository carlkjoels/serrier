// Serrier Pre-Send Guardian — inställningar (0005 steg 2, scaffold).
// Sparar port/token/fel-läge lokalt i chrome.storage.local. Token lämnar aldrig
// browsern annat än till loopback-daemonen.

const STANDARD = { port: 8788, token: "", failMode: "balanced", failClosed: false };
const $ = (id) => document.getElementById(id);

async function ladda() {
  const v = { ...STANDARD, ...(await chrome.storage.local.get(STANDARD)) };
  $("port").value = v.port;
  $("token").value = v.token;
  $("failMode").value = v.failMode;
  $("failClosed").checked = v.failClosed;
}

async function spara() {
  const port = parseInt($("port").value, 10);
  const status = $("status");
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    status.textContent = "ogiltig port"; status.className = "err"; return;
  }
  await chrome.storage.local.set({
    port,
    token: $("token").value.trim(),
    failMode: $("failMode").value,
    failClosed: $("failClosed").checked,
  });
  status.textContent = "sparat ✓"; status.className = "ok";
  setTimeout(() => { status.textContent = ""; }, 2000);
}

document.addEventListener("DOMContentLoaded", ladda);
document.getElementById("spara").addEventListener("click", spara);
