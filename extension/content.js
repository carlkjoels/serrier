// Serrier Pre-Send Guardian — content-script (0005 steg 2–3, scaffold).
//
// PEP:en i browsern. Hookar compose-rutans "skicka" på en stödd AI-sajt, läser
// texten, frågar den lokala daemonen via background-workern, och VERKSTÄLLER
// verdiktet (block / redact / warn / allow) FÖRE sändning. Själva beslutet fattas i
// decision.js (ren, testbar); här mappas det bara till DOM-åtgärder.
//
// ÄRLIG BEGRÄNSNING (0005 §5): DOM-kopplat och skört. Sajtens selektorer (nedan) går
// sönder när leverantören bygger om UI:t. När vi inte kan läsa fältet → UNKNOWN, aldrig
// tyst allow. Scaffold-kvalitet, inte publicerat.

// --- Per-sajt-selektorer (det som går sönder; medvetet isolerat) -----------
const SAJTER = [
  {
    värd: "claude.ai",
    editor: 'div[contenteditable="true"]',
    skicka: 'button[aria-label*="Send" i], button[aria-label*="Skicka" i]',
  },
  {
    värd: "chatgpt.com",
    editor: '#prompt-textarea, div[contenteditable="true"]',
    skicka: 'button[data-testid="send-button"], button[aria-label*="Send" i]',
  },
];

const sajt = SAJTER.find((s) => location.hostname.endsWith(s.värd));
if (sajt) start();

function editorEl() { return document.querySelector(sajt.editor); }
function skickaEl() { return document.querySelector(sajt.skicka); }
function läsText() {
  const e = editorEl();
  return e ? (e.innerText ?? e.textContent ?? "").trim() : null; // null = layout-miss
}

let bypass = false; // sätts när vi själva åter-utlöser en godkänd sändning

function start() {
  // Fånga BÅDE Enter och klick på skicka-knappen i capture-fas, så vi hinner före
  // sajtens egna hanterare.
  document.addEventListener("keydown", (ev) => {
    const e = editorEl();
    if (ev.key === "Enter" && !ev.shiftKey && e && e.contains(ev.target)) grinda(ev);
  }, true);
  document.addEventListener("click", (ev) => {
    const b = skickaEl();
    if (b && (ev.target === b || b.contains(ev.target))) grinda(ev);
  }, true);
}

// Grinden: stoppa sändningen, fråga daemonen, och tillämpa decision.js-verdiktet.
async function grinda(ev) {
  if (bypass) { bypass = false; return; } // vår egen åter-sändning — släpp igenom
  ev.preventDefault();
  ev.stopImmediatePropagation();

  const text = läsText();
  if (text !== null && text.trim() === "") return; // tomt → inget att skicka

  let svar = null;
  if (text !== null) {
    try {
      svar = await chrome.runtime.sendMessage({ type: "inspect", text });
    } catch (_e) {
      svar = { ok: false, reason: "unreachable" };
    }
  }
  const config = await chrome.runtime
    .sendMessage({ type: "config" })
    .catch(() => ({ failMode: "balanced", failClosed: true })); // ingen kontakt → fail-closed

  tillämpa(serrierBeslut(text, svar, config)); // serrierBeslut: global från decision.js
}

function tillämpa(b) {
  switch (b.kind) {
    case "allow":
      return skicka(b.unknown ? banner("warn", b.reason) : null);
    case "redact":
      sättText(b.safeText || "");
      return skicka(banner("warn", b.reason));
    case "confirm":
      return bannerBekräfta(b.reason);
    case "block":
    default:
      return banner("block", b.reason);
  }
}

// --- sändning + redigering -------------------------------------------------
function skicka(bannerEl) {
  if (bannerEl) setTimeout(() => bannerEl.remove(), 2500);
  const b = skickaEl();
  bypass = true;
  if (b) b.click(); // åter-utlös (scaffold: fungerar oftast för knappar)
  else bypass = false;
}

function sättText(t) {
  const e = editorEl();
  if (!e) return;
  e.focus();
  // Scaffold: enkel ersättning. Rika editorer (ProseMirror) kan kräva mer.
  e.textContent = t;
  e.dispatchEvent(new InputEvent("input", { bubbles: true }));
}

// --- banner-UI (shadow DOM, påverkar inte sidan) ---------------------------
function banner(sort, text) {
  const host = document.createElement("div");
  host.style.cssText = "position:fixed;z-index:2147483647;bottom:16px;right:16px;max-width:360px";
  const sh = host.attachShadow({ mode: "closed" });
  const färg = sort === "block" ? "#b00020" : "#8a6d00";
  sh.innerHTML = `<div style="font:13px system-ui;background:#fff;border-left:4px solid ${färg};
    box-shadow:0 2px 12px rgba(0,0,0,.2);border-radius:6px;padding:10px 12px;color:#222">
    <b style="color:${färg}">Serrier</b> — ${escapeHtml(text)}</div>`;
  document.body.appendChild(host);
  return host;
}

function bannerBekräfta(text) {
  const host = document.createElement("div");
  host.style.cssText = "position:fixed;z-index:2147483647;bottom:16px;right:16px;max-width:360px";
  const sh = host.attachShadow({ mode: "closed" });
  sh.innerHTML = `<div style="font:13px system-ui;background:#fff;border-left:4px solid #8a6d00;
    box-shadow:0 2px 12px rgba(0,0,0,.2);border-radius:6px;padding:10px 12px;color:#222">
    <b style="color:#8a6d00">Serrier</b> — ${escapeHtml(text)}
    <div style="margin-top:8px;text-align:right">
      <button id="avbryt" style="margin-right:8px">Avbryt</button>
      <button id="skicka">Skicka ändå</button></div></div>`;
  sh.getElementById("avbryt").onclick = () => host.remove();
  sh.getElementById("skicka").onclick = () => { host.remove(); skicka(null); };
  document.body.appendChild(host);
  return host;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}
