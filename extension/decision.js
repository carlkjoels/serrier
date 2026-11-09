// Serrier Pre-Send Guardian — ren enforcement-logik (0005 steg 3).
//
// INGEN DOM, INGEN chrome — därför testbar i Node (se test/decision.test.js). I browsern
// laddas den FÖRE content.js (manifest-js-ordning, delad content-script-scope), så
// `serrierBeslut` finns som global; content.js mappar beslutet till DOM-åtgärder.
//
// Kärn-invariant: ett UNKNOWN-TILLSTÅND SOM UPPSTÅR AV ETT FEL (daemon nere, ingen token,
// layout-miss) blir ALDRIG "allow". Enda vägen till allow är ett uttryckligt verdikt från en
// NÅBAR daemon (handling=forward) — inklusive permissive-läges medvetna "okänt men tillåtet",
// vilket är daemonens policy-beslut, inte extensionen som tyst släpper igenom vid fel.

function serrierReasonText(reason) {
  if (reason === "no-token") return "ingen token konfigurerad (öppna inställningar)";
  if (reason === "unreachable") return "Serrier-daemonen svarar inte (kör `serrier up`)";
  return "daemon-fel";
}

function serrierBeskriv(d) {
  const regler = (d.findings || []).map((f) => f.regel).filter(Boolean);
  const vad = regler.length ? ` (${[...new Set(regler)].join(", ")})` : "";
  return `Blockerat: känsligt innehåll stoppat innan sändning${vad}. Inget skickades.`;
}

function serrierOkäntBeslut(config, skäl) {
  const strikt = !!(config && (config.failClosed || config.failMode === "strict"));
  return strikt
    ? { kind: "block", unknown: true, reason: `Blockerat (fail-closed): ${skäl}. UNKNOWN ≠ säkert.` }
    : { kind: "confirm", unknown: true, reason: `UNKNOWN: ${skäl}. Skicka ändå?` };
}

// text: string | null (null = layout-miss, kunde ej läsas)
// svar: {ok:true, decision} | {ok:false, reason} (från background /inspect)
// config: {failMode, failClosed}
function serrierBeslut(text, svar, config) {
  if (text === null) return serrierOkäntBeslut(config, "kunde inte läsa compose-rutan (layout ändrad?)");
  if (text.trim() === "") return { kind: "allow", reason: "tomt" };
  if (!svar || !svar.ok) return serrierOkäntBeslut(config, serrierReasonText(svar && svar.reason));

  const d = svar.decision || {};
  const okänt = d.analysis_status === "unknown";
  switch (d.handling) {
    case "forward":
      return { kind: "allow", unknown: okänt,
               reason: okänt ? "okänt innehåll — vidarebefordrat enligt permissive-läge" : "" };
    case "redact":
      return { kind: "redact", safeText: d.safe_text || "",
               reason: "Serrier redakterade känsligt innehåll innan sändning." };
    case "block":
    default:
      return { kind: "block", reason: serrierBeskriv(d) };
  }
}

// Dual-export: global i browsern, module.exports i Node (för testet).
if (typeof module !== "undefined" && module.exports) {
  module.exports = { serrierBeslut, serrierOkäntBeslut, serrierBeskriv, serrierReasonText };
}
