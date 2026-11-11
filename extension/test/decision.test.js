// Serrier Pre-Send Guardian — test av ren enforcement-logik (0005 steg 3).
// Körs utan ramverk: `node extension/test/decision.test.js`. Inget browser-beroende.
//
// Beviset steg 3 kräver: selector-miss (text===null) och daemon-nere → UNKNOWN,
// aldrig tyst allow; fel-läget avgör (strict/fail-closed → block, balanced → confirm).

const assert = require("node:assert");
const { serrierBeslut } = require("../decision.js");

const bal = { failMode: "balanced", failClosed: false };
const strikt = { failMode: "strict", failClosed: false };
const failClosed = { failMode: "balanced", failClosed: true };

let n = 0;
const ok = (namn, villkor) => { assert.ok(villkor, namn); n++; };
const eq = (namn, a, b) => { assert.strictEqual(a, b, `${namn} (fick ${a}, väntade ${b})`); n++; };

// --- Nåbar daemon: följ verdiktet -----------------------------------------
eq("block-verdikt → block",
   serrierBeslut("sk-hemlig", { ok: true, decision: { handling: "block", findings: [{ regel: "anthropic" }] } }, bal).kind,
   "block");
eq("forward-verdikt → allow",
   serrierBeslut("hej", { ok: true, decision: { handling: "forward", analysis_status: "ok" } }, bal).kind,
   "allow");
const r = serrierBeslut("x", { ok: true, decision: { handling: "redact", safe_text: "[redacted]" } }, bal);
eq("redact-verdikt → redact", r.kind, "redact");
eq("redact bär safe_text", r.safeText, "[redacted]");

// --- Permissive-okänt: daemonens MEDVETNA policy (nåbar) → allow, markerat --
const p = serrierBeslut("x", { ok: true, decision: { handling: "forward", analysis_status: "unknown" } }, bal);
eq("permissive okänt → allow", p.kind, "allow");
ok("permissive okänt markeras unknown", p.unknown === true);

// --- Layout-miss (selector-miss): UNKNOWN, ALDRIG allow -------------------
const miss = serrierBeslut(null, null, bal);
ok("layout-miss aldrig allow", miss.kind !== "allow");
eq("layout-miss balanced → confirm", miss.kind, "confirm");
eq("layout-miss strict → block", serrierBeslut(null, null, strikt).kind, "block");
eq("layout-miss fail-closed → block", serrierBeslut(null, null, failClosed).kind, "block");

// --- Daemon nere / fel: UNKNOWN, ALDRIG allow -----------------------------
eq("daemon nere balanced → confirm", serrierBeslut("x", { ok: false, reason: "unreachable" }, bal).kind, "confirm");
eq("daemon nere strict → block", serrierBeslut("x", { ok: false, reason: "unreachable" }, strikt).kind, "block");
eq("daemon nere fail-closed → block", serrierBeslut("x", { ok: false, reason: "unreachable" }, failClosed).kind, "block");
ok("ingen token → aldrig allow", serrierBeslut("x", { ok: false, reason: "no-token" }, bal).kind !== "allow");
ok("http-fel → aldrig allow", serrierBeslut("x", { ok: false, reason: "http-500" }, bal).kind !== "allow");

// --- Kärn-invariant: inget FEL-UNKNOWN blir någonsin allow ----------------
const felSvar = [null, { ok: false, reason: "unreachable" }, { ok: false, reason: "no-token" }, { ok: false, reason: "http-500" }];
for (const cfg of [bal, strikt, failClosed]) {
  for (const svar of felSvar) {
    ok("fel-UNKNOWN (text) aldrig allow", serrierBeslut("x", svar, cfg).kind !== "allow");
    ok("fel-UNKNOWN (layout-miss) aldrig allow", serrierBeslut(null, svar, cfg).kind !== "allow");
  }
}

console.log(`extension/decision: ${n} assertions gröna`);
