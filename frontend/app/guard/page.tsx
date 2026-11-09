"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";

const API = process.env.NEXT_PUBLIC_API ?? "http://localhost:8000";

type Reason = { regel: string; kategori: string; sensitivity: string; action: string; forklaring: string };
type Finding = { regel: string; kategori: string; sensitivity: string; redacted: string };
type Decision = {
  action: string;
  analysis_status: string;
  failure_mode: string | null;
  safe_text: string;
  reasons: Reason[];
  findings: Finding[];
};
type GuardEvent = {
  action: string;
  analysis_status: string;
  failure_mode: string | null;
  upstream: string | null;
  rules: { regel: string; redacted: string }[];
  tid: string;
};

const ACTION_FARG: Record<string, string> = {
  block: "bg-red-600",
  require_approval: "bg-orange-500",
  redact: "bg-amber-400",
  warn: "bg-sky-400",
  allow: "bg-emerald-500",
};
const ORDNING = ["block", "require_approval", "redact", "warn", "allow"];

export default function Guardian() {
  const [text, setText] = useState("min nyckel sk-ant-api03-REALSECRET1234567890abcDEF");
  const [nyckel, setNyckel] = useState("");
  const [mode, setMode] = useState("balanced");
  const [d, setD] = useState<Decision | null>(null);
  const [events, setEvents] = useState<GuardEvent[]>([]);
  const [fel, setFel] = useState("");

  const hdrs = useCallback(
    (): HeadersInit => (nyckel ? { "X-API-Key": nyckel } : {}),
    [nyckel],
  );

  // Live-flöde: pollar kontrollplanet. Fylls på av /guard/inspect OCH av `serrier-guard run`.
  const hamtaEvents = useCallback(async () => {
    try {
      const r = await fetch(`${API}/guard/events?limit=50`, { headers: hdrs() });
      if (r.ok) setEvents(await r.json());
    } catch {
      /* tyst — pollning */
    }
  }, [hdrs]);

  useEffect(() => {
    hamtaEvents();
    const t = setInterval(hamtaEvents, 3000);
    return () => clearInterval(t);
  }, [hamtaEvents]);

  const tally = ORDNING.map((a) => ({ a, n: events.filter((e) => e.action === a).length }));

  async function inspektera() {
    setFel("");
    try {
      const r = await fetch(`${API}/guard/inspect`, {
        method: "POST",
        headers: { "content-type": "application/json", ...hdrs() },
        body: JSON.stringify({ text, failure_mode: mode }),
      });
      if (!r.ok) throw new Error(String(r.status));
      setD(await r.json());
      hamtaEvents(); // beslutet skrevs som event på servern — uppdatera flödet
    } catch {
      setD(null);
      setFel(`Kunde inte inspektera. Kör backend på ${API}.`);
    }
  }

  return (
    <main className="mx-auto max-w-5xl p-8">
      <header className="mb-6 flex items-end justify-between border-b-2 border-neutral-900 pb-3">
        <div>
          <h1 className="text-2xl font-bold">Serrier — Pre-Send Guardian</h1>
          <p className="text-sm text-neutral-500">
            Live-monitor över prevention-beslut. Rå text lämnar aldrig maskinen.
          </p>
        </div>
        <Link href="/" className="text-sm underline">
          ← Scanner-vy
        </Link>
      </header>

      <section className="mb-4 grid grid-cols-2 gap-4 md:grid-cols-5">
        {tally.map(({ a, n }) => (
          <div key={a} className="border-2 border-neutral-900 p-3 shadow-[4px_4px_0_0_#171717]">
            <div className="text-[11px] uppercase text-neutral-500">{a}</div>
            <div className="mt-1 text-2xl font-bold">{n}</div>
          </div>
        ))}
      </section>

      <section className="mb-6">
        <textarea
          className="h-24 w-full border-2 border-neutral-900 p-3 font-mono text-sm"
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder="Testa: klistra in text som är på väg till en AI-tjänst…"
        />
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <select
            className="border-2 border-neutral-900 px-2 py-2 text-sm"
            value={mode}
            onChange={(e) => setMode(e.target.value)}
            title="Fel-läge vid UNKNOWN"
          >
            <option value="strict">strict</option>
            <option value="balanced">balanced</option>
            <option value="permissive">permissive</option>
          </select>
          <input
            className="min-w-[10rem] flex-1 border-2 border-neutral-900 px-3 py-2 text-sm"
            placeholder="API-nyckel (valfri i dev)"
            value={nyckel}
            onChange={(e) => setNyckel(e.target.value)}
          />
          <button
            onClick={inspektera}
            className="border-2 border-neutral-900 bg-neutral-900 px-4 py-2 text-white"
          >
            Inspektera
          </button>
        </div>
      </section>

      {fel && <p className="mb-6 text-sm text-red-600">{fel}</p>}

      {d && (
        <section className="mb-8 border-2 border-neutral-900">
          <div className="flex items-center justify-between border-b-2 border-neutral-900 p-3">
            <span
              className={`inline-block px-3 py-1 text-sm font-bold uppercase text-white ${
                ACTION_FARG[d.action] ?? "bg-neutral-500"
              }`}
            >
              {d.action}
            </span>
            <span className="text-xs text-neutral-500">
              analysis_status: <b>{d.analysis_status}</b>
              {d.failure_mode ? ` · fel-läge: ${d.failure_mode}` : ""}
            </span>
          </div>
          <div className="p-3">
            <div className="mb-1 text-xs uppercase text-neutral-500">
              safe_text (det som skulle skickas)
            </div>
            <pre className="whitespace-pre-wrap break-words bg-neutral-50 p-2 font-mono text-sm">
              {d.safe_text}
            </pre>
            {d.reasons.length > 0 && (
              <ul className="mt-3 space-y-1 text-sm">
                {d.reasons.map((r, i) => (
                  <li key={i} className="font-mono text-xs">
                    • {r.forklaring}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </section>
      )}

      <section>
        <h2 className="mb-2 text-sm font-semibold uppercase text-neutral-500">
          Live-flöde ({events.length}) — uppdateras var 3:e sekund
        </h2>
        {events.length === 0 ? (
          <p className="text-sm text-neutral-500">
            Inga beslut än. Testa ovan, eller kör{" "}
            <code className="font-mono">serrier-guard run -- &lt;ditt-ai-verktyg&gt;</code> — besluten
            dyker upp här i realtid.
          </p>
        ) : (
          <div className="overflow-hidden border-2 border-neutral-900">
            <table className="w-full text-sm">
              <thead className="bg-neutral-900 text-left text-white">
                <tr>
                  <th className="p-2">Tid</th>
                  <th className="p-2">Aktion</th>
                  <th className="p-2">Status</th>
                  <th className="p-2">Upstream</th>
                  <th className="p-2">Fynd (redakterat)</th>
                </tr>
              </thead>
              <tbody>
                {events.map((e, i) => (
                  <tr key={i} className="border-t border-neutral-200">
                    <td className="p-2 text-neutral-500">
                      {new Date(e.tid).toLocaleTimeString()}
                    </td>
                    <td className="p-2">
                      <span
                        className={`inline-block px-2 py-0.5 text-xs text-white ${
                          ACTION_FARG[e.action] ?? "bg-neutral-400"
                        }`}
                      >
                        {e.action}
                      </span>
                    </td>
                    <td className="p-2 text-neutral-600">{e.analysis_status}</td>
                    <td className="p-2 font-mono text-xs text-neutral-600">{e.upstream ?? "—"}</td>
                    <td className="p-2 font-mono text-xs">
                      {e.rules.map((r) => r.regel).join(", ") || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <p className="mt-6 text-xs text-neutral-500">
        Flödet bär bara redakterad data (verdikt + first4…last4). Täcker body/text; headers
        innehålls-inspekteras inte. Recall &lt; 100 %.
      </p>
    </main>
  );
}
