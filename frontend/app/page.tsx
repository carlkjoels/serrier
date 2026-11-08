"use client";

import { useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

const API = process.env.NEXT_PUBLIC_API ?? "http://localhost:8000";

type Finding = {
  id: string;
  severity: string;
  confidence: string;
  detector: string;
  asset_ref: string;
  title: string;
  risk: number;
  status: string;
  aterkomster: number;
};

type Posture = {
  etikett: string;
  antal_findings: number;
  antal_oppna: number;
  antal_atgardade: number;
  risk_total: number;
  risk_snitt: number;
  per_severity: Record<string, number>;
  per_detektor: Record<string, number>;
  topp: Finding[];
};

type Regression = {
  id: string;
  asset_ref: string;
  title: string;
  detector: string;
  severity: string;
  aterkomster: number;
};

const SEV_FARG: Record<string, string> = {
  critical: "bg-red-600",
  high: "bg-orange-500",
  medium: "bg-amber-400",
  low: "bg-sky-400",
  info: "bg-neutral-300",
};
const SEV_ORDNING = ["critical", "high", "medium", "low", "info"];

export default function Dashboard() {
  const [pid, setPid] = useState("");
  const [nyckel, setNyckel] = useState("");
  const [posture, setPosture] = useState<Posture | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [korrelationer, setKorrelationer] = useState(0);
  const [regressioner, setRegressioner] = useState<Regression[]>([]);
  const [fel, setFel] = useState("");

  // Nyckel (om satt) skickas som X-API-Key. I dev-läge (ingen auth) behövs ingen.
  const hdrs = (): HeadersInit => (nyckel ? { "X-API-Key": nyckel } : {});

  async function ladda(id: string) {
    setFel("");
    try {
      const pr = await fetch(`${API}/projects/${id}/posture`, { headers: hdrs() });
      if (!pr.ok) throw new Error("okänt projekt");
      const p = await pr.json();
      const f = await fetch(`${API}/projects/${id}/findings`, { headers: hdrs() }).then(
        (r) => r.json(),
      );
      setPosture(p.posture);
      setKorrelationer(p.antal_korrelationer ?? 0);
      setRegressioner(p.regressioner ?? []);
      setFindings(f);
    } catch {
      setPosture(null);
      setFindings([]);
      setKorrelationer(0);
      setRegressioner([]);
      setFel(`Kunde inte hämta. Kör backend på ${API} och ange ett giltigt projekt-id.`);
    }
  }

  // Export: hämta med ev. nyckel-header och ladda ner som fil (länkar kan inte bära headers).
  async function exportera(format: "sarif" | "json") {
    if (!pid.trim()) return;
    const r = await fetch(`${API}/projects/${pid.trim()}/export?format=${format}`, {
      headers: hdrs(),
    });
    const blob = await r.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `serrier-${pid.trim()}.${format}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  const sevData = posture
    ? SEV_ORDNING.filter((s) => posture.per_severity[s]).map((s) => ({
        severity: s,
        antal: posture.per_severity[s],
      }))
    : [];

  return (
    <main className="mx-auto max-w-5xl p-8">
      <header className="mb-8 border-b-2 border-neutral-900 pb-3">
        <h1 className="text-2xl font-bold">Serrier</h1>
        <p className="text-sm text-neutral-500">
          Security intelligence for the AI-native era
        </p>
      </header>

      <form
        className="mb-8 flex flex-wrap gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          if (pid.trim()) ladda(pid.trim());
        }}
      >
        <input
          className="min-w-[12rem] flex-1 border-2 border-neutral-900 px-3 py-2"
          placeholder="projekt-id"
          value={pid}
          onChange={(e) => setPid(e.target.value)}
        />
        <input
          className="min-w-[12rem] flex-1 border-2 border-neutral-900 px-3 py-2"
          placeholder="API-nyckel (valfri i dev)"
          value={nyckel}
          onChange={(e) => setNyckel(e.target.value)}
        />
        <button className="border-2 border-neutral-900 bg-neutral-900 px-4 py-2 text-white">
          Visa
        </button>
      </form>

      {fel && <p className="mb-6 text-sm text-red-600">{fel}</p>}

      {posture && (
        <>
          <section className="mb-8 grid grid-cols-2 gap-4 md:grid-cols-5">
            <Kort etikett="Posture" varde={posture.etikett} />
            <Kort etikett="Öppna fynd" varde={String(posture.antal_oppna)} />
            <Kort etikett="Åtgärdade" varde={String(posture.antal_atgardade)} />
            <Kort etikett="Korrelationer" varde={String(korrelationer)} />
            <Kort etikett="Regressioner" varde={String(regressioner.length)} />
          </section>

          <section className="mb-8 flex gap-2">
            <button
              onClick={() => exportera("sarif")}
              className="border-2 border-neutral-900 px-3 py-1.5 text-sm"
            >
              Exportera SARIF
            </button>
            <button
              onClick={() => exportera("json")}
              className="border-2 border-neutral-900 px-3 py-1.5 text-sm"
            >
              Exportera JSON
            </button>
          </section>

          {regressioner.length > 0 && (
            <section className="mb-8 border-2 border-red-600 bg-red-50 p-3">
              <h2 className="mb-1 text-sm font-semibold uppercase text-red-700">
                Regressioner — fixar som inte höll
              </h2>
              <ul className="text-sm">
                {regressioner.map((r) => (
                  <li key={r.id} className="font-mono text-xs">
                    {r.asset_ref} · {r.detector} · återkom {r.aterkomster}×
                  </li>
                ))}
              </ul>
            </section>
          )}

          <section className="mb-8">
            <h2 className="mb-2 text-sm font-semibold uppercase text-neutral-500">
              Fördelning per severity (öppna)
            </h2>
            <div className="h-56 border-2 border-neutral-900 p-2">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={sevData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="severity" />
                  <YAxis allowDecimals={false} />
                  <Tooltip />
                  <Bar dataKey="antal" fill="#171717" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </section>

          <section>
            <h2 className="mb-2 text-sm font-semibold uppercase text-neutral-500">
              Findings ({findings.length})
            </h2>
            <div className="overflow-hidden border-2 border-neutral-900">
              <table className="w-full text-sm">
                <thead className="bg-neutral-900 text-left text-white">
                  <tr>
                    <th className="p-2">Severity</th>
                    <th className="p-2">Confidence</th>
                    <th className="p-2">Detector</th>
                    <th className="p-2">Plats</th>
                    <th className="p-2">Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {findings.map((f) => (
                    <tr key={f.id} className="border-t border-neutral-200">
                      <td className="p-2">
                        <span
                          className={`inline-block px-2 py-0.5 text-xs text-white ${
                            SEV_FARG[f.severity] ?? "bg-neutral-400"
                          }`}
                        >
                          {f.severity}
                        </span>
                      </td>
                      <td className="p-2 text-neutral-600">{f.confidence}</td>
                      <td className="p-2 text-neutral-600">{f.detector}</td>
                      <td className="p-2 font-mono text-xs">{f.asset_ref}</td>
                      <td className="p-2 font-semibold">{f.risk}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="mt-3 text-xs text-neutral-500">
              &quot;Inga öppna fynd&quot; betyder inte &quot;säker&quot; — bara att den körda
              täckningen inte hittade något öppet.
            </p>
          </section>
        </>
      )}
    </main>
  );
}

function Kort({ etikett, varde }: { etikett: string; varde: string }) {
  return (
    <div className="border-2 border-neutral-900 p-4 shadow-[4px_4px_0_0_#171717]">
      <div className="text-xs uppercase text-neutral-500">{etikett}</div>
      <div className="mt-1 text-xl font-bold">{varde}</div>
    </div>
  );
}
