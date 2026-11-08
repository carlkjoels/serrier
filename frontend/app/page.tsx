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
  const [posture, setPosture] = useState<Posture | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [fel, setFel] = useState("");

  async function ladda(id: string) {
    setFel("");
    try {
      const pr = await fetch(`${API}/projects/${id}/posture`);
      if (!pr.ok) throw new Error("okänt projekt");
      const p = await pr.json();
      const f = await fetch(`${API}/projects/${id}/findings`).then((r) => r.json());
      setPosture(p.posture);
      setFindings(f);
    } catch {
      setPosture(null);
      setFindings([]);
      setFel(`Kunde inte hämta. Kör backend på ${API} och ange ett giltigt projekt-id.`);
    }
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
        className="mb-8 flex gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          if (pid.trim()) ladda(pid.trim());
        }}
      >
        <input
          className="flex-1 border-2 border-neutral-900 px-3 py-2"
          placeholder="projekt-id"
          value={pid}
          onChange={(e) => setPid(e.target.value)}
        />
        <button className="border-2 border-neutral-900 bg-neutral-900 px-4 py-2 text-white">
          Visa
        </button>
      </form>

      {fel && <p className="mb-6 text-sm text-red-600">{fel}</p>}

      {posture && (
        <>
          <section className="mb-8 grid grid-cols-2 gap-4 md:grid-cols-4">
            <Kort etikett="Posture" varde={posture.etikett} />
            <Kort etikett="Öppna fynd" varde={String(posture.antal_oppna)} />
            <Kort etikett="Åtgärdade" varde={String(posture.antal_atgardade)} />
            <Kort etikett="Risk (snitt)" varde={String(posture.risk_snitt)} />
          </section>

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
