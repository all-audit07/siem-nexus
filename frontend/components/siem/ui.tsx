"use client";

// components/siem/ui.tsx — piezas visuales compartidas por las páginas de análisis

import { ReactNode, useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { SessionExpiredError, apiFetch, fmtDateTime } from "@/lib/siem";

export const Card = ({ title, icon, right, children, className = "" }:
  { title: ReactNode; icon?: ReactNode; right?: ReactNode; children: ReactNode; className?: string }) => (
  <section className={`bg-white/[0.025] border border-white/[0.07] rounded-2xl overflow-hidden backdrop-blur-sm shadow-[0_4px_24px_rgba(0,0,0,0.25)] ${className}`}>
    <div className="flex items-center justify-between gap-3 px-5 py-4 border-b border-white/[0.07] bg-white/[0.02]">
      <h2 className="flex items-center gap-2 text-[14px] font-semibold min-w-0">{icon}{title}</h2>
      {right}
    </div>
    {children}
  </section>
);

export const Stat = ({ label, value, color, hint }: { label: string; value: ReactNode; color?: string; hint?: string }) => (
  <div className="bg-white/[0.03] border border-white/[0.07] rounded-xl px-4 py-3.5">
    <div className="font-mono text-[26px] font-semibold leading-none tabular-nums" style={{ color }}>{value}</div>
    <div className="text-[11px] text-[#94A3B8] uppercase tracking-[0.08em] mt-2">{label}</div>
    {hint && <div className="font-mono text-[10px] text-[#94A3B8]/70 mt-1">{hint}</div>}
  </div>
);

export const Pill = ({ cls, children, title }: { cls: string; children: ReactNode; title?: string }) => (
  <span title={title} className={`inline-flex items-center font-mono text-[10px] font-semibold px-2 py-0.5 rounded border whitespace-nowrap ${cls}`}>{children}</span>
);

export const Banner = ({ tone, children }: { tone: "error" | "warn" | "ok" | "info"; children: ReactNode }) => {
  const cls = {
    error: "bg-red-500/[0.08] border-red-500/25 text-red-200",
    warn:  "bg-yellow-500/[0.08] border-yellow-500/25 text-yellow-100",
    ok:    "bg-green-500/[0.08] border-green-500/25 text-green-100",
    info:  "bg-blue-500/[0.08] border-blue-500/25 text-blue-100",
  }[tone];
  return <div role={tone === "error" ? "alert" : "status"} className={`rounded-xl border px-4 py-3 text-[13px] leading-relaxed ${cls}`}>{children}</div>;
};

export const Spinner = () => <span className="w-3.5 h-3.5 border-2 border-white/25 border-t-white rounded-full animate-spin inline-block" aria-hidden />;

export const th = "text-left px-4 py-2.5 font-mono text-[10px] tracking-[0.1em] uppercase text-[#94A3B8] font-medium whitespace-nowrap";
export const td = "px-4 py-2.5 align-top";

// ── Categorías de las reglas ─────────────────────────────────────
export const CATEGORY: Record<string, string> = {
  brute_force:          "Fuerza bruta",
  suspicious_login:     "Inicio sospechoso",
  privilege_escalation: "Escalamiento",
  process_execution:    "Comandos y procesos",
  lateral_movement:     "Movimiento lateral",
  anomaly:              "Otras anomalías",
};

export const ROLE: Record<string, { label: string; cls: string; hint: string }> = {
  trigger:    { label: "Disparador", cls: "bg-red-500/12 text-red-300 border-red-500/25",   hint: "Evento que activó la regla" },
  supporting: { label: "Soporte",    cls: "bg-blue-500/12 text-blue-300 border-blue-500/25", hint: "Evento que cumple la condición de la regla" },
  context:    { label: "Contexto",   cls: "bg-white/[0.05] text-[#94A3B8] border-white/10",  hint: "Evento previo que explica el hallazgo" },
};

// ── Importación seleccionada ─────────────────────────────────────
export interface ImportRow {
  id: string; file_name: string; status: string; rows_valid: number;
  imported_at: string; analyzed_at: string | null;
}

// Carga las importaciones y elige la indicada en ?import= o la última analizada.
export function useSelectedImport() {
  const router = useRouter();
  const [imports, setImports] = useState<ImportRow[] | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const r = await apiFetch<ImportRow[]>("/imports");
        if (!r.ok || !Array.isArray(r.data)) { setError(r.data?.error || "No se pudieron cargar las importaciones"); setImports([]); return; }
        const analyzed = r.data.filter((i) => i.status === "analyzed");
        setImports(analyzed);
        const wanted = new URLSearchParams(window.location.search).get("import");
        setSelected(analyzed.find((i) => i.id === wanted)?.id ?? analyzed[0]?.id ?? null);
      } catch (e) {
        if (e instanceof SessionExpiredError) router.replace("/login");
        else setError("Error inesperado al cargar las importaciones");
      }
    })();
  }, [router]);

  const select = useCallback((id: string) => {
    setSelected(id);
    const url = new URL(window.location.href);
    url.searchParams.set("import", id);
    window.history.replaceState(null, "", url);
  }, []);

  return { imports, selected, select, error };
}

export const ImportPicker = ({ imports, selected, onChange }:
  { imports: ImportRow[]; selected: string | null; onChange: (id: string) => void }) => (
  <label className="flex items-center gap-2 text-[12px] text-[#94A3B8]">
    Importación
    <select value={selected ?? ""} onChange={(e) => onChange(e.target.value)}
      className="bg-[#0b1324] border border-white/[0.12] rounded-lg px-2.5 py-1.5 font-mono text-[12px] text-[#E2E8F0] max-w-[320px]">
      {imports.map((i) => (
        <option key={i.id} value={i.id}>#{i.id} · {i.file_name} · {fmtDateTime(i.analyzed_at)}</option>
      ))}
    </select>
  </label>
);

export const NoAnalysis = () => (
  <Banner tone="info">
    Todavía no hay importaciones analizadas. Ve a <a href="/imports" className="underline font-semibold">Importar logs</a>,
    carga el archivo Excel y ejecuta el análisis.
  </Banner>
);
