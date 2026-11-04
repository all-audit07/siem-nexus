"use client";

// app/alerts/page.tsx — Alertas generadas por las reglas, con justificación y evidencia

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import AppShell from "@/components/siem/AppShell";
import {
  Banner, CATEGORY, Card, ImportPicker, NoAnalysis, Pill, ROLE, Spinner, useSelectedImport,
} from "@/components/siem/ui";
import { SessionExpiredError, SEVERITY, apiFetch, fmtDateTime } from "@/lib/siem";

interface Evidence {
  log_id: string; event_id: string; role: "trigger" | "supporting" | "context"; occurred_at: string;
  event_type: string; hostname: string | null; user_name: string | null; source_ip: string | null;
  description: string | null; command_line: string | null;
}

export interface Alert {
  id: string; title: string; description: string; severity: number; status: string;
  justification: string; window_start: string; window_end: string; analyzed_at: string;
  incident_id: string | null; rule_version: number; rule_code: string; rule_name: string;
  category: string; mitre_techniques: string[] | null; evidence: Evidence[];
}

export default function AlertsPage() {
  return (
    <AppShell title="Alertas" subtitle="Hallazgos de las reglas de detección, con su justificación y los registros que los sustentan">
      {() => <AlertsView />}
    </AppShell>
  );
}

function AlertsView() {
  const router = useRouter();
  const { imports, selected, select, error: importsError } = useSelectedImport();
  const [alerts, setAlerts] = useState<Alert[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [current, setCurrent] = useState<string | null>(null);
  const [sev, setSev] = useState<number | null>(null);
  const [cat, setCat] = useState("");
  const [incident, setIncident] = useState<string | null>(null);
  const [q, setQ] = useState("");

  // Filtros iniciales desde la URL (?alert=, ?incident=)
  useEffect(() => {
    const p = new URLSearchParams(window.location.search);
    setCurrent(p.get("alert"));
    setIncident(p.get("incident"));
    const s = Number(p.get("severity"));
    if ([2, 3, 4, 5].includes(s)) setSev(s);
    const c = p.get("category");
    if (c && c in CATEGORY) setCat(c);
  }, []);

  useEffect(() => {
    if (!selected) return;
    setAlerts(null); setError(null);
    (async () => {
      try {
        const r = await apiFetch<Alert[]>(`/imports/${selected}/alerts`);
        if (r.ok && Array.isArray(r.data)) setAlerts(r.data);
        else setError(r.data?.error || "No se pudieron cargar las alertas");
      } catch (e) {
        if (e instanceof SessionExpiredError) router.replace("/login");
        else setError("Error inesperado al cargar las alertas");
      }
    })();
  }, [selected, router]);

  const filtered = useMemo(() => {
    if (!alerts) return [];
    const term = q.trim().toLowerCase();
    return alerts.filter((a) =>
      (sev === null || a.severity === sev) &&
      (!cat || a.category === cat) &&
      (!incident || a.incident_id === incident) &&
      (!term || [a.title, a.justification, a.rule_code, ...a.evidence.map((e) => e.log_id)].join(" ").toLowerCase().includes(term)));
  }, [alerts, sev, cat, incident, q]);

  // Mantiene una alerta seleccionada visible en el panel de detalle
  useEffect(() => {
    if (!filtered.length) return;
    if (!current || !filtered.some((a) => a.id === current)) setCurrent(filtered[0].id);
  }, [filtered, current]);

  const selectAlert = (id: string) => {
    setCurrent(id);
    const url = new URL(window.location.href);
    url.searchParams.set("alert", id);
    window.history.replaceState(null, "", url);
  };

  const counts = useMemo(() => {
    const c: Record<number, number> = {};
    (alerts || []).forEach((a) => { c[a.severity] = (c[a.severity] || 0) + 1; });
    return c;
  }, [alerts]);

  const detail = filtered.find((a) => a.id === current) || null;

  if (imports === null) return <p className="text-[13px] text-[#94A3B8]">Cargando…</p>;
  if (importsError) return <Banner tone="error">{importsError}</Banner>;
  if (!imports.length) return <NoAnalysis />;

  return (
    <div className="space-y-5">
      {/* Filtros */}
      <div className="flex flex-wrap items-center gap-3">
        <ImportPicker imports={imports} selected={selected} onChange={(id) => { select(id); setIncident(null); }} />
        <div className="flex gap-1.5" role="group" aria-label="Filtrar por criticidad">
          <FilterChip active={sev === null} onClick={() => setSev(null)}>Todas · {alerts?.length ?? "…"}</FilterChip>
          {[5, 4, 3, 2].map((s) => (
            <FilterChip key={s} active={sev === s} onClick={() => setSev(sev === s ? null : s)} color={SEVERITY[s].color}>
              {SEVERITY[s].label} · {counts[s] || 0}
            </FilterChip>
          ))}
        </div>
        <select value={cat} onChange={(e) => setCat(e.target.value)} aria-label="Categoría"
          className="bg-[#0b1324] border border-white/[0.12] rounded-lg px-2.5 py-1.5 text-[12px]">
          <option value="">Todas las categorías</option>
          {Object.entries(CATEGORY).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </select>
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Buscar texto, regla o Log_ID…"
          className="flex-1 min-w-[200px] bg-[#0b1324] border border-white/[0.12] rounded-lg px-3 py-1.5 text-[12px] placeholder:text-[#64748B]" />
        {incident && (
          <button onClick={() => setIncident(null)} className="font-mono text-[11px] px-2.5 py-1.5 rounded-lg bg-purple-500/10 text-purple-300 border border-purple-500/25 hover:bg-purple-500/20">
            Incidente #{incident} ✕
          </button>
        )}
      </div>

      {error && <Banner tone="error">{error}</Banner>}

      <div className="grid grid-cols-[minmax(0,1fr)_minmax(0,1.15fr)] gap-5 items-start">
        {/* Lista */}
        <Card title={<>Alertas <span className="font-mono text-[11px] text-[#94A3B8] font-normal">({filtered.length})</span></>}>
          {alerts === null ? (
            <p className="px-5 py-6 text-[13px] text-[#94A3B8] flex items-center gap-2"><Spinner /> Cargando…</p>
          ) : filtered.length === 0 ? (
            <p className="px-5 py-6 text-[13px] text-[#94A3B8]">Ninguna alerta coincide con los filtros.</p>
          ) : (
            <ul className="divide-y divide-white/[0.05] max-h-[calc(100vh-260px)] overflow-y-auto">
              {filtered.map((a) => {
                const s = SEVERITY[a.severity];
                const active = a.id === current;
                return (
                  <li key={a.id}>
                    <button onClick={() => selectAlert(a.id)} aria-current={active}
                      className={`w-full text-left px-5 py-3.5 border-l-2 transition-colors ${active
                        ? "bg-blue-500/[0.08] border-blue-500" : "border-transparent hover:bg-white/[0.03]"}`}>
                      <div className="flex items-center gap-2 mb-1.5">
                        <Pill cls={s.cls}>{s.label}</Pill>
                        <span className="font-mono text-[10px] text-[#94A3B8]">{a.rule_code}</span>
                        <span className="text-[11px] text-[#94A3B8]">· {CATEGORY[a.category] || a.category}</span>
                        <span className="ml-auto font-mono text-[10px] text-[#94A3B8] whitespace-nowrap">{fmtDateTime(a.window_start).slice(11)}</span>
                      </div>
                      <p className="text-[13px] font-medium leading-snug">{a.title}</p>
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </Card>

        {/* Detalle */}
        <div className="sticky top-0">
          {detail ? <AlertDetail alert={detail} importId={selected} /> : alerts && (
            <Card title="Detalle"><p className="px-5 py-6 text-[13px] text-[#94A3B8]">Selecciona una alerta.</p></Card>
          )}
        </div>
      </div>
    </div>
  );
}

const FilterChip = ({ active, onClick, color, children }:
  { active: boolean; onClick: () => void; color?: string; children: React.ReactNode }) => (
  <button onClick={onClick} aria-pressed={active}
    className={`font-mono text-[11px] px-2.5 py-1.5 rounded-lg border transition-all ${active
      ? "bg-blue-500/[0.14] border-blue-500/40 text-[#E2E8F0]" : "bg-white/[0.03] border-white/[0.08] text-[#94A3B8] hover:text-[#E2E8F0]"}`}>
    {color && <span className="inline-block w-2 h-2 rounded-sm mr-1.5 align-middle" style={{ background: color }} />}
    {children}
  </button>
);

function AlertDetail({ alert: a, importId }: { alert: Alert; importId: string | null }) {
  const s = SEVERITY[a.severity];
  return (
    <Card title={<span className="truncate">Detalle de la alerta #{a.id}</span>}
      right={<Pill cls={s.cls}>{s.label}</Pill>}>
      <div className="p-5 space-y-5 max-h-[calc(100vh-260px)] overflow-y-auto">
        <h3 className="text-[16px] font-semibold leading-snug">{a.title}</h3>

        <dl className="grid grid-cols-2 gap-x-6 gap-y-3 text-[12px]">
          <Field label="Regla">
            <span className="font-mono">{a.rule_code}</span> · {a.rule_name.replace(/^[A-Z]{2}-\d{3} · /, "")}
            <span className="font-mono text-[#94A3B8]"> (v{a.rule_version})</span>
          </Field>
          <Field label="Categoría">{CATEGORY[a.category] || a.category}</Field>
          <Field label="Ventana evaluada (hora Panamá)">
            <span className="font-mono">{fmtDateTime(a.window_start)}</span>
            {a.window_end !== a.window_start && <> → <span className="font-mono">{fmtDateTime(a.window_end).slice(11)}</span></>}
          </Field>
          <Field label="MITRE ATT&CK">
            {a.mitre_techniques?.length
              ? <span className="flex flex-wrap gap-1">{a.mitre_techniques.map((t) => (
                  <a key={t} href={`https://attack.mitre.org/techniques/${t.replace(".", "/")}/`} target="_blank" rel="noreferrer"
                    className="font-mono text-[11px] text-blue-300 hover:underline">{t}</a>))}</span>
              : <span className="text-[#94A3B8]">—</span>}
          </Field>
          {a.incident_id && (
            <Field label="Incidente">
              <a href={`/incidents?import=${importId}&incident=${a.incident_id}`} className="text-blue-300 hover:underline font-mono">#{a.incident_id}</a>
            </Field>
          )}
          <Field label="Analizado">{fmtDateTime(a.analyzed_at)}</Field>
        </dl>

        <div>
          <p className="font-mono text-[10px] uppercase tracking-[0.12em] text-[#94A3B8] mb-2">Justificación de la criticidad</p>
          <p className="text-[13px] leading-relaxed bg-white/[0.03] border border-white/[0.07] rounded-xl px-4 py-3">{a.justification}</p>
        </div>

        <div>
          <p className="font-mono text-[10px] uppercase tracking-[0.12em] text-[#94A3B8] mb-2">
            Evidencia — {a.evidence.length} registro{a.evidence.length === 1 ? "" : "s"} del archivo importado
          </p>
          <ul className="rounded-xl border border-white/[0.07] divide-y divide-white/[0.05]">
            {a.evidence.map((e) => (
              <li key={e.event_id} className="px-4 py-2.5 text-[12px]">
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                  <span className="font-mono font-semibold">{e.log_id}</span>
                  <Pill cls={ROLE[e.role].cls} title={ROLE[e.role].hint}>{ROLE[e.role].label}</Pill>
                  <span className="font-mono text-[#94A3B8]">{fmtDateTime(e.occurred_at).slice(11)}</span>
                  <span className="font-mono text-[#CBD5E1]">
                    {[e.hostname, e.user_name, e.source_ip].filter(Boolean).join(" · ")}
                  </span>
                </div>
                <p className="mt-1 text-[#94A3B8] break-words">
                  {e.command_line ? <span className="font-mono text-[11px] text-[#CBD5E1]">{e.command_line}</span> : e.description || "—"}
                </p>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </Card>
  );
}

const Field = ({ label, children }: { label: string; children: React.ReactNode }) => (
  <div className="min-w-0">
    <dt className="font-mono text-[10px] uppercase tracking-[0.1em] text-[#94A3B8] mb-1">{label}</dt>
    <dd className="text-[#E2E8F0]">{children}</dd>
  </div>
);
