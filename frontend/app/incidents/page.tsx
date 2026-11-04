"use client";

// app/incidents/page.tsx — Incidentes: alertas relacionadas agrupadas por actor (IP externa o cuenta)

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import AppShell from "@/components/siem/AppShell";
import { Banner, Card, ImportPicker, NoAnalysis, Pill, Spinner, Stat, useSelectedImport } from "@/components/siem/ui";
import { SessionExpiredError, SEVERITY, apiFetch, fmtDateTime } from "@/lib/siem";

interface Incident {
  id: string; title: string; severity: number; status: string;
  affected_assets: string[] | null; mitre_tactics: string[] | null;
  start_at: string; end_at: string; alert_count: number;
  metadata: { users?: string[]; targeted_users?: string[]; external_ips?: string[]; hosts?: string[] };
  alerts: { id: string; title: string; severity: number }[];
}

const STATUS: Record<string, string> = {
  open: "Abierto", investigating: "En investigación", contained: "Contenido", resolved: "Resuelto", closed: "Cerrado",
};

export default function IncidentsPage() {
  return (
    <AppShell title="Incidentes" subtitle="Alertas relacionadas agrupadas por el mismo actor: una IP externa o una cuenta">
      {() => <IncidentsView />}
    </AppShell>
  );
}

function IncidentsView() {
  const router = useRouter();
  const { imports, selected, select, error: importsError } = useSelectedImport();
  const [incidents, setIncidents] = useState<Incident[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [focus, setFocus] = useState<string | null>(null);

  useEffect(() => { setFocus(new URLSearchParams(window.location.search).get("incident")); }, []);

  useEffect(() => {
    if (!selected) return;
    setIncidents(null); setError(null);
    (async () => {
      try {
        const r = await apiFetch<Incident[]>(`/imports/${selected}/incidents`);
        if (r.ok && Array.isArray(r.data)) setIncidents(r.data);
        else setError(r.data?.error || "No se pudieron cargar los incidentes");
      } catch (e) {
        if (e instanceof SessionExpiredError) router.replace("/login");
        else setError("Error inesperado al cargar los incidentes");
      }
    })();
  }, [selected, router]);

  // Desplaza hasta el incidente indicado en la URL
  useEffect(() => {
    if (!incidents || !focus) return;
    document.getElementById(`inc-${focus}`)?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [incidents, focus]);

  const stats = useMemo(() => {
    const list = incidents || [];
    return {
      total: list.length,
      critical: list.filter((i) => i.severity === 5).length,
      high: list.filter((i) => i.severity === 4).length,
      alerts: list.reduce((s, i) => s + i.alert_count, 0),
    };
  }, [incidents]);

  if (imports === null) return <p className="text-[13px] text-[#94A3B8]">Cargando…</p>;
  if (importsError) return <Banner tone="error">{importsError}</Banner>;
  if (!imports.length) return <NoAnalysis />;

  return (
    <div className="max-w-[1180px] mx-auto space-y-5">
      <div className="flex items-center justify-between gap-3">
        <ImportPicker imports={imports} selected={selected} onChange={(id) => { select(id); setFocus(null); }} />
        <p className="text-[12px] text-[#94A3B8]">La criticidad del incidente es la de su alerta más grave.</p>
      </div>

      {error && <Banner tone="error">{error}</Banner>}

      <div className="grid grid-cols-4 gap-3">
        <Stat label="Incidentes" value={incidents ? stats.total : "…"} />
        <Stat label="Críticos" value={incidents ? stats.critical : "…"} color={SEVERITY[5].color} />
        <Stat label="Altos" value={incidents ? stats.high : "…"} color={SEVERITY[4].color} />
        <Stat label="Alertas agrupadas" value={incidents ? stats.alerts : "…"} />
      </div>

      {incidents === null ? (
        <p className="text-[13px] text-[#94A3B8] flex items-center gap-2"><Spinner /> Cargando…</p>
      ) : incidents.length === 0 ? (
        <Banner tone="ok">El análisis de esta importación no generó incidentes.</Banner>
      ) : incidents.map((inc) => <IncidentCard key={inc.id} inc={inc} importId={selected} focused={inc.id === focus} />)}
    </div>
  );
}

function IncidentCard({ inc, importId, focused }: { inc: Incident; importId: string | null; focused: boolean }) {
  const s = SEVERITY[inc.severity];
  const m = inc.metadata || {};
  return (
    <div id={`inc-${inc.id}`} className="scroll-mt-4">
      <Card
        className={focused ? "ring-1 ring-blue-500/50" : ""}
        icon={<span className="w-1 self-stretch rounded-full mr-1" style={{ background: s.color }} />}
        title={<span className="truncate">#{inc.id} · {inc.title}</span>}
        right={<div className="flex items-center gap-2 flex-shrink-0">
          <Pill cls="bg-white/[0.05] text-[#CBD5E1] border-white/10">{STATUS[inc.status] || inc.status}</Pill>
          <Pill cls={s.cls}>{s.label}</Pill>
        </div>}>
        <div className="p-5 grid grid-cols-[minmax(0,1fr)_minmax(0,1.3fr)] gap-6">
          <dl className="space-y-3.5 text-[12px]">
            <Row label="Periodo (hora Panamá)">
              <span className="font-mono">{fmtDateTime(inc.start_at)}</span> → <span className="font-mono">{fmtDateTime(inc.end_at).slice(11)}</span>
            </Row>
            {!!m.external_ips?.length && <Row label="IPs externas implicadas"><Chips items={m.external_ips} cls="bg-red-500/10 text-red-200 border-red-500/20" /></Row>}
            {!!m.users?.length && <Row label="Cuentas que actuaron"><Chips items={m.users} cls="bg-orange-500/10 text-orange-200 border-orange-500/20" /></Row>}
            {!!m.targeted_users?.length && <Row label="Cuentas atacadas"><Chips items={m.targeted_users} cls="bg-white/[0.05] text-[#CBD5E1] border-white/10" /></Row>}
            {!!inc.affected_assets?.length && <Row label="Equipos afectados"><Chips items={inc.affected_assets} cls="bg-blue-500/10 text-blue-200 border-blue-500/20" /></Row>}
            {!!inc.mitre_tactics?.length && <Row label="Tácticas MITRE ATT&CK"><Chips items={inc.mitre_tactics} cls="bg-purple-500/10 text-purple-200 border-purple-500/20" /></Row>}
          </dl>

          <div>
            <p className="font-mono text-[10px] uppercase tracking-[0.12em] text-[#94A3B8] mb-2">
              Secuencia de alertas ({inc.alert_count})
            </p>
            <ol className="relative pl-5 space-y-2.5">
              <span className="absolute left-[5px] top-2 bottom-2 w-px bg-white/[0.08]" aria-hidden />
              {inc.alerts.map((a) => (
                <li key={a.id} className="relative">
                  <span className="absolute -left-[19px] top-[7px] w-[9px] h-[9px] rounded-full border-2 border-[#020817]"
                    style={{ background: SEVERITY[a.severity]?.color }} aria-hidden />
                  <a href={`/alerts?import=${importId}&incident=${inc.id}&alert=${a.id}`}
                    className="block rounded-lg px-3 py-2 hover:bg-white/[0.04] transition-colors">
                    <span className="text-[12px] font-medium leading-snug">{a.title}</span>
                    <span className="ml-2 font-mono text-[10px]" style={{ color: SEVERITY[a.severity]?.color }}>{SEVERITY[a.severity]?.label}</span>
                  </a>
                </li>
              ))}
            </ol>
          </div>
        </div>
      </Card>
    </div>
  );
}

const Row = ({ label, children }: { label: string; children: React.ReactNode }) => (
  <div>
    <dt className="font-mono text-[10px] uppercase tracking-[0.1em] text-[#94A3B8] mb-1.5">{label}</dt>
    <dd>{children}</dd>
  </div>
);

const Chips = ({ items, cls }: { items: string[]; cls: string }) => (
  <div className="flex flex-wrap gap-1.5">{items.map((i) => <Pill key={i} cls={cls}>{i}</Pill>)}</div>
);
