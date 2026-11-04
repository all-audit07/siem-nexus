"use client";

// app/events/page.tsx — Explorador de los registros importados (visualización completa del Excel)

import { Fragment, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import AppShell from "@/components/siem/AppShell";
import { Banner, Card, ImportPicker, NoAnalysis, Pill, ROLE, Spinner, useSelectedImport } from "@/components/siem/ui";

// Celdas compactas: la tabla tiene 12 columnas
const th = "text-left px-2.5 py-2.5 font-mono text-[10px] tracking-[0.08em] uppercase text-[#94A3B8] font-medium whitespace-nowrap";
const td = "px-2.5 py-2 align-top";
import { SessionExpiredError, SEVERITY, apiFetch, fmtDateTime, fmtNumber } from "@/lib/siem";

interface EventRow {
  id: string; log_id: string; occurred_at: string; event_type: string; event_code: string;
  severity: number; source_severity: string; hostname: string | null; user_name: string | null;
  source_ip: string | null; destination: string | null; log_source: string | null;
  description: string | null; command_line: string | null; result: string | null;
  raw_payload: Record<string, string>;
  alerts: { id: string; title: string; severity: number; role: keyof typeof ROLE; rule_code: string }[];
}

interface Facet { value: string; total: number }
interface EventsResponse {
  total: number; page: number; limit: number; rows: EventRow[];
  facets: { event_types: Facet[]; hosts: Facet[]; users: Facet[]; log_sources: Facet[] };
}

type Filters = { q: string; type: string; host: string; user: string; source: string; ip: string; severity: string; flagged: "" | "true" | "false" };
const EMPTY: Filters = { q: "", type: "", host: "", user: "", source: "", ip: "", severity: "", flagged: "" };
const SENSOR_SEVERITY: Record<string, string> = { "4": "High", "3": "Medium", "2": "Warning", "1": "Informational" };
const LIMIT = 50;

// Orden de columnas del Excel (JSONB no conserva el orden original de las claves)
const EXCEL_ORDER = ["Log_ID", "Timestamp", "Hostname", "Event_ID", "User", "Source_IP", "Destination",
  "Log_Source", "Event_Description", "Process_CommandLine", "Result", "Severity"];
const orderedEntries = (raw: Record<string, string>) => {
  const known = EXCEL_ORDER.filter((k) => k in raw).map((k) => [k, raw[k]] as const);
  const extra = Object.entries(raw).filter(([k]) => !EXCEL_ORDER.includes(k));
  return [...known, ...extra];
};

export default function EventsPage() {
  return (
    <AppShell title="Eventos" subtitle="Todos los registros importados del Excel, normalizados y con su fila original">
      {() => <EventsView />}
    </AppShell>
  );
}

function EventsView() {
  const router = useRouter();
  const { imports, selected, select, error: importsError } = useSelectedImport();
  const [filters, setFilters] = useState<Filters>(EMPTY);
  const [debouncedQ, setDebouncedQ] = useState("");
  const [page, setPage] = useState(1);
  const [data, setData] = useState<EventsResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);

  // Filtros iniciales desde la URL (p. ej. ?ip=203.0.113.74 desde el dashboard)
  useEffect(() => {
    const p = new URLSearchParams(window.location.search);
    const init = { ...EMPTY };
    (Object.keys(EMPTY) as (keyof Filters)[]).forEach((k) => { const v = p.get(k); if (v) (init[k] as string) = v; });
    setFilters(init);
    setDebouncedQ(init.q);
  }, []);

  useEffect(() => {
    const id = setTimeout(() => setDebouncedQ(filters.q), 300);
    return () => clearTimeout(id);
  }, [filters.q]);

  const query = useMemo(() => {
    const p = new URLSearchParams({ page: String(page), limit: String(LIMIT) });
    const f = { ...filters, q: debouncedQ };
    (Object.keys(f) as (keyof Filters)[]).forEach((k) => { if (f[k]) p.set(k, f[k]); });
    return p.toString();
  }, [filters, debouncedQ, page]);

  useEffect(() => {
    if (!selected) return;
    let cancelled = false;
    setLoading(true); setError(null);
    (async () => {
      try {
        const r = await apiFetch<EventsResponse>(`/imports/${selected}/events?${query}`);
        if (cancelled) return;
        if (r.ok) setData(r.data); else setError(r.data?.error || "No se pudieron cargar los eventos");
      } catch (e) {
        if (e instanceof SessionExpiredError) router.replace("/login");
        else if (!cancelled) setError("Error inesperado al cargar los eventos");
      } finally { if (!cancelled) setLoading(false); }
    })();
    return () => { cancelled = true; };
  }, [selected, query, router]);

  const set = (k: keyof Filters, v: string) => { setFilters((f) => ({ ...f, [k]: v })); setPage(1); setOpen(null); };
  const active = (Object.keys(filters) as (keyof Filters)[]).filter((k) => filters[k]).length;
  const pages = data ? Math.max(1, Math.ceil(data.total / LIMIT)) : 1;

  if (imports === null) return <p className="text-[13px] text-[#94A3B8]">Cargando…</p>;
  if (importsError) return <Banner tone="error">{importsError}</Banner>;
  if (!imports.length) return <NoAnalysis />;

  const select_ = "bg-[#0b1324] border border-white/[0.12] rounded-lg px-2.5 py-1.5 text-[12px] max-w-[190px]";
  const facet = (k: keyof Filters, label: string, list?: Facet[]) => (
    <select aria-label={label} value={filters[k]} onChange={(e) => set(k, e.target.value)} className={select_}>
      <option value="">{label}</option>
      {list?.map((f) => <option key={f.value} value={f.value}>{f.value} ({f.total})</option>)}
    </select>
  );

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2.5">
        <ImportPicker imports={imports} selected={selected} onChange={(id) => { select(id); setPage(1); setFilters(EMPTY); }} />
        <input value={filters.q} onChange={(e) => set("q", e.target.value)} placeholder="Buscar Log_ID, comando, descripción, IP…"
          className="flex-1 min-w-[220px] bg-[#0b1324] border border-white/[0.12] rounded-lg px-3 py-1.5 text-[12px] placeholder:text-[#64748B]" />
      </div>
      <div className="flex flex-wrap items-center gap-2.5">
        {facet("type", "Tipo de evento", data?.facets.event_types)}
        {facet("host", "Equipo", data?.facets.hosts)}
        {facet("user", "Usuario", data?.facets.users)}
        {facet("source", "Fuente", data?.facets.log_sources)}
        <input value={filters.ip} onChange={(e) => set("ip", e.target.value)} placeholder="IP exacta"
          className="w-[140px] bg-[#0b1324] border border-white/[0.12] rounded-lg px-2.5 py-1.5 font-mono text-[12px] placeholder:text-[#64748B]" />
        <select aria-label="Severidad del sensor" value={filters.severity} onChange={(e) => set("severity", e.target.value)} className={select_}>
          <option value="">Severidad del sensor</option>
          {Object.entries(SENSOR_SEVERITY).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </select>
        <select aria-label="Relación con alertas" value={filters.flagged} onChange={(e) => set("flagged", e.target.value)} className={select_}>
          <option value="">Todos los eventos</option>
          <option value="true">Solo evidencia de alertas</option>
          <option value="false">Sin relación con alertas</option>
        </select>
        {active > 0 && (
          <button onClick={() => { setFilters(EMPTY); setDebouncedQ(""); setPage(1); }}
            className="text-[12px] text-blue-300 hover:underline">Limpiar filtros ({active})</button>
        )}
      </div>

      {error && <Banner tone="error">{error}</Banner>}

      <Card
        title={<>Registros {data && <span className="font-mono text-[11px] text-[#94A3B8] font-normal">({fmtNumber(data.total)}{active ? " con filtros" : ""})</span>}</>}
        right={loading ? <Spinner /> : <span className="font-mono text-[11px] text-[#94A3B8]">Hora de Panamá (UTC−05:00)</span>}>
        {!data ? (
          <p className="px-5 py-6 text-[13px] text-[#94A3B8] flex items-center gap-2"><Spinner /> Cargando…</p>
        ) : data.rows.length === 0 ? (
          <p className="px-5 py-6 text-[13px] text-[#94A3B8]">Ningún registro coincide con los filtros.</p>
        ) : (
          <div className={`overflow-x-auto transition-opacity ${loading ? "opacity-50" : ""}`}>
            <table className="w-full text-[12px]">
              <thead><tr className="border-b border-white/[0.07] bg-white/[0.02]">
                {["", "Log_ID", "Fecha", "Equipo", "Event_ID · tipo", "Usuario", "IP origen", "Destino", "Resultado", "Sev. sensor", "Alertas"].map((h, i) =>
                  <th key={i} className={th}>{h}</th>)}
              </tr></thead>
              <tbody>
                {data.rows.map((e) => {
                  const isOpen = open === e.id;
                  const top = e.alerts[0];
                  return (
                    <Fragment key={e.id}>
                      <tr onClick={() => setOpen(isOpen ? null : e.id)}
                        className={`border-b border-white/[0.04] cursor-pointer ${isOpen ? "bg-blue-500/[0.07]" : "hover:bg-white/[0.03]"}`}>
                        <td className={`${td} text-[#94A3B8] w-5 !pr-0`} aria-hidden>{isOpen ? "▾" : "▸"}</td>
                        <td className={`${td} font-mono whitespace-nowrap`}>
                          <button aria-expanded={isOpen} className="hover:underline">{e.log_id}</button>
                        </td>
                        <td className={`${td} font-mono whitespace-nowrap text-[#94A3B8]`}>{fmtDateTime(e.occurred_at)}</td>
                        <td className={`${td} font-mono whitespace-nowrap`}>{e.hostname || "—"}</td>
                        <td className={`${td} font-mono whitespace-nowrap`}>
                          <span className="text-[#CBD5E1]">{e.event_code}</span>
                          <span className="block text-[10px] text-blue-300">{e.event_type}</span>
                        </td>
                        <td className={`${td} font-mono whitespace-nowrap`}>{e.user_name || "—"}</td>
                        <td className={`${td} font-mono whitespace-nowrap`}>{e.source_ip || "—"}</td>
                        <td className={`${td} font-mono whitespace-nowrap max-w-[120px] truncate`} title={e.destination || ""}>{e.destination || "—"}</td>
                        <td className={`${td} font-mono`}>{e.result || "—"}</td>
                        <td className={td}><Pill cls={SEVERITY[e.severity]?.cls || ""}>{e.source_severity}</Pill></td>
                        <td className={td}>
                          {top ? <Pill cls={SEVERITY[top.severity].cls} title={e.alerts.map((a) => a.title).join("\n")}>
                            {e.alerts.length} · {SEVERITY[top.severity].label}
                          </Pill> : <span className="text-[#475569]">—</span>}
                        </td>
                      </tr>
                      {isOpen && (
                        <tr className="bg-[#08101f] border-b border-white/[0.06]">
                          <td />
                          <td colSpan={10} className="px-4 py-4">
                            <EventDetail e={e} importId={selected} />
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {data && data.total > LIMIT && (
          <div className="flex items-center justify-between px-5 py-3 border-t border-white/[0.07] text-[12px]">
            <span className="text-[#94A3B8]">
              {fmtNumber((page - 1) * LIMIT + 1)}–{fmtNumber(Math.min(page * LIMIT, data.total))} de {fmtNumber(data.total)}
            </span>
            <div className="flex items-center gap-2">
              <PageBtn disabled={page === 1 || loading} onClick={() => { setPage(1); setOpen(null); }}>«</PageBtn>
              <PageBtn disabled={page === 1 || loading} onClick={() => { setPage(page - 1); setOpen(null); }}>Anterior</PageBtn>
              <span className="font-mono px-2">{page} / {pages}</span>
              <PageBtn disabled={page >= pages || loading} onClick={() => { setPage(page + 1); setOpen(null); }}>Siguiente</PageBtn>
              <PageBtn disabled={page >= pages || loading} onClick={() => { setPage(pages); setOpen(null); }}>»</PageBtn>
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}

const PageBtn = (p: React.ButtonHTMLAttributes<HTMLButtonElement>) => (
  <button {...p} className="px-3 py-1.5 rounded-lg bg-white/[0.04] border border-white/[0.09] hover:bg-white/[0.08] disabled:opacity-35 disabled:cursor-not-allowed" />
);

function EventDetail({ e, importId }: { e: EventRow; importId: string | null }) {
  return (
    <div className="grid grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)] gap-6">
      <div>
        <p className="font-mono text-[10px] uppercase tracking-[0.12em] text-[#94A3B8] mb-2">Fila original del Excel (sin modificar)</p>
        <dl className="grid grid-cols-[150px_minmax(0,1fr)] gap-x-3 gap-y-1.5 rounded-xl border border-white/[0.07] bg-white/[0.02] px-4 py-3">
          {orderedEntries(e.raw_payload).map(([k, v]) => (
            <Fragment key={k}>
              <dt className="font-mono text-[11px] text-[#94A3B8]">{k}</dt>
              <dd className="font-mono text-[11px] text-[#E2E8F0] break-words">{v === "" ? <span className="text-[#475569]">(vacío)</span> : v}</dd>
            </Fragment>
          ))}
        </dl>
      </div>
      <div>
        <p className="font-mono text-[10px] uppercase tracking-[0.12em] text-[#94A3B8] mb-2">
          Alertas que usan este registro como evidencia ({e.alerts.length})
        </p>
        {e.alerts.length === 0 ? (
          <p className="text-[12px] text-[#94A3B8] rounded-xl border border-white/[0.07] px-4 py-3">
            Ninguna regla usó este registro como evidencia.
          </p>
        ) : (
          <ul className="space-y-2">
            {e.alerts.map((a) => (
              <li key={a.id}>
                <a href={`/alerts?import=${importId}&alert=${a.id}`}
                  className="block rounded-xl border border-white/[0.07] bg-white/[0.02] hover:bg-white/[0.05] px-4 py-2.5">
                  <div className="flex items-center gap-2 mb-1">
                    <Pill cls={SEVERITY[a.severity].cls}>{SEVERITY[a.severity].label}</Pill>
                    <span className="font-mono text-[10px] text-[#94A3B8]">{a.rule_code}</span>
                    <Pill cls={ROLE[a.role].cls} title={ROLE[a.role].hint}>{ROLE[a.role].label}</Pill>
                  </div>
                  <p className="text-[12px] font-medium">{a.title}</p>
                </a>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
