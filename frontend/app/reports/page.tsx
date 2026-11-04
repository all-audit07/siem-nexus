"use client";

// app/reports/page.tsx — Informe técnico: generación (con o sin IA), consulta y exportación a PDF

import { ReactNode, useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import AppShell from "@/components/siem/AppShell";
import { Banner, Card, ImportPicker, NoAnalysis, Pill, Spinner, Stat, useSelectedImport } from "@/components/siem/ui";
import { API, SessionExpiredError, SEVERITY, SiemUser, apiFetch, clearSession, fmtDateTime, getToken } from "@/lib/siem";

// ── Tipos (reports.content) ──────────────────────────────────────
interface AiInfo { requested: boolean; used: boolean; model: string | null; errors: { section: string; problems: string[] }[]; note?: string | null }
interface Finding {
  id: string; title: string; severity: number; severity_label: string; period: { text: string };
  entities: { external_ips: string[]; actors: string[]; targeted: string[]; hosts: string[] };
  mitre_tactics: string[]; narrative: string; narrative_source: "reglas" | "ia";
  alerts: { id: string; rule_code: string; rule_name: string; severity: number; severity_label: string; title: string; justification: string; window: string; evidence: { log_id: string; role: string }[] }[];
  recommendations: string[];
}
interface ReportContent {
  meta: { title: string; generated_at: string; generated_by: string | null; import: { id: string; file_name: string; rows_rejected: number }; period: { text: string } };
  executive_summary: { text: string; source: "reglas" | "ia"; model?: string };
  scope: { events: number; hosts: number; users: number; external_sources: number; logon_failures: number; evidence_events: number };
  methodology: string[];
  risk_overview: { alerts: Record<string, number>; incidents: Record<string, number> };
  coverage: { category: string; label: string; rules: string[]; alerts: number; note: string }[];
  findings: Finding[]; hypotheses: string[]; limitations: string[];
  appendix: { rules: { code: string; name: string; category: string; severity: string; params: Record<string, number>; triggered: number }[]; evidence: unknown[] };
  ai: AiInfo;
}
interface ReportRow { id: string; title: string; ai_model: string | null; ai_generated_sections: string[] | null; created_at: string }
interface ReportFull extends ReportRow { content: ReportContent }

const SECTION_LABEL = (s: string) => (s === "executive_summary" ? "Resumen ejecutivo" : s.startsWith("incident:") ? `Incidente #${s.slice(9)}` : s);

export default function ReportsPage() {
  return (
    <AppShell title="Informes" subtitle="Informe técnico basado en los hallazgos, con exportación a PDF">
      {(user) => <ReportsView user={user} />}
    </AppShell>
  );
}

function ReportsView({ user }: { user: SiemUser | null }) {
  const router = useRouter();
  const { imports, selected, select, error: importsError } = useSelectedImport();
  const [reports, setReports] = useState<ReportRow[] | null>(null);
  const [current, setCurrent] = useState<ReportFull | null>(null);
  const [useAi, setUseAi] = useState(true);
  const [busy, setBusy] = useState<null | "generate" | "load" | `pdf-${string}`>(null);
  const [error, setError] = useState<string | null>(null);
  const [lastAi, setLastAi] = useState<AiInfo | null>(null);
  const canWrite = user?.role === "admin" || user?.role === "analyst";

  const call = useCallback(async <T,>(fn: () => Promise<T>): Promise<T | null> => {
    try { return await fn(); }
    catch (e) {
      if (e instanceof SessionExpiredError) router.replace("/login");
      else setError("Error inesperado. Revisa la consola del navegador.");
      return null;
    }
  }, [router]);

  const openReport = useCallback(async (id: string) => {
    setBusy("load");
    const r = await call(() => apiFetch<ReportFull>(`/analysis/reports/${id}`));
    setBusy(null);
    if (r?.ok) setCurrent(r.data); else if (r) setError(r.data?.error || "No se pudo abrir el informe");
  }, [call]);

  const loadList = useCallback(async (openFirst: boolean) => {
    if (!selected) return;
    const r = await call(() => apiFetch<ReportRow[]>(`/imports/${selected}/reports`));
    if (!r) return;
    if (r.ok && Array.isArray(r.data)) {
      setReports(r.data);
      if (openFirst && r.data[0]) openReport(r.data[0].id);
    } else setError(r.data?.error || "No se pudieron cargar los informes");
  }, [selected, call, openReport]);

  useEffect(() => { setReports(null); setCurrent(null); setLastAi(null); loadList(true); }, [loadList]);

  const generate = async () => {
    setError(null); setLastAi(null); setBusy("generate");
    const r = await call(() => apiFetch<{ id: string; ai: AiInfo }>(`/imports/${selected}/reports`, {
      method: "POST", body: JSON.stringify({ useAi }),
    }));
    setBusy(null);
    if (!r) return;
    if (!r.ok) { setError(r.data?.error || `No se pudo generar el informe (HTTP ${r.status})`); return; }
    setLastAi(r.data.ai);
    await loadList(false);
    openReport(r.data.id);
  };

  // Descarga el PDF con el token (no puede ser un enlace directo)
  const downloadPdf = async (id: string) => {
    setError(null); setBusy(`pdf-${id}`);
    try {
      const res = await fetch(`${API}/analysis/reports/${id}/pdf`, { headers: { Authorization: `Bearer ${getToken()}` } });
      if (res.status === 401 || res.status === 403) { clearSession(); router.replace("/login"); return; }
      if (!res.ok) { setError(`No se pudo generar el PDF (HTTP ${res.status})`); return; }
      const blob = await res.blob();
      const name = /filename="([^"]+)"/.exec(res.headers.get("Content-Disposition") || "")?.[1] || `informe-${id}.pdf`;
      const url = URL.createObjectURL(blob);
      const a = Object.assign(document.createElement("a"), { href: url, download: name });
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 2000);
    } catch {
      setError("No se pudo descargar el PDF");
    } finally { setBusy(null); }
  };

  if (imports === null) return <p className="text-[13px] text-[#94A3B8]">Cargando…</p>;
  if (importsError) return <Banner tone="error">{importsError}</Banner>;
  if (!imports.length) return <NoAnalysis />;

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between gap-3">
        <ImportPicker imports={imports} selected={selected} onChange={select} />
      </div>
      {error && <Banner tone="error">{error}</Banner>}

      <div className="grid grid-cols-[340px_minmax(0,1fr)] gap-5 items-start">
        <div className="space-y-5">
          {/* Generar */}
          <Card title="Generar informe">
            <div className="p-5 space-y-4">
              <label className={`flex items-start gap-3 rounded-xl border px-3.5 py-3 cursor-pointer ${useAi ? "border-blue-500/30 bg-blue-500/[0.06]" : "border-white/[0.08] bg-white/[0.02]"}`}>
                <input type="checkbox" checked={useAi} onChange={(e) => setUseAi(e.target.checked)} className="mt-0.5 accent-blue-500" />
                <span className="text-[12px] leading-relaxed">
                  <b className="text-[13px]">Redactar con IA (Claude)</b><br />
                  <span className="text-[#94A3B8]">Reescribe el resumen y la narrativa de cada incidente usando solo los hallazgos.
                    Si un texto cita un Log_ID, IP, cuenta o equipo que no está en la evidencia, se descarta y se conserva el de las reglas.</span>
                </span>
              </label>
              <button onClick={generate} disabled={!canWrite || busy !== null}
                className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg text-[13px] font-semibold bg-blue-600 hover:bg-blue-500 text-white disabled:opacity-40 disabled:cursor-not-allowed">
                {busy === "generate" && <Spinner />}
                {busy === "generate" ? (useAi ? "Generando y validando…" : "Generando…") : "Generar informe"}
              </button>
              {!canWrite && <p className="text-[11px] text-[#94A3B8]">Tu rol solo permite consultar informes.</p>}
              {lastAi?.requested && <AiOutcome ai={lastAi} />}
            </div>
          </Card>

          {/* Historial */}
          <Card title="Informes generados">
            {reports === null ? <p className="px-5 py-5 text-[12px] text-[#94A3B8] flex items-center gap-2"><Spinner /> Cargando…</p>
              : reports.length === 0 ? <p className="px-5 py-5 text-[12px] text-[#94A3B8]">Aún no hay informes para esta importación.</p>
              : (
                <ul className="divide-y divide-white/[0.05]">
                  {reports.map((r) => (
                    <li key={r.id} className={`px-4 py-3 ${current?.id === r.id ? "bg-blue-500/[0.07]" : ""}`}>
                      <div className="flex items-center gap-2">
                        <button onClick={() => openReport(r.id)} className="text-[13px] font-semibold hover:underline">Informe #{r.id}</button>
                        <span className="ml-auto font-mono text-[10px] text-[#94A3B8]">{fmtDateTime(r.created_at)}</span>
                      </div>
                      <div className="flex items-center gap-2 mt-1.5">
                        {r.ai_model
                          ? <Pill cls="bg-purple-500/10 text-purple-300 border-purple-500/25" title={(r.ai_generated_sections || []).map(SECTION_LABEL).join(", ")}>
                              IA · {r.ai_generated_sections?.length || 0} secciones
                            </Pill>
                          : <Pill cls="bg-white/[0.05] text-[#CBD5E1] border-white/10">Solo reglas</Pill>}
                        <button onClick={() => downloadPdf(r.id)} disabled={busy !== null}
                          className="ml-auto inline-flex items-center gap-1.5 text-[11px] font-semibold text-blue-300 hover:underline disabled:opacity-40">
                          {busy === `pdf-${r.id}` && <Spinner />}PDF ↓
                        </button>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
          </Card>
        </div>

        {/* Visor */}
        <div>
          {busy === "load" && !current ? <p className="text-[13px] text-[#94A3B8] flex items-center gap-2"><Spinner /> Abriendo…</p>
            : current ? <ReportViewer report={current} onPdf={() => downloadPdf(current.id)} pdfBusy={busy === `pdf-${current.id}`} />
            : <Card title="Vista del informe"><p className="px-5 py-6 text-[13px] text-[#94A3B8]">Genera un informe o selecciona uno de la lista.</p></Card>}
        </div>
      </div>
    </div>
  );
}

function AiOutcome({ ai }: { ai: AiInfo }) {
  if (!ai.used && ai.note) return <Banner tone="warn">{ai.note}{ai.errors[0] && <><br /><span className="font-mono text-[11px]">{ai.errors[0].problems.join("; ")}</span></>}</Banner>;
  return (
    <div className="space-y-2">
      <Banner tone="ok">Redacción con {ai.model}. Las secciones aceptadas se marcan como «IA» en el informe.</Banner>
      {ai.errors.length > 0 && (
        <Banner tone="warn">
          <b>Textos de la IA descartados por no ajustarse a la evidencia</b> (se mantuvo la redacción de las reglas):
          <ul className="mt-1.5 space-y-1">
            {ai.errors.map((e) => <li key={e.section}>· {SECTION_LABEL(e.section)}: {e.problems.join("; ")}</li>)}
          </ul>
        </Banner>
      )}
    </div>
  );
}

// ── Visor del informe ────────────────────────────────────────────
const H = ({ n, children }: { n: string; children: ReactNode }) => (
  <h3 className="flex items-baseline gap-2 text-[15px] font-semibold mt-7 mb-3 pb-2 border-b border-white/[0.07]">
    <span className="font-mono text-[12px] text-blue-300">{n}</span>{children}
  </h3>
);
const SourceTag = ({ source, model }: { source: "reglas" | "ia"; model?: string | null }) => source === "ia"
  ? <Pill cls="bg-purple-500/10 text-purple-300 border-purple-500/25" title="Validado contra la evidencia">IA{model ? ` · ${model}` : ""}</Pill>
  : <Pill cls="bg-white/[0.05] text-[#CBD5E1] border-white/10">Reglas</Pill>;

function ReportViewer({ report, onPdf, pdfBusy }: { report: ReportFull; onPdf: () => void; pdfBusy: boolean }) {
  const c = report.content;
  const [openInc, setOpenInc] = useState<string | null>(c.findings[0]?.id ?? null);
  useEffect(() => { setOpenInc(c.findings[0]?.id ?? null); }, [report.id, c.findings]);

  return (
    <Card title={<span className="truncate">Informe #{report.id} · {c.meta.import.file_name}</span>}
      right={<button onClick={onPdf} disabled={pdfBusy}
        className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-[12px] font-semibold bg-blue-600 hover:bg-blue-500 text-white disabled:opacity-50">
        {pdfBusy && <Spinner />}Descargar PDF
      </button>}>
      <div className="px-6 pb-6 max-h-[calc(100vh-200px)] overflow-y-auto text-[13px] leading-relaxed">
        <p className="mt-4 text-[12px] text-[#94A3B8]">
          Periodo de los registros: <span className="font-mono text-[#CBD5E1]">{c.meta.period.text}</span> (hora de Panamá) ·
          generado el {fmtDateTime(c.meta.generated_at)}{c.meta.generated_by ? ` por ${c.meta.generated_by}` : ""}
        </p>

        <H n="1">Resumen ejecutivo <span className="ml-auto"><SourceTag source={c.executive_summary.source} model={c.executive_summary.model} /></span></H>
        <p>{c.executive_summary.text}</p>
        <div className="grid grid-cols-4 gap-3 mt-4">
          {[5, 4, 3, 2].map((s) => (
            <Stat key={s} label={`Alertas · ${SEVERITY[s].label}`} value={c.risk_overview.alerts[s] || 0}
              hint={`${c.risk_overview.incidents[s] || 0} incidente(s)`} />
          ))}
        </div>

        <H n="2">Alcance de los datos</H>
        <p className="text-[#CBD5E1]">
          {c.scope.events} eventos · {c.scope.hosts} equipos · {c.scope.users} cuentas · {c.scope.external_sources} IPs externas de origen ·
          {" "}{c.scope.logon_failures} inicios de sesión fallidos · {c.scope.evidence_events} eventos usados como evidencia
          {c.meta.import.rows_rejected ? ` · ${c.meta.import.rows_rejected} filas rechazadas` : ""}.
        </p>

        <H n="3">Metodología</H>
        <ol className="list-decimal pl-5 space-y-1.5 text-[#CBD5E1]">{c.methodology.map((m) => <li key={m}>{m}</li>)}</ol>

        <H n="4">Cobertura de las detecciones solicitadas</H>
        <div className="rounded-xl border border-white/[0.07] overflow-hidden">
          {c.coverage.map((cv) => (
            <div key={cv.category} className="grid grid-cols-[170px_60px_minmax(0,1fr)] gap-3 px-4 py-2.5 border-b border-white/[0.05] last:border-0 text-[12px]">
              <span className="font-semibold">{cv.label}</span>
              <span className="font-mono">{cv.alerts}</span>
              <span className="text-[#94A3B8]">{cv.note}</span>
            </div>
          ))}
        </div>

        <H n="5">Hallazgos por incidente</H>
        <div className="space-y-2.5">
          {c.findings.map((f) => {
            const open = openInc === f.id;
            return (
              <div key={f.id} className="rounded-xl border border-white/[0.08] overflow-hidden">
                <button onClick={() => setOpenInc(open ? null : f.id)} aria-expanded={open}
                  className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-white/[0.03]">
                  <Pill cls={SEVERITY[f.severity].cls}>{f.severity_label}</Pill>
                  <span className="font-medium truncate">#{f.id} · {f.title}</span>
                  <span className="ml-auto font-mono text-[11px] text-[#94A3B8] whitespace-nowrap">{f.alerts.length} alertas {open ? "▾" : "▸"}</span>
                </button>
                {open && (
                  <div className="px-4 pb-4 space-y-3 border-t border-white/[0.06]">
                    <p className="pt-3 text-[12px] text-[#94A3B8]">
                      <span className="font-mono">{f.period.text}</span>
                      {f.entities.external_ips.length > 0 && <> · IPs: <span className="font-mono text-[#CBD5E1]">{f.entities.external_ips.join(", ")}</span></>}
                      {f.entities.actors.length > 0 && <> · Cuentas: <span className="font-mono text-[#CBD5E1]">{f.entities.actors.join(", ")}</span></>}
                      {f.entities.hosts.length > 0 && <> · Equipos: <span className="font-mono text-[#CBD5E1]">{f.entities.hosts.join(", ")}</span></>}
                    </p>
                    <div>
                      <p className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.12em] text-[#94A3B8] mb-1.5">Descripción <SourceTag source={f.narrative_source} /></p>
                      <p>{f.narrative}</p>
                    </div>
                    <div>
                      <p className="font-mono text-[10px] uppercase tracking-[0.12em] text-[#94A3B8] mb-1.5">Alertas y justificación</p>
                      <ul className="space-y-2">
                        {f.alerts.map((a) => (
                          <li key={a.id} className="rounded-lg bg-white/[0.02] border border-white/[0.06] px-3 py-2.5">
                            <p className="flex items-center gap-2"><Pill cls={SEVERITY[a.severity].cls}>{a.severity_label}</Pill>
                              <span className="font-mono text-[10px] text-[#94A3B8]">{a.rule_code}</span><span className="font-medium text-[12px]">{a.title}</span></p>
                            <p className="text-[12px] text-[#CBD5E1] mt-1.5">{a.justification}</p>
                          </li>
                        ))}
                      </ul>
                    </div>
                    {f.recommendations.length > 0 && (
                      <div>
                        <p className="font-mono text-[10px] uppercase tracking-[0.12em] text-[#94A3B8] mb-1.5">Recomendaciones</p>
                        <ul className="list-disc pl-5 space-y-1 text-[12px] text-[#CBD5E1]">{f.recommendations.map((r) => <li key={r}>{r}</li>)}</ul>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>

        <H n="6">Hipótesis a investigar (no confirmadas)</H>
        {c.hypotheses.length
          ? <ul className="list-disc pl-5 space-y-1.5 text-[#CBD5E1]">{c.hypotheses.map((h) => <li key={h}>{h}</li>)}</ul>
          : <p className="text-[#94A3B8]">No se identificaron relaciones entre incidentes que requieran investigación adicional.</p>}

        <H n="7">Limitaciones del análisis</H>
        <ul className="list-disc pl-5 space-y-1.5 text-[#CBD5E1]">{c.limitations.map((l) => <li key={l}>{l}</li>)}</ul>

        <p className="mt-6 text-[12px] text-[#94A3B8]">
          El PDF incluye además el anexo A ({c.appendix.rules.length} reglas con sus umbrales) y el anexo B ({c.appendix.evidence.length} registros citados como evidencia).
        </p>
      </div>
    </Card>
  );
}
