"use client";

// app/audit/page.tsx — v2.0 · Modo auditoría
// Hallazgos de auditoría por control ISO/IEC 27001:2022 (con su salvaguarda CIS v8):
// condición probada por la evidencia, causa probable a verificar y seguimiento con plazo.

import { useCallback, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import AppShell from "@/components/siem/AppShell";
import { Banner, Card, ImportPicker, NoAnalysis, Pill, Spinner, Stat, useSelectedImport } from "@/components/siem/ui";
import { API, SessionExpiredError, SEVERITY, SiemUser, apiFetch, fmtDateTime, getToken } from "@/lib/siem";

interface Finding {
  id: number; code: string; finding_type: "deficiencia" | "indicador"; severity: number; severity_label: string;
  iso_controls: string[]; cis_safeguards: string[]; iso_detail: { id: string; title: string }[];
  condition: string; effect: string | null; probable_cause: string; verification: string; recommendation: string;
  alert_ids: number[]; incident_ids: number[]; evidence_log_ids: string[];
  status: string; owner: string | null; due_date: string | null; mapping_version: number;
  closed_by?: string | null; verified_by?: string | null; verified_at?: string | null;
  incident_detail?: { id: number; title: string; severity: number }[];
  alert_detail?: { id: number; title: string; severity: number; rule_code: string | null }[];
}
interface HistoryRow {
  changed_at: string; changed_by: string; changed_role: string; old_status: string | null; new_status: string | null;
  old_owner: string | null; new_owner: string | null; note: string | null;
}
interface Control { id: string; title: string; severity: number; findings: string[] }
interface AuditData { total: number; deficiencies: number; indicators: number; controls: Control[]; findings: Finding[] }

const STATUS: Record<string, { label: string; cls: string }> = {
  abierto:        { label: "Abierto",        cls: "bg-white/[0.05] text-[#CBD5E1] border-white/10" },
  en_remediacion: { label: "En remediación", cls: "bg-yellow-500/10 text-yellow-200 border-yellow-500/25" },
  cerrado:        { label: "Cerrado",        cls: "bg-blue-500/10 text-blue-200 border-blue-500/25" },
  verificado:     { label: "Verificado",     cls: "bg-green-500/10 text-green-200 border-green-500/25" },
};
const TYPE: Record<string, { label: string; cls: string; hint: string }> = {
  deficiencia: { label: "Deficiencia", cls: "bg-red-500/10 text-red-200 border-red-500/20", hint: "Un control falló o no existe" },
  indicador:   { label: "Indicador",   cls: "bg-purple-500/10 text-purple-200 border-purple-500/20", hint: "Actividad sospechosa que por sí sola no demuestra un fallo de control" },
};
const CAN_GENERATE = ["admin", "auditor"];
const MANAGE_ROLES = ["admin", "auditor", "responder", "analyst"];
const VERIFY_ROLES = ["admin", "auditor"];
const TRANSITIONS: Record<string, string[]> = {
  abierto: ["en_remediacion"], en_remediacion: ["cerrado"], cerrado: ["verificado", "en_remediacion"], verificado: [],
};

// Fecha DD/MM/AAAA a partir de "AAAA-MM-DD..." (sin conversión de zona: es una fecha de calendario)
const fmtDate = (d: string | null) => (d ? `${d.slice(8, 10)}/${d.slice(5, 7)}/${d.slice(0, 4)}` : "—");
const isOverdue = (f: Finding) =>
  !!f.due_date && !["cerrado", "verificado"].includes(f.status) && f.due_date.slice(0, 10) < new Date().toISOString().slice(0, 10);

export default function AuditPage() {
  return (
    <AppShell title="Auditoría" subtitle="Hallazgos de auditoría por control ISO/IEC 27001:2022 y CIS v8, con su evidencia y plazo de remediación">
      {(user) => <AuditView user={user} />}
    </AppShell>
  );
}

function AuditView({ user }: { user: SiemUser | null }) {
  const router = useRouter();
  const { imports, selected, select, error: importsError } = useSelectedImport();
  const [data, setData] = useState<AuditData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState<string | null>(null);
  const canGenerate = CAN_GENERATE.includes((user?.role || "").toLowerCase());

  const call = useCallback(async (method: "GET" | "POST") => {
    if (!selected) return;
    setError(null);
    try {
      const r = await apiFetch<AuditData>(method === "GET" ? `/imports/${selected}/audit-findings` : `/imports/${selected}/audit`, { method });
      if (r.ok && Array.isArray(r.data?.findings)) setData(r.data);
      else setError(r.data?.error || "No se pudieron cargar los hallazgos de auditoría");
    } catch (e) {
      if (e instanceof SessionExpiredError) router.replace("/login");
      else setError("Error inesperado al cargar los hallazgos de auditoría");
    }
  }, [selected, router]);

  useEffect(() => { setData(null); setOpen(null); call("GET"); }, [call]);

  const generate = async () => { setBusy(true); await call("POST"); setBusy(false); };

  // Descarga el informe de auditoría en PDF (necesita el token, por eso no es un enlace directo)
  const [pdfBusy, setPdfBusy] = useState(false);
  const downloadPdf = async () => {
    if (!selected) return;
    setError(null); setPdfBusy(true);
    try {
      const res = await fetch(`${API}/imports/${selected}/audit-report.pdf`, { headers: { Authorization: `Bearer ${getToken()}` } });
      if (res.status === 401) { router.replace("/login"); return; }
      if (!res.ok) { setError((await res.json().catch(() => null))?.error || "No se pudo generar el informe de auditoría"); return; }
      const blob = await res.blob();
      const name = /filename="([^"]+)"/.exec(res.headers.get("Content-Disposition") || "")?.[1] || `informe-auditoria-${selected}.pdf`;
      const url = URL.createObjectURL(blob);
      const a = Object.assign(document.createElement("a"), { href: url, download: name });
      document.body.appendChild(a); a.click(); a.remove();
      URL.revokeObjectURL(url);
    } catch {
      setError("Error inesperado al descargar el informe de auditoría");
    } finally {
      setPdfBusy(false);
    }
  };

  const stats = useMemo(() => {
    const f = data?.findings || [];
    return {
      critical: f.filter((x) => x.severity === 5).length,
      overdue: f.filter(isOverdue).length,
    };
  }, [data]);

  const goTo = (code: string) => {
    setOpen(code);
    setTimeout(() => document.getElementById(`af-${code}`)?.scrollIntoView({ behavior: "smooth", block: "start" }), 50);
  };

  if (imports === null) return <p className="text-[13px] text-[#94A3B8]">Cargando…</p>;
  if (importsError) return <Banner tone="error">{importsError}</Banner>;
  if (!imports.length) return <NoAnalysis />;

  return (
    <div className="max-w-[1180px] mx-auto space-y-5">
      <div className="flex items-center justify-between gap-3">
        <ImportPicker imports={imports} selected={selected} onChange={select} />
        <div className="flex items-center gap-2">
          {!!data?.total && (
            <button onClick={downloadPdf} disabled={pdfBusy}
              className="flex items-center gap-2 border border-white/[0.15] hover:bg-white/[0.06] disabled:opacity-60 text-[#E2E8F0] text-[13px] font-semibold px-4 py-2 rounded-lg transition-colors">
              {pdfBusy && <Spinner />}Informe de auditoría (PDF)
            </button>
          )}
          {canGenerate ? (
            <button onClick={generate} disabled={busy}
              className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-60 text-white text-[13px] font-semibold px-4 py-2 rounded-lg transition-colors">
              {busy && <Spinner />}{data?.total ? "Regenerar hallazgos" : "Generar hallazgos"}
            </button>
          ) : (
            <p className="text-[12px] text-[#94A3B8]">Solo los roles admin y auditor generan hallazgos.</p>
          )}
        </div>
      </div>

      {error && <Banner tone="error">{error}</Banner>}

      <Banner tone="info">
        La <b>condición</b> está probada por los registros importados; la <b>causa probable</b> es una hipótesis que se confirma
        con el procedimiento de <b>verificación</b>. Regenerar conserva el estado, el responsable y la fecha de cada hallazgo.
      </Banner>

      <div className="grid grid-cols-5 gap-3">
        <Stat label="Hallazgos" value={data ? data.total : "…"} />
        <Stat label="Deficiencias" value={data ? data.deficiencies : "…"} color={SEVERITY[4].color} />
        <Stat label="Indicadores" value={data ? data.indicators : "…"} />
        <Stat label="Controles afectados" value={data ? data.controls.length : "…"} />
        <Stat label="Críticos" value={data ? stats.critical : "…"} color={SEVERITY[5].color}
          hint={data && stats.overdue ? `${stats.overdue} vencido(s)` : undefined} />
      </div>

      {data === null && !error ? (
        <p className="text-[13px] text-[#94A3B8] flex items-center gap-2"><Spinner /> Cargando…</p>
      ) : data && data.total === 0 ? (
        <Banner tone="warn">
          Aún no hay hallazgos de auditoría para esta importación.{" "}
          {canGenerate ? "Pulsa «Generar hallazgos»." : "Pide a un usuario admin o auditor que los genere."}
        </Banner>
      ) : data && (
        <>
          <ControlMatrix controls={data.controls} onPick={goTo} />
          <div className="space-y-3">
            {data.findings.map((f) => (
              <FindingCard key={f.code} f={f} importId={selected} open={open === f.code} user={user}
                onToggle={() => setOpen(open === f.code ? null : f.code)} onChanged={() => call("GET")} />
            ))}
          </div>
        </>
      )}
    </div>
  );
}

function ControlMatrix({ controls, onPick }: { controls: Control[]; onPick: (code: string) => void }) {
  return (
    <Card title="Controles ISO/IEC 27001:2022 con hallazgos"
      right={<span className="text-[11px] text-[#94A3B8]">Ordenados por la criticidad de su peor hallazgo</span>}>
      <table className="w-full text-[12px]">
        <thead>
          <tr className="border-b border-white/[0.07]">
            <th className="text-left px-5 py-2.5 font-mono text-[10px] tracking-[0.1em] uppercase text-[#94A3B8] font-medium w-[70px]">Control</th>
            <th className="text-left px-3 py-2.5 font-mono text-[10px] tracking-[0.1em] uppercase text-[#94A3B8] font-medium">Título</th>
            <th className="text-left px-3 py-2.5 font-mono text-[10px] tracking-[0.1em] uppercase text-[#94A3B8] font-medium w-[100px]">Criticidad</th>
            <th className="text-left px-5 py-2.5 font-mono text-[10px] tracking-[0.1em] uppercase text-[#94A3B8] font-medium">Hallazgos</th>
          </tr>
        </thead>
        <tbody>
          {controls.map((c) => (
            <tr key={c.id} className="border-b border-white/[0.04] last:border-0">
              <td className="px-5 py-2.5 font-mono font-semibold">{c.id}</td>
              <td className="px-3 py-2.5">{c.title}</td>
              <td className="px-3 py-2.5"><Pill cls={SEVERITY[c.severity]?.cls || ""}>{SEVERITY[c.severity]?.label}</Pill></td>
              <td className="px-5 py-2.5">
                <div className="flex flex-wrap gap-1.5">
                  {c.findings.map((code) => (
                    <button key={code} onClick={() => onPick(code)}
                      className="font-mono text-[10px] font-semibold px-2 py-0.5 rounded border border-white/10 bg-white/[0.04] hover:bg-blue-500/15 hover:border-blue-500/40 transition-colors">
                      {code}
                    </button>
                  ))}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}

function FindingCard({ f, importId, open, onToggle, user, onChanged }:
  { f: Finding; importId: string | null; open: boolean; onToggle: () => void; user: SiemUser | null; onChanged: () => void }) {
  const s = SEVERITY[f.severity];
  const st = STATUS[f.status] || STATUS.abierto;
  const overdue = isOverdue(f);
  const shown = f.evidence_log_ids.slice(0, 12);

  return (
    <div id={`af-${f.code}`} className="scroll-mt-4">
      <section className={`bg-white/[0.025] border rounded-2xl overflow-hidden ${open ? "border-blue-500/40" : "border-white/[0.07]"}`}>
        <button onClick={onToggle} aria-expanded={open}
          className="w-full flex items-center gap-3 px-5 py-3.5 text-left hover:bg-white/[0.03] transition-colors">
          <span className="w-1 self-stretch rounded-full" style={{ background: s?.color }} aria-hidden />
          <span className="font-mono text-[13px] font-semibold w-[64px] flex-shrink-0">{f.code}</span>
          <Pill cls={s?.cls || ""}>{s?.label}</Pill>
          <Pill cls={TYPE[f.finding_type].cls} title={TYPE[f.finding_type].hint}>{TYPE[f.finding_type].label}</Pill>
          <span className="flex flex-wrap gap-1.5 min-w-0 flex-1">
            {f.iso_detail.map((c) => (
              <span key={c.id} className="text-[11px] text-[#CBD5E1] truncate"><b className="font-mono">{c.id}</b> {c.title}</span>
            )).reduce<React.ReactNode[]>((acc, el, i) => (i ? [...acc, <span key={`s${i}`} className="text-[#94A3B8]">·</span>, el] : [el]), [])}
          </span>
          <span className="font-mono text-[11px] whitespace-nowrap" style={{ color: overdue ? SEVERITY[5].color : "#94A3B8" }}>
            {overdue ? "Vencido · " : "Vence "}{fmtDate(f.due_date)}
          </span>
          <Pill cls={st.cls}>{st.label}</Pill>
          <span className="text-[#94A3B8] text-[12px]" aria-hidden>{open ? "▲" : "▼"}</span>
        </button>

        {open && (
          <div className="px-5 pb-5 pt-1 grid grid-cols-2 gap-x-6 gap-y-4 text-[12.5px] leading-relaxed border-t border-white/[0.06]">
            <Attr label="Condición" tag="Probada por la evidencia" tagCls="text-green-300" wide>{f.condition}</Attr>
            <Attr label="Criterio">
              <ul className="space-y-0.5">
                {f.iso_detail.map((c) => <li key={c.id}>ISO/IEC 27001:2022 · <b className="font-mono">{c.id}</b> {c.title}</li>)}
                <li className="text-[#94A3B8]">CIS Controls v8 · {f.cis_safeguards.join(", ")}</li>
              </ul>
            </Attr>
            <Attr label="Efecto">{f.effect || "—"}</Attr>
            <Attr label="Causa probable" tag="Hipótesis: verificar" tagCls="text-yellow-300">{f.probable_cause}</Attr>
            <Attr label="Procedimiento de verificación">{f.verification}</Attr>
            <Attr label="Recomendación" wide>{f.recommendation}</Attr>

            <div className="col-span-2 grid grid-cols-2 gap-x-6 gap-y-3 pt-1">
              {!!f.incident_ids.length && (
                <DetailLinks label="Incidentes" items={(f.incident_detail?.length ? f.incident_detail : f.incident_ids.map((id) => ({ id, title: "", severity: 0 })))
                  .map((i) => ({ key: String(i.id), code: `#${i.id}`, title: i.title, severity: i.severity, href: `/incidents?import=${importId}&incident=${i.id}` }))} />
              )}
              {!!f.alert_ids.length && (
                <DetailLinks label="Alertas" items={(f.alert_detail?.length ? f.alert_detail : f.alert_ids.map((id) => ({ id, title: "", severity: 0, rule_code: null })))
                  .map((a) => ({ key: String(a.id), code: `#${a.id}${a.rule_code ? ` · ${a.rule_code}` : ""}`, title: a.title, severity: a.severity, href: `/alerts?import=${importId}&alert=${a.id}` }))} />
              )}
              <div className="col-span-2">
                <p className="font-mono text-[10px] uppercase tracking-[0.1em] text-[#94A3B8] mb-1.5">
                  Evidencia ({f.evidence_log_ids.length} {f.evidence_log_ids.length === 1 ? "registro" : "registros"})
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {shown.map((id) => (
                    <a key={id} href={`/events?import=${importId}&q=${encodeURIComponent(id)}`} title="Ver la fila original en Eventos"
                      className="font-mono text-[10px] font-semibold px-2 py-0.5 rounded border border-white/10 bg-white/[0.04] text-[#CBD5E1] hover:bg-blue-500/15 hover:border-blue-500/40 transition-colors">
                      {id}
                    </a>
                  ))}
                  {f.evidence_log_ids.length > shown.length && (
                    <span className="font-mono text-[10px] text-[#94A3B8] self-center">+{f.evidence_log_ids.length - shown.length} más</span>
                  )}
                </div>
              </div>
            </div>

            <p className="col-span-2 font-mono text-[10px] text-[#94A3B8]/70">
              Responsable: {f.owner || "sin asignar"}
              {f.closed_by ? ` · Cerrado por ${f.closed_by}` : ""}
              {f.verified_by ? ` · Verificado por ${f.verified_by}` : ""} · Catálogo de mapeo v{f.mapping_version}
            </p>

            <FollowUp f={f} user={user} onChanged={onChanged} />
          </div>
        )}
      </section>
    </div>
  );
}

const Attr = ({ label, tag, tagCls, wide, children }:
  { label: string; tag?: string; tagCls?: string; wide?: boolean; children: React.ReactNode }) => (
  <div className={wide ? "col-span-2" : ""}>
    <p className="font-mono text-[10px] uppercase tracking-[0.1em] text-[#94A3B8] mb-1">
      {label}{tag && <span className={`ml-2 normal-case tracking-normal ${tagCls}`}>{tag}</span>}
    </p>
    <div className="text-[#E2E8F0]">{children}</div>
  </div>
);

const DetailLinks = ({ label, items }:
  { label: string; items: { key: string; code: string; title: string; severity: number; href: string }[] }) => (
  <div className="min-w-0">
    <p className="font-mono text-[10px] uppercase tracking-[0.1em] text-[#94A3B8] mb-1.5">{label} ({items.length})</p>
    <ul className="space-y-1">
      {items.map((i) => (
        <li key={i.key}>
          <a href={i.href} className="flex items-center gap-2 rounded-lg px-2.5 py-1.5 border border-white/[0.07] bg-white/[0.02] hover:bg-blue-500/10 hover:border-blue-500/30 transition-colors">
            <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: SEVERITY[i.severity]?.color || "#94A3B8" }} aria-hidden />
            <span className="font-mono text-[10.5px] font-semibold text-blue-200 flex-shrink-0">{i.code}</span>
            <span className="text-[11.5px] text-[#CBD5E1] truncate">{i.title}</span>
            <span className="ml-auto text-[#94A3B8] text-[11px] flex-shrink-0" aria-hidden>→</span>
          </a>
        </li>
      ))}
    </ul>
  </div>
);

const LinkList = ({ label, items }: { label: string; items: { key: string; text: string; href: string }[] }) => (
  <div>
    <p className="font-mono text-[10px] uppercase tracking-[0.1em] text-[#94A3B8] mb-1.5">{label}</p>
    <div className="flex flex-wrap gap-1.5">
      {items.map((i) => (
        <a key={i.key} href={i.href}
          className="font-mono text-[10px] font-semibold px-2 py-0.5 rounded border border-blue-500/30 bg-blue-500/10 text-blue-200 hover:bg-blue-500/20 transition-colors">
          {i.text}
        </a>
      ))}
    </div>
  </div>
);

// ── Seguimiento: responsable, estado con nota de evidencia e historial inmutable ──
function FollowUp({ f, user, onChanged }: { f: Finding; user: SiemUser | null; onChanged: () => void }) {
  const router = useRouter();
  const role = (user?.role || "").toLowerCase();
  const canManage = MANAGE_ROLES.includes(role) && f.status !== "verificado";
  const [owner, setOwner] = useState(f.owner || "");
  const [next, setNext] = useState("");
  const [note, setNote] = useState("");
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState<{ tone: "error" | "ok"; text: string } | null>(null);
  const [history, setHistory] = useState<HistoryRow[] | null>(null);

  const loadHistory = useCallback(async () => {
    try {
      const r = await apiFetch<HistoryRow[]>(`/analysis/audit-findings/${f.id}/history`);
      setHistory(r.ok && Array.isArray(r.data) ? r.data : []);
    } catch (e) {
      if (e instanceof SessionExpiredError) router.replace("/login");
    }
  }, [f.id, router]);
  useEffect(() => { loadHistory(); }, [loadHistory]);
  useEffect(() => { setOwner(f.owner || ""); setNext(""); setNote(""); }, [f.owner, f.status]);

  const options = (TRANSITIONS[f.status] || []).filter((s) => s !== "verificado" || VERIFY_ROLES.includes(role));
  const selfVerify = next === "verificado" && !!f.closed_by && f.closed_by === user?.username;
  const needsNote = next === "cerrado" || next === "verificado" || (f.status === "cerrado" && next === "en_remediacion");

  const save = async () => {
    setSaving(true); setMsg(null);
    try {
      const body: Record<string, string> = {};
      if (owner.trim() !== (f.owner || "")) body.owner = owner.trim();
      if (next) body.status = next;
      if (note.trim()) body.note = note.trim();
      const r = await apiFetch<{ status: string }>(`/analysis/audit-findings/${f.id}`, { method: "PATCH", body: JSON.stringify(body) });
      if (!r.ok) { setMsg({ tone: "error", text: r.data?.error || "No se pudo guardar el cambio" }); return; }
      setMsg({ tone: "ok", text: "Cambio guardado y registrado en el historial." });
      await loadHistory();
      onChanged();
    } catch (e) {
      if (e instanceof SessionExpiredError) router.replace("/login");
      else setMsg({ tone: "error", text: "Error inesperado al guardar" });
    } finally {
      setSaving(false);
    }
  };

  const input = "w-full bg-[#0b1324] border border-white/[0.12] rounded-lg px-2.5 py-1.5 text-[12px] text-[#E2E8F0]";
  return (
    <div className="col-span-2 mt-1 pt-4 border-t border-white/[0.06] grid grid-cols-2 gap-6">
      <div>
        <p className="font-mono text-[10px] uppercase tracking-[0.1em] text-[#94A3B8] mb-2">Seguimiento</p>
        {!canManage ? (
          <p className="text-[12px] text-[#94A3B8]">
            {f.status === "verificado" ? "Hallazgo verificado: queda cerrado y no admite cambios." : "Tu rol puede consultar el seguimiento, pero no modificarlo."}
          </p>
        ) : (
          <div className="space-y-2.5">
            <label className="block text-[11px] text-[#94A3B8]">Responsable
              <input value={owner} onChange={(e) => setOwner(e.target.value)} maxLength={80} placeholder="Persona o equipo" className={`${input} mt-1`} />
            </label>
            <label className="block text-[11px] text-[#94A3B8]">Cambiar estado
              <select value={next} onChange={(e) => setNext(e.target.value)} className={`${input} mt-1`}>
                <option value="">Sin cambio ({STATUS[f.status]?.label || f.status})</option>
                {options.map((s) => (
                  <option key={s} value={s}>
                    {f.status === "cerrado" && s === "en_remediacion" ? "Rechazar cierre: volver a En remediación" : STATUS[s]?.label || s}
                  </option>
                ))}
              </select>
            </label>
            {(needsNote || note) && (
              <label className="block text-[11px] text-[#94A3B8]">Nota de evidencia {needsNote && <span className="text-yellow-300">(obligatoria, mín. 10 caracteres)</span>}
                <textarea value={note} onChange={(e) => setNote(e.target.value)} rows={3} maxLength={2000}
                  placeholder="Qué se hizo y dónde está la evidencia (ticket, captura, configuración revisada…)" className={`${input} mt-1`} />
              </label>
            )}
            {selfVerify && <Banner tone="warn">Segregación de funciones: cerraste este hallazgo, así que debe verificarlo otra persona.</Banner>}
            {msg && <Banner tone={msg.tone}>{msg.text}</Banner>}
            <button onClick={save} disabled={saving || selfVerify || (needsNote && note.trim().length < 10) || (!next && owner.trim() === (f.owner || ""))}
              className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-[12px] font-semibold px-3.5 py-1.5 rounded-lg transition-colors">
              {saving && <Spinner />}Guardar cambio
            </button>
          </div>
        )}
      </div>

      <div>
        <p className="font-mono text-[10px] uppercase tracking-[0.1em] text-[#94A3B8] mb-2">Historial (no editable)</p>
        {history === null ? <p className="text-[12px] text-[#94A3B8]">Cargando…</p>
          : history.length === 0 ? <p className="text-[12px] text-[#94A3B8]">Sin cambios desde que se generó el hallazgo.</p>
          : (
            <ol className="space-y-2">
              {history.map((h, i) => (
                <li key={i} className="text-[11.5px] leading-snug border-l-2 border-white/[0.1] pl-2.5">
                  <span className="font-mono text-[10px] text-[#94A3B8]">{fmtDateTime(h.changed_at)}</span>{" "}
                  <b>{h.changed_by}</b> <span className="text-[#94A3B8]">({h.changed_role})</span>
                  {h.old_status !== h.new_status && <> · {STATUS[h.old_status || ""]?.label || h.old_status} → <b>{STATUS[h.new_status || ""]?.label || h.new_status}</b></>}
                  {h.old_owner !== h.new_owner && <> · responsable: {h.new_owner || "sin asignar"}</>}
                  {h.note && (
                    <div className="mt-1 rounded-md px-2.5 py-1.5"
                      style={{ background: "rgba(234,179,8,0.08)", border: "1px solid rgba(234,179,8,0.28)", color: "#FEF3C7" }}>
                      <span className="font-mono text-[9.5px] uppercase tracking-[0.1em]" style={{ color: "#FACC15" }}>Nota de evidencia</span>
                      <div className="mt-0.5">“{h.note}”</div>
                    </div>
                  )}
                </li>
              ))}
            </ol>
          )}
      </div>
    </div>
  );
}
