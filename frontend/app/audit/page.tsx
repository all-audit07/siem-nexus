"use client";

// app/audit/page.tsx — v2.0 · Modo auditoría
// Hallazgos de auditoría por control ISO/IEC 27001:2022 (con su salvaguarda CIS v8):
// condición probada por la evidencia, causa probable a verificar y seguimiento con plazo.

import { useCallback, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import AppShell from "@/components/siem/AppShell";
import { Banner, Card, ImportPicker, NoAnalysis, Pill, Spinner, Stat, useSelectedImport } from "@/components/siem/ui";
import { SessionExpiredError, SEVERITY, SiemUser, apiFetch } from "@/lib/siem";

interface Finding {
  id: number; code: string; finding_type: "deficiencia" | "indicador"; severity: number; severity_label: string;
  iso_controls: string[]; cis_safeguards: string[]; iso_detail: { id: string; title: string }[];
  condition: string; effect: string | null; probable_cause: string; verification: string; recommendation: string;
  alert_ids: number[]; incident_ids: number[]; evidence_log_ids: string[];
  status: string; owner: string | null; due_date: string | null; mapping_version: number;
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
        {canGenerate ? (
          <button onClick={generate} disabled={busy}
            className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-60 text-white text-[13px] font-semibold px-4 py-2 rounded-lg transition-colors">
            {busy && <Spinner />}{data?.total ? "Regenerar hallazgos" : "Generar hallazgos"}
          </button>
        ) : (
          <p className="text-[12px] text-[#94A3B8]">Solo los roles admin y auditor generan hallazgos.</p>
        )}
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
              <FindingCard key={f.code} f={f} importId={selected} open={open === f.code}
                onToggle={() => setOpen(open === f.code ? null : f.code)} />
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

function FindingCard({ f, importId, open, onToggle }: { f: Finding; importId: string | null; open: boolean; onToggle: () => void }) {
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

            <div className="col-span-2 flex flex-wrap items-start gap-x-8 gap-y-3 pt-1">
              {!!f.incident_ids.length && (
                <LinkList label="Incidentes" items={f.incident_ids.map((id) => ({ key: String(id), text: `#${id}`, href: `/incidents?import=${importId}&incident=${id}` }))} />
              )}
              {!!f.alert_ids.length && (
                <LinkList label="Alertas" items={f.alert_ids.map((id) => ({ key: String(id), text: `#${id}`, href: `/alerts?import=${importId}&alert=${id}` }))} />
              )}
              <div>
                <p className="font-mono text-[10px] uppercase tracking-[0.1em] text-[#94A3B8] mb-1.5">
                  Evidencia ({f.evidence_log_ids.length} {f.evidence_log_ids.length === 1 ? "registro" : "registros"})
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {shown.map((id) => <Pill key={id} cls="bg-white/[0.04] text-[#CBD5E1] border-white/10">{id}</Pill>)}
                  {f.evidence_log_ids.length > shown.length && (
                    <span className="font-mono text-[10px] text-[#94A3B8] self-center">+{f.evidence_log_ids.length - shown.length} más</span>
                  )}
                </div>
              </div>
            </div>

            <p className="col-span-2 font-mono text-[10px] text-[#94A3B8]/70">
              Responsable: {f.owner || "sin asignar"} · Catálogo de mapeo v{f.mapping_version}
            </p>
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
