"use client";

// app/imports/page.tsx — Carga de archivos: vista previa, importación y análisis

import { DragEvent, ReactNode, useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import AppShell from "@/components/siem/AppShell";
import {
  SessionExpiredError, SEVERITY, SEVERITY_BY_LABEL, SiemUser, apiFetch, fmtDateTime, fmtNumber, getToken,
} from "@/lib/siem";

// ── Tipos de la API ──────────────────────────────────────────────
interface Rejected { row: number; log_id: string | null; motivos: string[] }

interface SampleEvent {
  source_log_id: string; event_type: string; event_code: string; severity: number;
  source_ip: string | null; hostname: string | null; user_name: string | null;
  description: string | null; command_line: string | null; result: string | null;
  source_severity: string | null; occurred_at: string;
}

interface Preview {
  fileName: string; sheetNames: string[]; sheetName: string; headers: string[];
  sourceTimezone: string; rowsTotal: number; rowsValid: number; rowsRejected: number;
  rejected: Rejected[]; sample: SampleEvent[];
  alreadyImported: { id: string; file_name: string; imported_at: string } | null;
}

interface ImportResult {
  id: string; fileName: string; sheetName: string; rowsTotal: number;
  rowsValid: number; rowsRejected: number; importedAt: string;
}

interface AnalysisResult {
  importId: number; analyzedAt: string; eventsAnalyzed: number; alerts: number;
  incidents: number; alertsBySeverity: Record<string, number>; rulesEvaluated: string[];
}

interface ImportRow {
  id: string; file_name: string; sheet_name: string; rows_total: number; rows_valid: number;
  rows_rejected: number; status: "pending" | "imported" | "analyzed" | "failed";
  imported_at: string; analyzed_at: string | null;
}

const STATUS: Record<ImportRow["status"], { label: string; cls: string }> = {
  pending:  { label: "Pendiente",  cls: "bg-white/[0.06] text-[#94A3B8] border-white/10" },
  imported: { label: "Importado",  cls: "bg-blue-500/12 text-blue-300 border-blue-500/25" },
  analyzed: { label: "Analizado",  cls: "bg-green-500/12 text-green-300 border-green-500/25" },
  failed:   { label: "Fallido",    cls: "bg-red-500/12 text-red-300 border-red-500/25" },
};

// ── Piezas de interfaz ───────────────────────────────────────────
const Card = ({ title, icon, right, children }: { title: string; icon?: ReactNode; right?: ReactNode; children: ReactNode }) => (
  <section className="bg-white/[0.025] border border-white/[0.07] rounded-2xl overflow-hidden backdrop-blur-sm shadow-[0_4px_24px_rgba(0,0,0,0.25)]">
    <div className="flex items-center justify-between gap-3 px-5 py-4 border-b border-white/[0.07] bg-white/[0.02]">
      <h2 className="flex items-center gap-2 text-[14px] font-semibold">{icon}{title}</h2>
      {right}
    </div>
    {children}
  </section>
);

const Stat = ({ label, value, color, hint }: { label: string; value: ReactNode; color?: string; hint?: string }) => (
  <div className="bg-white/[0.03] border border-white/[0.07] rounded-xl px-4 py-3.5">
    <div className="font-mono text-[26px] font-semibold leading-none tabular-nums" style={{ color }}>{value}</div>
    <div className="text-[11px] text-[#94A3B8] uppercase tracking-[0.08em] mt-2">{label}</div>
    {hint && <div className="font-mono text-[10px] text-[#94A3B8]/70 mt-1">{hint}</div>}
  </div>
);

const Pill = ({ cls, children }: { cls: string; children: ReactNode }) => (
  <span className={`inline-flex items-center font-mono text-[10px] font-semibold px-2 py-0.5 rounded border ${cls}`}>{children}</span>
);

const Banner = ({ tone, children }: { tone: "error" | "warn" | "ok" | "info"; children: ReactNode }) => {
  const cls = {
    error: "bg-red-500/[0.08] border-red-500/25 text-red-200",
    warn:  "bg-yellow-500/[0.08] border-yellow-500/25 text-yellow-100",
    ok:    "bg-green-500/[0.08] border-green-500/25 text-green-100",
    info:  "bg-blue-500/[0.08] border-blue-500/25 text-blue-100",
  }[tone];
  return <div role={tone === "error" ? "alert" : "status"} className={`rounded-xl border px-4 py-3 text-[13px] leading-relaxed ${cls}`}>{children}</div>;
};

const Btn = ({ kind = "primary", ...p }: React.ButtonHTMLAttributes<HTMLButtonElement> & { kind?: "primary" | "ghost" | "danger" }) => {
  const cls = {
    primary: "bg-blue-600 hover:bg-blue-500 text-white shadow-[0_0_20px_rgba(59,130,246,0.25)]",
    ghost:   "bg-white/[0.04] hover:bg-white/[0.08] text-[#E2E8F0] border border-white/[0.09]",
    danger:  "bg-red-500/10 hover:bg-red-500/20 text-red-300 border border-red-500/25",
  }[kind];
  return <button {...p} className={`inline-flex items-center justify-center gap-2 px-4 py-2 rounded-lg text-[13px] font-semibold transition-all disabled:opacity-40 disabled:cursor-not-allowed ${cls} ${p.className || ""}`} />;
};

const Spinner = () => <span className="w-3.5 h-3.5 border-2 border-white/25 border-t-white rounded-full animate-spin" aria-hidden />;

const th = "text-left px-4 py-2.5 font-mono text-[10px] tracking-[0.1em] uppercase text-[#94A3B8] font-medium whitespace-nowrap";
const td = "px-4 py-2.5 align-top";

// ── Página ───────────────────────────────────────────────────────
export default function ImportsPage() {
  return (
    <AppShell title="Importar logs" subtitle="Carga un archivo Excel (.xlsx), revisa la validación e impórtalo a PostgreSQL">
      {(user) => <ImportsView user={user} />}
    </AppShell>
  );
}

function ImportsView({ user }: { user: SiemUser | null }) {
  const router = useRouter();
  const inputRef = useRef<HTMLInputElement>(null);

  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [imported, setImported] = useState<ImportResult | null>(null);
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
  const [history, setHistory] = useState<ImportRow[] | null>(null);
  const [busy, setBusy] = useState<null | "preview" | "import" | `analyze-${string}` | `delete-${string}`>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);

  const isDemo = getToken() === "demo-token";
  const canWrite = user?.role === "admin" || user?.role === "analyst";
  const isAdmin = user?.role === "admin";

  // Ejecuta una llamada y gestiona la sesión expirada en un solo lugar
  const call = useCallback(async <T,>(fn: () => Promise<T>): Promise<T | null> => {
    try { return await fn(); }
    catch (e) {
      if (e instanceof SessionExpiredError) { router.replace("/login"); return null; }
      setError("Error inesperado. Revisa la consola del navegador.");
      console.error(e);
      return null;
    }
  }, [router]);

  const loadHistory = useCallback(async () => {
    if (isDemo) { setHistory([]); return; }
    const r = await call(() => apiFetch<ImportRow[]>("/imports"));
    if (!r) return;
    if (r.ok && Array.isArray(r.data)) setHistory(r.data);
    else setError(r.data?.error || "No se pudo cargar el historial");
  }, [call, isDemo]);

  useEffect(() => { loadHistory(); }, [loadHistory]);

  // ── Paso 1: elegir archivo → vista previa ──
  const runPreview = async (f: File, sheet?: string) => {
    setError(null); setPreview(null); setImported(null); setAnalysis(null);
    if (!/\.xlsx$/i.test(f.name)) { setError("Solo se aceptan archivos .xlsx"); return; }
    if (f.size > 10 * 1024 * 1024) { setError("El archivo supera 10 MB"); return; }
    setFile(f);
    setBusy("preview");
    const fd = new FormData();
    fd.append("file", f);
    if (sheet) fd.append("sheet", sheet);
    const r = await call(() => apiFetch<Preview>("/imports/preview", { method: "POST", body: fd }));
    setBusy(null);
    if (!r) return;
    if (r.ok) setPreview(r.data);
    else setError(r.data?.error || `No se pudo validar el archivo (HTTP ${r.status})`);
  };

  const onPick = (f?: File | null) => { if (f) runPreview(f); };
  const onDrop = (e: DragEvent<HTMLLabelElement>) => {
    e.preventDefault(); setDragging(false);
    onPick(e.dataTransfer.files?.[0]);
  };

  const reset = () => {
    setFile(null); setPreview(null); setImported(null); setAnalysis(null); setError(null);
    if (inputRef.current) inputRef.current.value = "";
  };

  // ── Paso 2: importar ──
  const runImport = async () => {
    if (!file || !preview) return;
    setError(null); setBusy("import");
    const fd = new FormData();
    fd.append("file", file);
    fd.append("sheet", preview.sheetName);
    const r = await call(() => apiFetch<ImportResult>("/imports", { method: "POST", body: fd }));
    setBusy(null);
    if (!r) return;
    if (r.ok) { setImported(r.data); loadHistory(); }
    else setError(r.data?.error || `No se pudo importar (HTTP ${r.status})`);
  };

  // ── Paso 3: analizar ──
  const runAnalysis = async (importId: string) => {
    setError(null); setBusy(`analyze-${importId}`);
    const r = await call(() => apiFetch<AnalysisResult>(`/imports/${importId}/analyze`, { method: "POST" }));
    setBusy(null);
    if (!r) return;
    if (r.ok) { setAnalysis(r.data); loadHistory(); }
    else setError(r.data?.error || `No se pudo analizar (HTTP ${r.status})`);
  };

  const runDelete = async (importId: string) => {
    setError(null); setBusy(`delete-${importId}`);
    const r = await call(() => apiFetch<{ deleted: boolean }>(`/imports/${importId}`, { method: "DELETE" }));
    setBusy(null); setConfirmDelete(null);
    if (!r) return;
    if (r.ok) {
      if (imported?.id === importId) { setImported(null); setAnalysis(null); }
      if (analysis && String(analysis.importId) === importId) setAnalysis(null);
      loadHistory();
    } else setError(r.data?.error || `No se pudo eliminar (HTTP ${r.status})`);
  };

  const step = analysis ? 3 : imported ? 2 : preview ? 1 : 0;

  return (
    <div className="max-w-[1180px] mx-auto space-y-5">
      {isDemo && (
        <Banner tone="warn">
          Estás en <b>modo demo</b> (sin backend). La importación necesita una sesión real: cierra sesión e inicia con una cuenta válida.
        </Banner>
      )}
      {!isDemo && user && !canWrite && (
        <Banner tone="info">Tu rol (<b>{user.role}</b>) solo permite consultar. Importar y analizar requiere rol analyst o admin.</Banner>
      )}
      {error && <Banner tone="error">{error}</Banner>}

      {/* Pasos */}
      <ol className="grid grid-cols-3 gap-3" aria-label="Progreso">
        {["Validar archivo", "Importar a PostgreSQL", "Analizar con reglas"].map((label, i) => {
          const done = step > i, current = step === i;
          return (
            <li key={label} className={`flex items-center gap-3 rounded-xl border px-4 py-3 ${done
              ? "border-green-500/25 bg-green-500/[0.05]" : current ? "border-blue-500/30 bg-blue-500/[0.06]" : "border-white/[0.07] bg-white/[0.02]"}`}>
              <span className={`w-6 h-6 rounded-full flex items-center justify-center font-mono text-[11px] font-bold ${done
                ? "bg-green-500/20 text-green-300" : current ? "bg-blue-500/20 text-blue-300" : "bg-white/[0.06] text-[#94A3B8]"}`}>
                {done ? "✓" : i + 1}
              </span>
              <span className={`text-[13px] font-medium ${done || current ? "text-[#E2E8F0]" : "text-[#94A3B8]"}`}>{label}</span>
            </li>
          );
        })}
      </ol>

      {/* Zona de carga */}
      {!preview && (
        <label
          onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          className={`block cursor-pointer rounded-2xl border-2 border-dashed px-6 py-14 text-center transition-all ${dragging
            ? "border-blue-400 bg-blue-500/[0.08]" : "border-white/[0.12] bg-white/[0.02] hover:border-blue-500/40 hover:bg-blue-500/[0.04]"}
            ${!canWrite || isDemo ? "pointer-events-none opacity-50" : ""}`}>
          <input ref={inputRef} type="file" accept=".xlsx,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            className="sr-only" disabled={!canWrite || isDemo || busy !== null}
            onChange={(e) => onPick(e.target.files?.[0])} />
          <div className="mx-auto w-12 h-12 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center mb-4">
            {busy === "preview" ? <Spinner /> : (
              <svg width="22" height="22" fill="none" viewBox="0 0 24 24" stroke="#3B82F6" strokeWidth={1.8} aria-hidden>
                <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v2a2 2 0 002 2h12a2 2 0 002-2v-2M12 4v12m0-12l-4 4m4-4l4 4" />
              </svg>
            )}
          </div>
          <p className="text-[15px] font-semibold">{busy === "preview" ? `Validando ${file?.name}…` : "Arrastra aquí el archivo Excel o haz clic para elegirlo"}</p>
          <p className="text-[12px] text-[#94A3B8] mt-1.5">Formato .xlsx · máximo 10 MB · se valida antes de guardar nada</p>
        </label>
      )}

      {/* Vista previa */}
      {preview && (
        <Card
          title="Resultado de la validación"
          right={
            <div className="flex items-center gap-3 min-w-0">
              <span className="font-mono text-[11px] text-[#94A3B8] truncate max-w-[380px]" title={preview.fileName}>{preview.fileName}</span>
              {!imported && <Btn kind="ghost" onClick={reset} disabled={busy !== null}>Elegir otro archivo</Btn>}
            </div>
          }>
          <div className="p-5 space-y-5">
            <div className="grid grid-cols-4 gap-3">
              <Stat label="Filas leídas" value={fmtNumber(preview.rowsTotal)} hint={`Hoja «${preview.sheetName}»`} />
              <Stat label="Válidas" value={fmtNumber(preview.rowsValid)} color="#22C55E" />
              <Stat label="Rechazadas" value={fmtNumber(preview.rowsRejected)} color={preview.rowsRejected ? "#EF4444" : "#94A3B8"} />
              <Stat label="Zona horaria" value={<span className="text-[15px]">UTC−05:00</span>} hint={preview.sourceTimezone} />
            </div>

            {preview.sheetNames.length > 1 && !imported && (
              <div className="flex items-center gap-3 text-[13px]">
                <label htmlFor="sheet" className="text-[#94A3B8]">Hoja a importar:</label>
                <select id="sheet" value={preview.sheetName} disabled={busy !== null}
                  onChange={(e) => file && runPreview(file, e.target.value)}
                  className="bg-[#0b1324] border border-white/[0.12] rounded-lg px-3 py-1.5 font-mono text-[12px]">
                  {preview.sheetNames.map((s) => <option key={s} value={s}>{s}</option>)}
                </select>
              </div>
            )}

            <div>
              <p className="font-mono text-[10px] uppercase tracking-[0.12em] text-[#94A3B8] mb-2">Columnas detectadas ({preview.headers.length})</p>
              <div className="flex flex-wrap gap-1.5">
                {preview.headers.map((h) => <Pill key={h} cls="bg-white/[0.04] text-[#CBD5E1] border-white/[0.08]">{h}</Pill>)}
              </div>
            </div>

            {preview.alreadyImported && !imported && (
              <Banner tone="warn">
                Este archivo ya se importó el {fmtDateTime(preview.alreadyImported.imported_at)} (importación #{preview.alreadyImported.id}).
                No se volverá a guardar; puedes analizarlo desde el historial.
              </Banner>
            )}

            {preview.rowsRejected > 0 && (
              <div>
                <p className="text-[13px] font-semibold text-red-300 mb-2">
                  Filas rechazadas — no se importarán{preview.rowsRejected > preview.rejected.length ? ` (se muestran ${preview.rejected.length} de ${preview.rowsRejected})` : ""}
                </p>
                <div className="rounded-xl border border-red-500/20 overflow-x-auto max-h-[260px]">
                  <table className="w-full text-[12px]">
                    <thead className="sticky top-0 bg-[#140c12]"><tr className="border-b border-red-500/15">
                      <th className={th}>Fila</th><th className={th}>Log_ID</th><th className={th}>Motivo</th>
                    </tr></thead>
                    <tbody>
                      {preview.rejected.map((r) => (
                        <tr key={r.row} className="border-b border-white/[0.04]">
                          <td className={`${td} font-mono`}>{r.row}</td>
                          <td className={`${td} font-mono`}>{r.log_id || "—"}</td>
                          <td className={`${td} text-red-200`}>{r.motivos.join(" · ")}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            <div>
              <p className="text-[13px] font-semibold mb-2">
                Muestra normalizada <span className="font-normal text-[#94A3B8]">— primeras {preview.sample.length} filas válidas, tal como se guardarán</span>
              </p>
              <div className="rounded-xl border border-white/[0.07] overflow-x-auto max-h-[340px]">
                <table className="w-full text-[12px]">
                  <thead className="sticky top-0 bg-[#0b1324]"><tr className="border-b border-white/[0.07]">
                    {["Log_ID", "Fecha (Panamá)", "Host", "Event_ID", "Tipo normalizado", "Usuario", "IP origen", "Sev. sensor", "Detalle"].map((h) => <th key={h} className={th}>{h}</th>)}
                  </tr></thead>
                  <tbody>
                    {preview.sample.map((e) => (
                      <tr key={e.source_log_id} className="border-b border-white/[0.04] hover:bg-blue-500/[0.04]">
                        <td className={`${td} font-mono whitespace-nowrap`}>{e.source_log_id}</td>
                        <td className={`${td} font-mono whitespace-nowrap text-[#94A3B8]`}>{fmtDateTime(e.occurred_at)}</td>
                        <td className={`${td} font-mono whitespace-nowrap`}>{e.hostname || "—"}</td>
                        <td className={`${td} font-mono`}>{e.event_code}</td>
                        <td className={`${td} font-mono text-blue-300 whitespace-nowrap`}>{e.event_type}</td>
                        <td className={`${td} font-mono whitespace-nowrap`}>{e.user_name || "—"}</td>
                        <td className={`${td} font-mono whitespace-nowrap`}>{e.source_ip || "—"}</td>
                        <td className={td}><Pill cls={SEVERITY[e.severity]?.cls || ""}>{e.source_severity}</Pill></td>
                        <td className={`${td} text-[#94A3B8] min-w-[220px]`}>{e.command_line || e.description || "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {!imported && (
              <div className="flex items-center justify-end gap-3 pt-1">
                <p className="text-[12px] text-[#94A3B8] mr-auto">
                  Se guardará la fila original completa de cada evento como evidencia.
                </p>
                <Btn onClick={runImport}
                  disabled={!canWrite || busy !== null || !!preview.alreadyImported || preview.rowsValid === 0}>
                  {busy === "import" && <Spinner />}
                  Importar {fmtNumber(preview.rowsValid)} eventos
                </Btn>
              </div>
            )}
          </div>
        </Card>
      )}

      {/* Importación completada → análisis */}
      {imported && (
        <Card title={`Importación #${imported.id} completada`}
          icon={<span className="w-2 h-2 rounded-full bg-green-400 shadow-[0_0_8px_#22C55E]" />}>
          <div className="p-5 space-y-4">
            <Banner tone="ok">
              Se guardaron <b>{fmtNumber(imported.rowsValid)}</b> eventos en PostgreSQL
              {imported.rowsRejected > 0 && <> y se descartaron <b>{imported.rowsRejected}</b> filas inválidas</>}.
              Ahora puedes ejecutar las reglas de detección sobre estos registros.
            </Banner>
            {!analysis && (
              <div className="flex justify-end">
                <Btn onClick={() => runAnalysis(imported.id)} disabled={!canWrite || busy !== null}>
                  {busy === `analyze-${imported.id}` && <Spinner />}
                  Ejecutar análisis de seguridad
                </Btn>
              </div>
            )}
          </div>
        </Card>
      )}

      {/* Resultado del análisis */}
      {analysis && <AnalysisSummary result={analysis} onNew={reset} />}

      {/* Historial */}
      <Card title="Historial de importaciones"
        right={<Btn kind="ghost" onClick={loadHistory} disabled={busy !== null}>Actualizar</Btn>}>
        {history === null ? (
          <p className="px-5 py-6 text-[13px] text-[#94A3B8]">Cargando…</p>
        ) : history.length === 0 ? (
          <p className="px-5 py-6 text-[13px] text-[#94A3B8]">Aún no hay importaciones.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-[13px]">
              <thead><tr className="border-b border-white/[0.07] bg-white/[0.02]">
                {["#", "Archivo", "Importado", "Eventos", "Rechazadas", "Estado", "Analizado", ""].map((h) => <th key={h} className={th}>{h}</th>)}
              </tr></thead>
              <tbody>
                {history.map((h) => (
                  <tr key={h.id} className="border-b border-white/[0.04] hover:bg-blue-500/[0.04]">
                    <td className={`${td} font-mono text-[#94A3B8]`}>{h.id}</td>
                    <td className={`${td} max-w-[260px]`}>
                      <p className="truncate font-medium" title={h.file_name}>{h.file_name}</p>
                      <p className="font-mono text-[10px] text-[#94A3B8]">{h.sheet_name}</p>
                    </td>
                    <td className={`${td} font-mono text-[12px] whitespace-nowrap text-[#94A3B8]`}>{fmtDateTime(h.imported_at)}</td>
                    <td className={`${td} font-mono tabular-nums`}>{fmtNumber(h.rows_valid)}</td>
                    <td className={`${td} font-mono tabular-nums ${h.rows_rejected ? "text-red-300" : "text-[#94A3B8]"}`}>{h.rows_rejected}</td>
                    <td className={td}><Pill cls={STATUS[h.status]?.cls || STATUS.pending.cls}>{STATUS[h.status]?.label || h.status}</Pill></td>
                    <td className={`${td} font-mono text-[12px] whitespace-nowrap text-[#94A3B8]`}>{fmtDateTime(h.analyzed_at)}</td>
                    <td className={`${td} whitespace-nowrap text-right`}>
                      <div className="inline-flex gap-2">
                        {canWrite && (
                          <Btn kind="ghost" className="!px-3 !py-1.5 !text-[12px]" disabled={busy !== null}
                            onClick={() => runAnalysis(h.id)}>
                            {busy === `analyze-${h.id}` && <Spinner />}
                            {h.status === "analyzed" ? "Re-analizar" : "Analizar"}
                          </Btn>
                        )}
                        {isAdmin && (confirmDelete === h.id ? (
                          <>
                            <Btn kind="danger" className="!px-3 !py-1.5 !text-[12px]" disabled={busy !== null} onClick={() => runDelete(h.id)}>
                              {busy === `delete-${h.id}` && <Spinner />}Confirmar
                            </Btn>
                            <Btn kind="ghost" className="!px-3 !py-1.5 !text-[12px]" onClick={() => setConfirmDelete(null)}>Cancelar</Btn>
                          </>
                        ) : (
                          <Btn kind="danger" className="!px-3 !py-1.5 !text-[12px]" disabled={busy !== null}
                            title="Borra la importación con sus eventos, alertas, incidentes e informes"
                            onClick={() => setConfirmDelete(h.id)}>Eliminar</Btn>
                        ))}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}

function AnalysisSummary({ result, onNew }: { result: AnalysisResult; onNew: () => void }) {
  const order = ["Crítico", "Alto", "Medio", "Bajo"];
  return (
    <Card title={`Análisis de la importación #${result.importId}`}
      icon={<span className="w-2 h-2 rounded-full bg-blue-400 shadow-[0_0_8px_#3B82F6]" />}
      right={<span className="font-mono text-[11px] text-[#94A3B8]">{fmtDateTime(result.analyzedAt)}</span>}>
      <div className="p-5 space-y-5">
        <div className="grid grid-cols-3 gap-3">
          <Stat label="Eventos analizados" value={fmtNumber(result.eventsAnalyzed)} />
          <Stat label="Alertas generadas" value={result.alerts} color={result.alerts ? "#F97316" : "#22C55E"} />
          <Stat label="Incidentes" value={result.incidents} color={result.incidents ? "#EF4444" : "#22C55E"} />
        </div>

        <div>
          <p className="font-mono text-[10px] uppercase tracking-[0.12em] text-[#94A3B8] mb-2">Alertas por criticidad</p>
          <div className="grid grid-cols-4 gap-3">
            {order.map((label) => {
              const sev = SEVERITY[SEVERITY_BY_LABEL[label]];
              const n = result.alertsBySeverity[label] || 0;
              return (
                <div key={label} className="flex items-center justify-between rounded-xl border border-white/[0.07] bg-white/[0.02] px-4 py-3">
                  <span className="flex items-center gap-2 text-[13px]">
                    <span className="w-2.5 h-2.5 rounded-sm" style={{ background: sev.color }} />{label}
                  </span>
                  <span className="font-mono text-[18px] font-semibold tabular-nums" style={{ color: n ? sev.color : "#475569" }}>{n}</span>
                </div>
              );
            })}
          </div>
        </div>

        <p className="text-[12px] text-[#94A3B8] leading-relaxed">
          Se evaluaron {result.rulesEvaluated.length} reglas ({result.rulesEvaluated.join(", ")}).
          Cada alerta conserva la regla que la generó, su justificación y los Log_ID que la sustentan.
          {result.alerts === 0 && " Ninguna regla encontró evidencia suficiente en estos registros."}
        </p>

        <div className="flex justify-end gap-3">
          <Btn kind="ghost" onClick={onNew}>Importar otro archivo</Btn>
          <Link href="/dashboard" className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-[13px] font-semibold bg-blue-600 hover:bg-blue-500 text-white">
            Ir al dashboard →
          </Link>
        </div>
      </div>
    </Card>
  );
}
