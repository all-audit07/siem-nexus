"use client";

// app/dashboard/page.tsx — Resumen del análisis. Todo sale de la importación seleccionada:
// eventos del Excel + alertas e incidentes generados por las reglas. Sin datos simulados.

import { ReactNode, useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import AppShell from "@/components/siem/AppShell";
import { Banner, CATEGORY, Card, ImportPicker, NoAnalysis, Pill, Spinner, Stat, useSelectedImport } from "@/components/siem/ui";
import { SessionExpiredError, SEVERITY, TZ, apiFetch, fmtDateTime, fmtNumber } from "@/lib/siem";

// ── Tipos ────────────────────────────────────────────────────────
interface Entity { value: string; alerts: number; max_severity: number }
interface AlertLite { id: string; title: string; severity: number; window_start: string; window_end: string; incident_id: string | null; rule_code: string; category: string }
interface Summary {
  import: { id: string; file_name: string; rows_valid: number; rows_rejected: number; imported_at: string; analyzed_at: string | null; source_timezone: string };
  events: {
    total: number; first_at: string | null; last_at: string | null; hosts: number; users: number;
    external_sources: number; logon_failures: number;
    by_type: { event_type: string; total: number }[];
    by_sensor_severity: { severity: number; label: string; total: number }[];
  };
  timeline: { bucket: string; total: number; flagged: number }[];
  alerts: { total: number; by_severity: Record<string, number>; by_category: { category: string; total: number }[]; list: AlertLite[] };
  incidents: { total: number; by_severity: Record<string, number>; list: { id: string; title: string; severity: number; status: string; start_at: string; end_at: string; alert_count: number }[] };
  top: { hosts: Entity[]; users: Entity[]; external_ips: Entity[] };
}

const hhmm = new Intl.DateTimeFormat("en-GB", { timeZone: TZ, hour: "2-digit", minute: "2-digit", hourCycle: "h23" });
const fmtTime = (v: string) => hhmm.format(new Date(v));

// Rangos reservados para documentación (RFC 5737): no corresponden a ninguna ubicación real
const isDocIp = (ip: string) => /^(192\.0\.2|198\.51\.100|203\.0\.113)\./.test(ip);

// Familias de tipos de evento → color categórico (orden fijo, validado para fondo oscuro y daltonismo)
const FAMILIES = [
  { key: "auth",    label: "Autenticación",        color: "#3987e5", types: ["logon_success", "logon_failure", "logoff", "special_privileges"] },
  { key: "process", label: "Procesos y servicios", color: "#d95926", types: ["process_creation", "powershell_scriptblock", "scheduled_task_created", "service_installed", "service_state_change"] },
  { key: "files",   label: "Archivos y recursos",  color: "#199e70", types: ["object_access", "share_access", "share_access_detailed"] },
  { key: "network", label: "Red",                  color: "#c98500", types: ["network_connection_allowed"] },
  { key: "web",     label: "Web y proxy",          color: "#d55181", types: ["http_request", "proxy_request"] },
];
const OTHER_FAMILY = { key: "other", label: "Otros", color: "#64748B", types: [] as string[] };
const familyOf = (type: string) => FAMILIES.find((f) => f.types.includes(type)) || OTHER_FAMILY;

const INC_STATUS: Record<string, string> = { open: "Abierto", investigating: "En investigación", contained: "Contenido", resolved: "Resuelto", closed: "Cerrado" };

export default function DashboardPage() {
  return (
    <AppShell title="Dashboard" subtitle="Resumen del análisis de la importación seleccionada">
      {() => <DashboardView />}
    </AppShell>
  );
}

function DashboardView() {
  const router = useRouter();
  const { imports, selected, select, error: importsError } = useSelectedImport();
  const [data, setData] = useState<Summary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!selected) return;
    setData(null); setError(null);
    (async () => {
      try {
        const r = await apiFetch<Summary>(`/imports/${selected}/summary`);
        if (r.ok) setData(r.data); else setError(r.data?.error || "No se pudo cargar el resumen");
      } catch (e) {
        if (e instanceof SessionExpiredError) router.replace("/login");
        else setError("Error inesperado al cargar el resumen");
      }
    })();
  }, [selected, router]);

  if (imports === null) return <p className="text-[13px] text-[#94A3B8]">Cargando…</p>;
  if (importsError) return <Banner tone="error">{importsError}</Banner>;
  if (!imports.length) return <NoAnalysis />;

  const go = (path: string) => router.push(`${path}${path.includes("?") ? "&" : "?"}import=${selected}`);

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <ImportPicker imports={imports} selected={selected} onChange={select} />
        {data && (
          <p className="text-[12px] text-[#94A3B8]">
            Registros del <span className="font-mono text-[#CBD5E1]">{fmtDateTime(data.events.first_at)}</span> al{" "}
            <span className="font-mono text-[#CBD5E1]">{fmtDateTime(data.events.last_at)}</span> (hora de Panamá) ·
            analizado el <span className="font-mono text-[#CBD5E1]">{fmtDateTime(data.import.analyzed_at)}</span>
          </p>
        )}
      </div>

      {error && <Banner tone="error">{error}</Banner>}
      {!data ? <p className="text-[13px] text-[#94A3B8] flex items-center gap-2"><Spinner /> Cargando resumen…</p> : (
        <>
          {/* Indicadores */}
          <div className="grid grid-cols-4 gap-4">
            <Kpi label="Eventos analizados" value={fmtNumber(data.events.total)} accent="#3B82F6"
              hint={`${data.import.rows_rejected} filas rechazadas al importar`} onClick={() => go("/events")} />
            <Kpi label="Alertas" value={data.alerts.total} accent="#F97316"
              hint={`${data.alerts.by_severity[5] || 0} críticas · ${data.alerts.by_severity[4] || 0} altas`} onClick={() => go("/alerts")} />
            <Kpi label="Incidentes" value={data.incidents.total} accent="#EF4444"
              hint={`${data.incidents.by_severity[5] || 0} críticos · ${data.incidents.by_severity[4] || 0} altos`} onClick={() => go("/incidents")} />
            <Kpi label="Eventos usados como evidencia" value={fmtNumber(data.timeline.reduce((s, b) => s + b.flagged, 0))} accent="#7C3AED"
              hint={`de ${fmtNumber(data.events.total)} registros`} onClick={() => go("/events?flagged=true")} />
          </div>
          <div className="grid grid-cols-4 gap-4">
            <Stat label="Equipos distintos" value={data.events.hosts} />
            <Stat label="Cuentas distintas" value={data.events.users} />
            <Stat label="IPs externas de origen" value={data.events.external_sources} />
            <Stat label="Inicios de sesión fallidos" value={fmtNumber(data.events.logon_failures)} />
          </div>

          {/* Criticidad + categoría */}
          <div className="grid grid-cols-2 gap-4">
            <Card title="Alertas por criticidad" right={<Hint>Clic en una barra para ver las alertas</Hint>}>
              <div className="p-5">
                <HBars
                  rows={[5, 4, 3, 2].map((s) => ({
                    key: String(s), label: SEVERITY[s].label, value: data.alerts.by_severity[s] || 0, color: SEVERITY[s].color, swatch: true,
                    onClick: () => go(`/alerts?severity=${s}`),
                  }))}
                  unit="alertas" />
              </div>
            </Card>
            <Card title="Alertas por categoría de detección" right={<Hint>Las 6 categorías del enunciado</Hint>}>
              <div className="p-5">
                <HBars
                  rows={Object.keys(CATEGORY).map((c) => ({
                    key: c, label: CATEGORY[c], value: data.alerts.by_category.find((x) => x.category === c)?.total || 0,
                    color: "#3B82F6", onClick: () => go(`/alerts?category=${c}`),
                  }))}
                  unit="alertas" />
              </div>
            </Card>
          </div>

          {/* Línea de tiempo */}
          <Card title="Actividad en el tiempo — eventos cada 10 minutos y alertas"
            right={<Hint>Hora de Panamá · pasa el cursor para ver el detalle</Hint>}>
            <div className="p-5">
              <Timeline buckets={data.timeline} alerts={data.alerts.list} onAlert={(id) => go(`/alerts?alert=${id}`)} />
            </div>
          </Card>

          {/* Incidentes */}
          <Card title="Incidentes detectados" right={<button onClick={() => go("/incidents")} className="font-mono text-[11px] text-blue-300 hover:underline">Ver todos →</button>}>
            {data.incidents.list.length === 0 ? (
              <p className="px-5 py-6 text-[13px] text-[#94A3B8]">El análisis no generó incidentes.</p>
            ) : (
              <ul className="divide-y divide-white/[0.05]">
                {data.incidents.list.map((i) => (
                  <li key={i.id}>
                    <button onClick={() => go(`/incidents?incident=${i.id}`)}
                      className="w-full grid grid-cols-[90px_minmax(0,1fr)_150px_100px_110px] items-center gap-4 px-5 py-3 text-left hover:bg-white/[0.03]">
                      <Pill cls={SEVERITY[i.severity].cls}>{SEVERITY[i.severity].label}</Pill>
                      <span className="text-[13px] font-medium truncate">#{i.id} · {i.title}</span>
                      <span className="font-mono text-[11px] text-[#94A3B8]">{fmtTime(i.start_at)} → {fmtTime(i.end_at)}</span>
                      <span className="font-mono text-[11px] text-[#94A3B8]">{i.alert_count} alerta{i.alert_count === 1 ? "" : "s"}</span>
                      <span className="text-[11px] text-[#94A3B8] text-right">{INC_STATUS[i.status] || i.status}</span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </Card>

          {/* Rankings */}
          <div className="grid grid-cols-3 gap-4">
            <TopCard title="Equipos con más alertas" rows={data.top.hosts} onPick={(v) => go(`/events?flagged=true&host=${encodeURIComponent(v)}`)} />
            <TopCard title="Cuentas en la evidencia" note="Incluye cuentas atacadas, no solo atacantes"
              rows={data.top.users} onPick={(v) => go(`/events?flagged=true&user=${encodeURIComponent(v)}`)} />
            <TopCard title="IPs externas en alertas" rows={data.top.external_ips}
              note={data.top.external_ips.some((r) => isDocIp(r.value)) ? "Rangos de documentación (RFC 5737): no se geolocalizan" : undefined}
              onPick={(v) => go(`/events?ip=${encodeURIComponent(v)}`)} />
          </div>

          {/* Composición del archivo */}
          <div className="grid grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)] gap-4">
            <Card title="Eventos por tipo" right={<Hint>Clic en una barra para ver esos eventos</Hint>}>
              <div className="p-5 space-y-4">
                <div className="flex flex-wrap gap-x-4 gap-y-1.5 text-[11px] text-[#94A3B8]">
                  {[...FAMILIES, OTHER_FAMILY].filter((f) => data.events.by_type.some((t) => familyOf(t.event_type).key === f.key)).map((f) => (
                    <span key={f.key} className="flex items-center gap-1.5">
                      <span style={{ width: 10, height: 10, borderRadius: 2, background: f.color, display: "inline-block" }} />{f.label}
                    </span>
                  ))}
                </div>
                <HBars compact unit="eventos"
                  rows={data.events.by_type.map((t) => ({
                    key: t.event_type, label: t.event_type, value: t.total, color: familyOf(t.event_type).color, mono: true,
                    onClick: () => go(`/events?type=${t.event_type}`),
                  }))} />
              </div>
            </Card>
            <Card title="Severidad asignada por el sensor (origen)" right={<Hint>Antes del análisis</Hint>}>
              <div className="p-5 space-y-4">
                <HBars compact unit="eventos"
                  rows={data.events.by_sensor_severity.map((s) => ({
                    key: String(s.severity), label: s.label, value: s.total,
                    color: SEVERITY[s.severity]?.color || "#64748B", swatch: true,
                    onClick: () => go(`/events?severity=${s.severity}`),
                  }))} />
                <p className="text-[11px] text-[#94A3B8] leading-relaxed">
                  Es la severidad que trae cada fila del Excel. La criticidad de las alertas (Crítico, Alto, Medio, Bajo)
                  la asignan las reglas a partir de la evidencia combinada.
                </p>
              </div>
            </Card>
          </div>
        </>
      )}
    </div>
  );
}

// ── Componentes ──────────────────────────────────────────────────
const Hint = ({ children }: { children: ReactNode }) => <span className="text-[11px] text-[#94A3B8] text-right">{children}</span>;

const Kpi = ({ label, value, hint, accent, onClick }: { label: string; value: ReactNode; hint: string; accent: string; onClick: () => void }) => (
  <button onClick={onClick}
    className="relative text-left bg-white/[0.03] border border-white/[0.07] rounded-2xl p-5 overflow-hidden hover:bg-white/[0.05] hover:-translate-y-0.5 transition-all shadow-[0_4px_24px_rgba(0,0,0,0.3)]">
    <span className="absolute top-0 left-0 right-0 h-[3px]" style={{ background: `linear-gradient(90deg, ${accent}, transparent)` }} />
    <div className="font-mono text-[34px] font-semibold leading-none tabular-nums">{value}</div>
    <div className="text-xs text-[#94A3B8] uppercase tracking-[0.08em] mt-2">{label}</div>
    <div className="text-[11px] font-mono mt-3 text-[#CBD5E1]">{hint}</div>
  </button>
);

interface BarRow { key: string; label: string; value: number; color: string; onClick?: () => void; mono?: boolean; swatch?: boolean }

// Barras horizontales: etiqueta a la izquierda, valor al final de la barra.
// La geometría y el resaltado usan estilos en línea para no depender de clases generadas.
function HBars({ rows, unit, compact = false }: { rows: BarRow[]; unit: string; compact?: boolean }) {
  const max = Math.max(1, ...rows.map((r) => r.value));
  return (
    <ul className={compact ? "space-y-1" : "space-y-2"}>
      {rows.map((r) => <HBarRow key={r.key} r={r} max={max} unit={unit} compact={compact} />)}
    </ul>
  );
}

function HBarRow({ r, max, unit, compact }: { r: BarRow; max: number; unit: string; compact: boolean }) {
  const [hover, setHover] = useState(false);
  const clickable = !!r.onClick;
  const Comp = clickable ? "button" : "div";
  return (
    <li>
      <Comp onClick={r.onClick} title={`${r.label}: ${fmtNumber(r.value)} ${unit}${clickable ? " · clic para ver" : ""}`}
        onMouseEnter={() => setHover(true)} onMouseLeave={() => setHover(false)}
        style={{
          display: "grid", gridTemplateColumns: `${r.mono ? 190 : 150}px minmax(0,1fr)`, alignItems: "center", columnGap: 12,
          width: "100%", textAlign: "left", borderRadius: 6, padding: compact ? "3px 6px" : "5px 6px",
          cursor: clickable ? "pointer" : "default",
          background: clickable && hover ? "rgba(255,255,255,0.06)" : "transparent", transition: "background .15s",
        }}>
        <span className={`flex items-center gap-2 text-[12px] truncate ${r.mono ? "font-mono text-[11px]" : ""}`}
          style={{ color: clickable && hover ? "#FFFFFF" : undefined }}>
          {r.swatch && <span style={{ width: 8, height: 8, borderRadius: 2, flexShrink: 0, background: r.color, display: "inline-block" }} />}
          {r.label}
        </span>
        <span className="flex items-center gap-2 min-w-0">
          <span style={{
            display: "block", flexShrink: 0, height: compact ? 9 : 14, borderRadius: "0 4px 4px 0",
            width: r.value ? `${Math.max(1.5, (r.value / max) * 85)}%` : 0, background: r.color,
            opacity: clickable && hover ? 1 : 0.88, transition: "width .7s, opacity .15s",
          }} />
          <span className="font-mono text-[12px] tabular-nums text-[#E2E8F0]">{fmtNumber(r.value)}</span>
          {clickable && <span className="text-[11px] text-[#94A3B8]" style={{ opacity: hover ? 1 : 0, transition: "opacity .15s" }}>→</span>}
        </span>
      </Comp>
    </li>
  );
}

function TopCard({ title, rows, onPick, note }: { title: string; rows: Entity[]; onPick: (v: string) => void; note?: string }) {
  const max = Math.max(1, ...rows.map((r) => r.alerts));
  return (
    <Card title={title}>
      <div className="p-4">
        {rows.length === 0 ? <p className="text-[12px] text-[#94A3B8] px-1">Sin datos.</p> : (
          <ul className="space-y-1">
            {rows.map((r) => (
              <li key={r.value}>
                <button onClick={() => onPick(r.value)} title={`${r.value}: ${r.alerts} alertas · máxima ${SEVERITY[r.max_severity]?.label}`}
                  style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) auto", alignItems: "center", columnGap: 12 }}
                  className="w-full rounded-md px-2 py-1.5 hover:bg-white/[0.04] text-left">
                  <span className="text-[12px] truncate font-mono">{r.value}</span>
                  <span className="flex items-center gap-2">
                    <span className="font-mono text-[12px] tabular-nums">{r.alerts}</span>
                    <Pill cls={SEVERITY[r.max_severity]?.cls || ""}>{SEVERITY[r.max_severity]?.label}</Pill>
                  </span>
                  <span style={{ gridColumn: "span 2", display: "block", height: 4, marginTop: 4, borderRadius: 999, background: "rgba(255,255,255,0.05)" }}>
                    <span style={{ display: "block", height: "100%", borderRadius: 999, background: "#3B82F6", width: `${(r.alerts / max) * 100}%` }} />
                  </span>
                </button>
              </li>
            ))}
          </ul>
        )}
        {note && <p className="mt-3 px-2 text-[11px] text-[#94A3B8]">{note}</p>}
      </div>
    </Card>
  );
}

// Columnas de eventos cada 10 min (parte usada como evidencia resaltada) + carril de alertas
function Timeline({ buckets, alerts, onAlert }: { buckets: Summary["timeline"]; alerts: AlertLite[]; onAlert: (id: string) => void }) {
  const wrapRef = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(900);
  const [tip, setTip] = useState<{ x: number; y: number; body: ReactNode } | null>(null);

  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const ro = new ResizeObserver(([e]) => setWidth(Math.max(320, e.contentRect.width)));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const H = 180, padL = 36, padR = 8, padT = 10, padB = 24;
  const plotW = width - padL - padR, plotH = H - padT - padB;
  const max = Math.max(1, ...buckets.map((b) => b.total));
  const niceMax = Math.ceil(max / 5) * 5;
  const n = buckets.length;
  const slot = plotW / Math.max(1, n);
  const barW = Math.min(24, Math.max(3, slot - 2));
  const t0 = n ? new Date(buckets[0].bucket).getTime() : 0;
  const span = n * 10 * 60 * 1000 || 1;
  const xAt = (iso: string) => padL + ((new Date(iso).getTime() - t0) / span) * plotW;
  const y = (v: number) => padT + plotH - (v / niceMax) * plotH;
  const ticks = [0, niceMax / 2, niceMax];
  const labelEvery = Math.max(1, Math.ceil(n / Math.floor(plotW / 56)));

  // Alertas en el carril: si dos puntos quedarían a menos de 12 px, el segundo baja una fila
  const placed = useMemo(() => {
    const rowsLastX: number[] = [];
    return alerts.map((a) => {
      const x = xAt(a.window_start);
      let row = rowsLastX.findIndex((last) => x - last >= 12);
      if (row === -1) { row = rowsLastX.length; rowsLastX.push(x); } else rowsLastX[row] = x;
      return { a, x, row };
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [alerts, width, t0]);
  const laneRows = Math.max(1, ...placed.map((p) => p.row + 1));

  const show = (ev: React.MouseEvent, body: ReactNode) => {
    const box = wrapRef.current!.getBoundingClientRect();
    setTip({ x: ev.clientX - box.left, y: ev.clientY - box.top, body });
  };

  if (!n) return <p className="text-[12px] text-[#94A3B8]">Sin eventos.</p>;

  return (
    <div ref={wrapRef} className="relative" onMouseLeave={() => setTip(null)}>
      <div className="flex items-center gap-4 mb-3 text-[11px] text-[#94A3B8]">
        <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-sm bg-[#334155]" />Eventos</span>
        <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-sm bg-[#7C3AED]" />De ellos, evidencia de alertas</span>
        <span className="flex items-center gap-3 ml-auto">Alertas:
          {[5, 4, 3, 2].map((s) => (
            <span key={s} className="flex items-center gap-1"><span className="w-2 h-2 rounded-full" style={{ background: SEVERITY[s].color }} />{SEVERITY[s].label}</span>
          ))}
        </span>
      </div>

      <svg width={width} height={H + 16 + laneRows * 12} role="img" aria-label="Eventos por intervalo de 10 minutos y alertas generadas">
        {ticks.map((t) => (
          <g key={t}>
            <line x1={padL} x2={width - padR} y1={y(t)} y2={y(t)} stroke="rgba(255,255,255,0.06)" />
            <text x={padL - 6} y={y(t) + 3} textAnchor="end" fontSize="10" fill="#94A3B8" fontFamily="ui-monospace,monospace">{t}</text>
          </g>
        ))}
        {buckets.map((b, i) => {
          const cx = padL + i * slot + slot / 2;
          const x = cx - barW / 2;
          const rest = b.total - b.flagged;
          return (
            <g key={b.bucket}
              onMouseMove={(ev) => show(ev, (
                <>
                  <p className="font-mono text-[11px] text-[#94A3B8]">{fmtTime(b.bucket)}–{fmtTime(new Date(new Date(b.bucket).getTime() + 600000).toISOString())}</p>
                  <p className="text-[12px] mt-1"><b className="font-mono">{b.total}</b> eventos</p>
                  <p className="text-[12px]"><b className="font-mono">{b.flagged}</b> usados como evidencia</p>
                </>
              ))}>
              <rect x={padL + i * slot} y={padT} width={slot} height={plotH} fill="transparent" />
              {rest > 0 && <rect x={x} y={y(b.total)} width={barW} height={y(b.flagged) - y(b.total) - (b.flagged ? 2 : 0)} rx={b.flagged ? 0 : 3} fill="#334155" />}
              {b.flagged > 0 && <rect x={x} y={y(b.flagged)} width={barW} height={padT + plotH - y(b.flagged)} fill="#7C3AED" />}
              {i % labelEvery === 0 && (
                <text x={cx} y={H - 6} textAnchor="middle" fontSize="10" fill="#94A3B8" fontFamily="ui-monospace,monospace">{fmtTime(b.bucket)}</text>
              )}
            </g>
          );
        })}
        <line x1={padL} x2={width - padR} y1={padT + plotH} y2={padT + plotH} stroke="rgba(255,255,255,0.15)" />

        {/* Carril de alertas */}
        <text x={padL - 6} y={H + 18} textAnchor="end" fontSize="9" fill="#94A3B8">Alertas</text>
        <line x1={padL} x2={width - padR} y1={H + 14} y2={H + 14} stroke="rgba(255,255,255,0.06)" />
        {placed.map(({ a, x, row }) => (
          <circle key={a.id} cx={x} cy={H + 14 + row * 12} r={5}
            fill={SEVERITY[a.severity].color} stroke="#0b1220" strokeWidth={2} className="cursor-pointer"
            onClick={() => onAlert(a.id)}
            onMouseMove={(ev) => show(ev, (
              <>
                <p className="flex items-center gap-2"><Pill cls={SEVERITY[a.severity].cls}>{SEVERITY[a.severity].label}</Pill>
                  <span className="font-mono text-[10px] text-[#94A3B8]">{a.rule_code} · {fmtTime(a.window_start)}</span></p>
                <p className="text-[12px] mt-1.5 leading-snug">{a.title}</p>
                <p className="text-[10px] text-[#94A3B8] mt-1">Clic para abrir la alerta</p>
              </>
            ))} />
        ))}
      </svg>

      {tip && (
        <div role="tooltip" className="pointer-events-none absolute z-20 max-w-[300px] rounded-lg border border-white/[0.12] bg-[#0b1324]/95 px-3 py-2 shadow-xl"
          style={{ left: Math.max(0, Math.min(tip.x + 14, width - 300)), top: tip.y - 12, transform: "translateY(-100%)" }}>
          {tip.body}
        </div>
      )}
    </div>
  );
}
