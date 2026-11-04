// src/services/pdfService.js — Exporta un informe (JSON de reports.content) a PDF con pdfkit.
// Usa las fuentes estándar de PDF: no requieren archivos externos dentro del contenedor.

const PDFDocument = require('pdfkit');

const C = {
    ink: '#0F172A', muted: '#475569', faint: '#94A3B8', rule: '#CBD5E1', band: '#F1F5F9', brand: '#1D4ED8',
    sev: { 5: '#B91C1C', 4: '#C2410C', 3: '#A16207', 2: '#1D4ED8', 1: '#15803D' },
};
const SEV_LABEL = { 5: 'Crítico', 4: 'Alto', 3: 'Medio', 2: 'Bajo', 1: 'Info' };
const ROLE = { trigger: 'disparador', supporting: 'soporte', context: 'contexto' };

// Las fuentes estándar solo cubren WinAnsi: se sustituyen los símbolos que no tienen glifo
const EXTRA_WINANSI = new Set('€‚ƒ„…†‡ˆ‰Š‹ŒŽ‘’“”•–—˜™š›œžŸ');
const REPLACE = { '→': '->', '←': '<-', '−': '-', '≥': '>=', '≤': '<=', '✓': '', '✕': 'x', '≈': '~', ' ': ' ' };
const t = (s) => String(s ?? '').replace(/./gsu, (ch) => {
    if (REPLACE[ch] !== undefined) return REPLACE[ch];
    const code = ch.codePointAt(0);
    if (code <= 0xff || EXTRA_WINANSI.has(ch)) return ch;
    return '?';
});

const fmtLocal = (iso) => {
    if (!iso) return '—';
    const p = Object.fromEntries(new Intl.DateTimeFormat('en-GB', {
        timeZone: 'America/Panama', day: '2-digit', month: '2-digit', year: 'numeric',
        hour: '2-digit', minute: '2-digit', hourCycle: 'h23',
    }).formatToParts(new Date(iso)).map((x) => [x.type, x.value]));
    return `${p.day}/${p.month}/${p.year} ${p.hour}:${p.minute}`;
};

const renderReportPdf = (report, stream) => {
    const r = report.content;
    const doc = new PDFDocument({
        size: 'A4', margins: { top: 56, bottom: 60, left: 54, right: 54 }, bufferPages: true,
        info: { Title: t(r.meta.title), Author: 'SIEM NEXUS', Subject: t(`Importación #${r.meta.import.id}`) },
    });
    doc.pipe(stream);

    const L = doc.page.margins.left;
    const W = doc.page.width - L - doc.page.margins.right;
    const bottom = () => doc.page.height - doc.page.margins.bottom;
    const ensure = (h) => { if (doc.y + h > bottom()) doc.addPage(); };

    const font = (name, size, color = C.ink) => doc.font(name).fontSize(size).fillColor(color);
    const para = (text, opts = {}) => {
        font(opts.bold ? 'Helvetica-Bold' : 'Helvetica', opts.size || 10, opts.color || C.ink);
        doc.text(t(text), opts.x ?? L, doc.y, { width: opts.width ?? W, align: opts.align || 'left', lineGap: 2.5 });
        doc.moveDown(opts.after ?? 0.5);
    };
    const h1 = (text) => {
        ensure(60);
        doc.moveDown(0.6);
        font('Helvetica-Bold', 15, C.brand).text(t(text), L, doc.y, { width: W });
        doc.moveTo(L, doc.y + 3).lineTo(L + W, doc.y + 3).lineWidth(0.8).strokeColor(C.rule).stroke();
        doc.moveDown(0.8);
    };
    const h2 = (text) => { ensure(90); doc.moveDown(0.3); font('Helvetica-Bold', 11.5).text(t(text), L, doc.y, { width: W }); doc.moveDown(0.35); };
    const bullet = (text, indent = 12) => {
        ensure(24);
        const y = doc.y;
        font('Helvetica', 10).text('•', L + indent - 10, y);
        doc.text(t(text), L + indent, y, { width: W - indent, lineGap: 2.5 });
        doc.moveDown(0.3);
    };
    const tag = (label, color, x, y) => {
        font('Helvetica-Bold', 8, '#FFFFFF');
        const w = doc.widthOfString(t(label)) + 10;
        doc.roundedRect(x, y, w, 13, 2).fill(color);
        doc.fillColor('#FFFFFF').text(t(label), x + 5, y + 3, { lineBreak: false });
        return w;
    };

    // Tabla con ajuste de línea y salto de página (repite la cabecera)
    const table = (cols, rows, opts = {}) => {
        const size = opts.size || 8.5;
        const pad = 4;
        const header = () => {
            font('Helvetica-Bold', size, C.muted);
            const hh = Math.max(...cols.map((c) => doc.heightOfString(t(c.label), { width: c.w - pad * 2 }))) + pad * 2;
            ensure(hh + 16);
            const y = doc.y;
            doc.rect(L, y, W, hh).fill(C.band);
            let x = L;
            cols.forEach((c) => { font('Helvetica-Bold', size, C.muted).text(t(c.label), x + pad, y + pad, { width: c.w - pad * 2 }); x += c.w; });
            doc.y = y + hh;
        };
        header();
        rows.forEach((row) => {
            const cells = cols.map((c) => t(typeof c.get === 'function' ? c.get(row) : row[c.key]));
            const hgt = Math.max(...cols.map((c, i) => {
                font(c.mono ? 'Courier' : 'Helvetica', c.mono ? size - 0.5 : size);
                return doc.heightOfString(cells[i] || ' ', { width: c.w - pad * 2 });
            })) + pad * 2;
            if (doc.y + hgt > bottom()) { doc.addPage(); header(); }
            const y = doc.y;
            let x = L;
            cols.forEach((c, i) => {
                const color = c.color ? c.color(row) : C.ink;
                font(c.bold ? 'Helvetica-Bold' : c.mono ? 'Courier' : 'Helvetica', c.mono ? size - 0.5 : size, color);
                doc.text(cells[i], x + pad, y + pad, { width: c.w - pad * 2 });
                x += c.w;
            });
            doc.moveTo(L, y + hgt).lineTo(L + W, y + hgt).lineWidth(0.4).strokeColor(C.rule).stroke();
            doc.y = y + hgt;
        });
        doc.moveDown(0.8);
    };
    const kv = (pairs, keyW = 170) => table(
        [{ label: 'Dato', key: 'k', w: keyW, bold: true }, { label: 'Valor', key: 'v', w: W - keyW }],
        pairs.map(([k, v]) => ({ k, v })));

    // ── Portada ─────────────────────────────────────────────────────────────
    doc.rect(0, 0, doc.page.width, 8).fill(C.brand);
    doc.y = 150;
    font('Helvetica-Bold', 11, C.brand).text('SIEM NEXUS', L, doc.y, { characterSpacing: 2 });
    doc.moveDown(0.6);
    font('Helvetica-Bold', 26).text(t(r.meta.title), L, doc.y, { width: W });
    doc.moveDown(0.4);
    font('Helvetica', 12, C.muted).text(t(`Archivo analizado: ${r.meta.import.file_name}`), { width: W });
    doc.moveDown(2);
    kv([
        ['Informe', `#${report.id}`],
        ['Importación', `#${r.meta.import.id} · hoja «${r.meta.import.sheet || '—'}»`],
        ['Periodo de los registros', `${r.meta.period.text} (hora de Panamá)`],
        ['Eventos analizados', `${r.scope.events} (${r.meta.import.rows_rejected} filas rechazadas al importar)`],
        ['Generado', `${fmtLocal(r.meta.generated_at)}${r.meta.generated_by ? ` por ${r.meta.generated_by}` : ''}`],
        ['Redacción', r.ai.used
            ? `Resumen y narrativas redactados con IA (${r.ai.model}) y validados contra la evidencia; el resto procede de las reglas.`
            : 'Generada íntegramente a partir de las reglas de detección (sin IA).'],
    ]);
    doc.moveDown(1);
    para('Este informe se basa exclusivamente en los registros importados. Cada hallazgo indica la regla que lo generó, su justificación y los Log_ID que lo sustentan. Una alerta es una sospecha fundada en evidencia, no una confirmación de compromiso.', { color: C.muted, size: 9.5 });

    // ── 1. Resumen ejecutivo ────────────────────────────────────────────────
    doc.addPage();
    h1('1. Resumen ejecutivo');
    para(r.executive_summary.text, { size: 10.5 });
    para(r.executive_summary.source === 'ia'
        ? `Redactado con IA (${r.executive_summary.model}) a partir de los hallazgos calculados; validado automáticamente contra los Log_ID, IPs, cuentas y equipos de la evidencia.`
        : 'Redacción generada por el motor de reglas.', { size: 8.5, color: C.faint });

    h2('Panorama de riesgo');
    const sevs = [5, 4, 3, 2];
    const maxV = Math.max(1, ...sevs.map((s) => r.risk_overview.alerts[s] || 0));
    sevs.forEach((s) => {
        ensure(20);
        const y = doc.y;
        const n = r.risk_overview.alerts[s] || 0;
        const inc = r.risk_overview.incidents[s] || 0;
        font('Helvetica', 10).text(SEV_LABEL[s], L, y + 1, { width: 60 });
        if (n) doc.rect(L + 64, y + 2, (n / maxV) * 260, 9).fill(C.sev[s]);
        font('Helvetica', 9.5).text(`${n} alerta${n === 1 ? '' : 's'} · ${inc} incidente${inc === 1 ? '' : 's'}`, L + 64 + (n ? (n / maxV) * 260 + 8 : 0), y + 1);
        doc.y = y + 17;
    });
    doc.moveDown(0.5);

    // ── 2. Alcance ──────────────────────────────────────────────────────────
    h1('2. Alcance de los datos');
    kv([
        ['Eventos importados', r.scope.events],
        ['Equipos distintos', r.scope.hosts],
        ['Cuentas distintas', r.scope.users],
        ['IPs externas de origen', r.scope.external_sources],
        ['Inicios de sesión fallidos', r.scope.logon_failures],
        ['Eventos usados como evidencia', r.scope.evidence_events],
    ]);
    h2('Eventos por tipo normalizado');
    table([
        { label: 'Tipo', key: 'event_type', w: W * 0.7, mono: true },
        { label: 'Eventos', key: 'total', w: W * 0.3 },
    ], r.scope.by_type);

    // ── 3. Metodología ──────────────────────────────────────────────────────
    h1('3. Metodología');
    r.methodology.forEach((m, i) => para(`${i + 1}. ${m}`));

    // ── 4. Cobertura ────────────────────────────────────────────────────────
    h1('4. Cobertura de las detecciones solicitadas');
    table([
        { label: 'Detección', key: 'label', w: 110, bold: true },
        { label: 'Reglas', get: (c) => c.rules.join(', '), w: 105, mono: true },
        { label: 'Alertas', key: 'alerts', w: 45 },
        { label: 'Resultado', key: 'note', w: W - 260 },
    ], r.coverage);

    // ── 5. Hallazgos ────────────────────────────────────────────────────────
    h1('5. Hallazgos por incidente');
    r.findings.forEach((f, idx) => {
        ensure(120);
        if (idx) doc.moveDown(0.6);
        const y = doc.y;
        const w = tag(f.severity_label, C.sev[f.severity], L, y);
        font('Helvetica-Bold', 11.5).text(t(`Incidente #${f.id} · ${f.title}`), L + w + 8, y, { width: W - w - 8 });
        doc.moveDown(0.4);
        const ent = [
            ['Periodo (hora de Panamá)', f.period.text],
            f.entities.external_ips.length && ['IPs externas', f.entities.external_ips.join(', ')],
            f.entities.actors.length && ['Cuentas que actúan', f.entities.actors.join(', ')],
            f.entities.targeted.length && ['Cuentas atacadas', f.entities.targeted.join(', ')],
            f.entities.hosts.length && ['Equipos afectados', f.entities.hosts.join(', ')],
            f.mitre_tactics.length && ['Tácticas MITRE ATT&CK', f.mitre_tactics.join(', ')],
        ].filter(Boolean);
        kv(ent, 150);

        h2('Descripción');
        para(f.narrative);
        para(f.narrative_source === 'ia' ? 'Narrativa redactada con IA y validada contra la evidencia de este incidente.' : 'Narrativa compuesta con las justificaciones de las reglas.', { size: 8, color: C.faint });

        h2(`Alertas (${f.alerts.length})`);
        f.alerts.forEach((a) => {
            ensure(70);
            const yy = doc.y;
            const tw = tag(a.severity_label, C.sev[a.severity], L, yy);
            font('Helvetica-Bold', 9.5).text(t(`${a.rule_code} · ${a.title}`), L + tw + 6, yy + 1, { width: W - tw - 6 });
            doc.moveDown(0.25);
            para(`Regla: ${a.rule_name} (v${a.rule_version}) · Categoría: ${a.category}${a.mitre.length ? ` · MITRE: ${a.mitre.join(', ')}` : ''} · Ventana: ${a.window}`, { size: 8.5, color: C.muted, after: 0.2 });
            para(`Justificación: ${a.justification}`, { size: 9, after: 0.2 });
            const ids = a.evidence.map((e) => `${e.log_id} (${ROLE[e.role]})`).join(', ');
            font('Courier', 7.8, C.muted).text(t(`Evidencia: ${ids}`), L, doc.y, { width: W, lineGap: 1.5 });
            doc.moveDown(0.6);
        });

        if (f.recommendations.length) {
            h2('Recomendaciones');
            f.recommendations.forEach((rec) => bullet(rec));
        }
    });

    // ── 6. Hipótesis ────────────────────────────────────────────────────────
    h1('6. Hipótesis a investigar (no confirmadas)');
    if (r.hypotheses.length) r.hypotheses.forEach((h) => bullet(h));
    else para('No se identificaron relaciones entre incidentes que requieran investigación adicional.');

    // ── 7. Limitaciones ─────────────────────────────────────────────────────
    h1('7. Limitaciones del análisis');
    r.limitations.forEach((l) => bullet(l));

    // ── Anexos ──────────────────────────────────────────────────────────────
    doc.addPage();
    h1('Anexo A. Reglas aplicadas');
    const params = (p) => Object.entries(p).map(([k, v]) => `${k}=${v}`).join(', ') || '—';
    table([
        { label: 'Código', key: 'code', w: 50, mono: true },
        { label: 'Regla', key: 'name', w: 150 },
        { label: 'Categoría', key: 'category', w: 85 },
        { label: 'Crit.', key: 'severity', w: 45 },
        { label: 'Umbrales', get: (x) => params(x.params), w: W - 375, mono: true },
        { label: 'Alertas', key: 'triggered', w: 45 },
    ], r.appendix.rules, { size: 8 });

    h1('Anexo B. Registros citados como evidencia');
    para(`${r.appendix.evidence.length} registros del archivo original. La fila completa de cada uno puede consultarse en la aplicación (Eventos).`, { size: 9, color: C.muted });
    const cut = (s, n) => (s && s.length > n ? `${s.slice(0, n - 1)}…` : s || '—');
    table([
        { label: 'Log_ID', key: 'log_id', w: 62, mono: true },
        { label: 'Fecha y hora', key: 'time', w: 92, mono: true },
        { label: 'Equipo', key: 'hostname', w: 62 },
        { label: 'Usuario', get: (e) => e.user_name || '—', w: 92 },
        { label: 'IP origen', get: (e) => e.source_ip || '—', w: 72, mono: true },
        { label: 'Detalle', get: (e) => cut(e.detail, 90), w: W - 380 },
    ], r.appendix.evidence, { size: 7.5 });

    // ── Pie de página en todas las páginas ──────────────────────────────────
    const range = doc.bufferedPageRange();
    for (let i = range.start; i < range.start + range.count; i++) {
        doc.switchToPage(i);
        doc.page.margins.bottom = 0;           // permite escribir en el pie sin crear páginas nuevas
        const y = doc.page.height - 38;
        doc.moveTo(L, y - 6).lineTo(L + W, y - 6).lineWidth(0.4).strokeColor(C.rule).stroke();
        font('Helvetica', 7.5, C.faint);
        doc.text(t(`SIEM NEXUS · Informe #${report.id} · Importación #${r.meta.import.id}`), L, y, { width: W / 2, lineBreak: false });
        doc.text(`Página ${i + 1} de ${range.count}`, L + W / 2, y, { width: W / 2, align: 'right', lineBreak: false });
    }
    doc.end();
};

module.exports = { renderReportPdf };
