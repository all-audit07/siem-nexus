// src/services/auditReportService.js
// v2.0 · Informe de auditoría en PDF a partir de los hallazgos de auditoría de una importación.
// Contenido determinista (sin IA). Incluye la huella SHA-256 del archivo importado y la de los
// hallazgos, para que cualquier alteración posterior del informe o de los datos sea detectable.

const crypto      = require('crypto');
const PDFDocument = require('pdfkit');
const { pool }    = require('../config/postgres');
const audit       = require('./auditService');

const C = {
    ink: '#0F172A', muted: '#475569', faint: '#94A3B8', rule: '#CBD5E1', band: '#F1F5F9', brand: '#1D4ED8',
    sev: { 5: '#B91C1C', 4: '#C2410C', 3: '#A16207', 2: '#1D4ED8' },
};
const SEV_LABEL = { 5: 'Crítico', 4: 'Alto', 3: 'Medio', 2: 'Bajo' };
const STATUS = { abierto: 'Abierto', en_remediacion: 'En remediación', cerrado: 'Cerrado', verificado: 'Verificado' };
const DOMAINS = [
    { prefix: '5.', name: 'Controles organizacionales (5.x)' },
    { prefix: '6.', name: 'Controles de personas (6.x)' },
    { prefix: '7.', name: 'Controles físicos (7.x)' },
    { prefix: '8.', name: 'Controles tecnológicos (8.x)' },
];
// Valoración según el hallazgo más grave del dominio
const RATING = {
    5: 'No eficaz: existen deficiencias críticas con compromiso probable o acción destructiva.',
    4: 'Deficiencias significativas: actividad maliciosa clara que los controles no impidieron.',
    3: 'Requiere mejora: debilidades que requieren contexto o corrección planificada.',
    2: 'Eficaz con observaciones: debilidades menores sin actividad maliciosa asociada.',
};

// Las fuentes estándar de PDF solo cubren WinAnsi: se sustituyen los símbolos sin glifo
const EXTRA_WINANSI = new Set('€‚ƒ„…†‡ˆ‰Š‹ŒŽ‘’“”•–—˜™š›œžŸ');
const REPLACE = { '→': '->', '←': '<-', '−': '-', '≥': '>=', '≤': '<=', '≈': '~', ' ': ' ' };
const t = (s) => String(s ?? '').replace(/./gsu, (ch) => {
    if (REPLACE[ch] !== undefined) return REPLACE[ch];
    const code = ch.codePointAt(0);
    return code <= 0xff || EXTRA_WINANSI.has(ch) ? ch : '?';
});
const fmtLocal = (iso, withTime = true) => {
    if (!iso) return '—';
    const p = Object.fromEntries(new Intl.DateTimeFormat('en-GB', {
        timeZone: 'America/Panama', day: '2-digit', month: '2-digit', year: 'numeric',
        hour: '2-digit', minute: '2-digit', hourCycle: 'h23',
    }).formatToParts(new Date(iso)).map((x) => [x.type, x.value]));
    return withTime ? `${p.day}/${p.month}/${p.year} ${p.hour}:${p.minute}` : `${p.day}/${p.month}/${p.year}`;
};
const fmtDate = (d) => {
    if (!d) return '—';
    const s = d instanceof Date ? d.toISOString() : String(d);
    return `${s.slice(8, 10)}/${s.slice(5, 7)}/${s.slice(0, 4)}`;
};
const pl = (n, one, many) => `${n} ${n === 1 ? one : many}`;
const listText = (a) => (a.length <= 1 ? a.join('') : `${a.slice(0, -1).join(', ')} y ${a[a.length - 1]}`);

// ── Contenido ────────────────────────────────────────────────────────────────

const buildAuditReport = async (importId, generatedBy) => {
    const { rows: [imp] } = await pool.query(
        `SELECT id, file_name, file_sha256, sheet_name, rows_valid, rows_rejected, analyzed_at
           FROM log_imports WHERE id = $1`, [importId]);
    if (!imp) throw new audit.AuditError('Importación no encontrada', 404);

    const data = await audit.listFindings(importId);
    if (!data.total) throw new audit.AuditError('Genera los hallazgos de auditoría antes de exportar el informe', 409);

    const { rows: [period] } = await pool.query(
        'SELECT min(occurred_at) AS first_at, max(occurred_at) AS last_at FROM security_events WHERE import_id = $1', [importId]);

    const findings = data.findings;

    // Huella de los hallazgos: cambia si cambia cualquier condición, control, evidencia, estado o plazo
    const canonical = findings.map((f) => ({
        code: f.code, severity: f.severity, type: f.finding_type, iso: f.iso_controls, cis: f.cis_safeguards,
        condition: f.condition, evidence: f.evidence_log_ids, status: f.status, owner: f.owner,
        due: fmtDate(f.due_date), mapping: f.mapping_version,
    }));
    const fingerprint = crypto.createHash('sha256').update(JSON.stringify(canonical)).digest('hex');

    const domains = DOMAINS.map((d) => {
        const controls = data.controls.filter((c) => c.id.startsWith(d.prefix));
        if (!controls.length) return null;
        const worst = Math.max(...controls.map((c) => c.severity));
        const top = [...controls].sort((a, b) => b.findings.length - a.findings.length || b.severity - a.severity)[0];
        return {
            name: d.name, controls, worst, rating: RATING[worst],
            text: `Se identificaron deficiencias o indicadores en ${pl(controls.length, 'control', 'controles')}: ${listText(controls.map((c) => c.id))}. ` +
                  `El control con más evidencia es ${top.id} ${top.title} (${pl(top.findings.length, 'hallazgo', 'hallazgos')}: ${top.findings.join(', ')}).`,
        };
    }).filter(Boolean);

    const bySev = [5, 4, 3, 2].map((s) => {
        const list = findings.filter((f) => f.severity === s);
        const iso = (d) => (d instanceof Date ? d.toISOString() : String(d || ''));
        const first = list.map((f) => f.due_date).filter(Boolean).sort((a, b) => iso(a).localeCompare(iso(b)))[0];
        return { severity: s, count: list.length, codes: list.map((f) => f.code), due: fmtDate(first) };
    }).filter((x) => x.count);

    const mostExposed = [...data.controls].sort((a, b) => b.findings.length - a.findings.length || b.severity - a.severity)[0];
    const critical = findings.filter((f) => f.severity === 5);

    const conclusion = [
        `La revisión de los registros de la importación #${imp.id} identificó ${pl(data.total, 'hallazgo', 'hallazgos')} de auditoría ` +
        `(${pl(data.deficiencies, 'deficiencia', 'deficiencias')} y ${pl(data.indicators, 'indicador', 'indicadores')}) que afectan a ${pl(data.controls.length, 'control', 'controles')} del Anexo A de ISO/IEC 27001:2022.`,
        critical.length
            ? `${critical.length === 1 ? 'Un hallazgo es crítico' : `${critical.length} hallazgos son críticos`} (${critical.map((f) => f.code).join(', ')}) y debe${critical.length === 1 ? '' : 'n'} remediarse antes del ${fmtDate(critical[0].due_date)}.`
            : 'No se identificaron hallazgos críticos.',
        `El control con más evidencia de deficiencia es ${mostExposed.id} ${mostExposed.title}, con ${pl(mostExposed.findings.length, 'hallazgo', 'hallazgos')}.`,
        'Las causas indicadas son hipótesis: cada hallazgo incluye el procedimiento de verificación necesario para confirmarla antes de cerrar la remediación.',
    ];

    return {
        meta: {
            title: 'Informe de auditoría de controles de seguridad',
            generated_at: new Date().toISOString(), generated_by: generatedBy || null,
            import: imp, period, fingerprint,
        },
        conclusion, bySev, domains, controls: data.controls, findings,
        totals: { total: data.total, deficiencies: data.deficiencies, indicators: data.indicators },
        scope: [
            'Objetivo: evaluar, a partir de la evidencia registrada, si los controles de seguridad impidieron o detectaron la actividad observada.',
            `Alcance: ${imp.rows_valid} eventos del archivo «${imp.file_name}» (hoja «${imp.sheet_name || '—'}»), registrados entre el ${fmtLocal(period.first_at)} y el ${fmtLocal(period.last_at)} (hora de Panamá).`,
            'Criterios: ISO/IEC 27001:2022, Anexo A (se citan número y título de cada control) y CIS Controls v8 como referencia técnica.',
        ],
        limitations: [
            'La evaluación se basa solo en los registros importados: no incluye entrevistas, revisión de configuraciones ni pruebas técnicas sobre los sistemas.',
            'Los controles sin hallazgos no se consideran evaluados: la ausencia de evidencia no demuestra que un control sea eficaz.',
            'La causa de cada hallazgo es una hipótesis hasta que se ejecute su procedimiento de verificación.',
        ],
        methodology: [
            'Evidencia: cada fila del Excel se valida, se normaliza y se conserva intacta, junto con la huella SHA-256 del archivo.',
            'Detección: 18 reglas deterministas generan alertas, cada una con los Log_ID que la sustentan.',
            'Evaluación: un catálogo versionado asocia cada regla a los controles cuya deficiencia explicaría el hallazgo, con su causa probable, verificación y recomendación.',
            'Hallazgos transversales: se evalúa también lo que falta en los datos (por ejemplo, ausencia de eventos de bloqueo de cuenta) y la coherencia del inventario de activos.',
            'Clasificación: la criticidad de cada hallazgo es la de su alerta más grave; el plazo de remediación se fija por criticidad (Crítico 15 días, Alto 30, Medio 60, Bajo 90).',
        ],
    };
};

// ── PDF ──────────────────────────────────────────────────────────────────────

const renderAuditPdf = (r, stream) => {
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
        doc.text(t(text), opts.x ?? L, doc.y, { width: opts.width ?? W, lineGap: 2.5 });
        doc.moveDown(opts.after ?? 0.5);
    };
    const h1 = (text) => {
        ensure(60);
        doc.moveDown(0.6);
        font('Helvetica-Bold', 15, C.brand).text(t(text), L, doc.y, { width: W });
        doc.moveTo(L, doc.y + 3).lineTo(L + W, doc.y + 3).lineWidth(0.8).strokeColor(C.rule).stroke();
        doc.moveDown(0.8);
    };
    const bullet = (text) => {
        ensure(24);
        const y = doc.y;
        font('Helvetica', 10).text('•', L + 2, y);
        doc.text(t(text), L + 12, y, { width: W - 12, lineGap: 2.5 });
        doc.moveDown(0.3);
    };
    const tag = (label, color, x, y) => {
        font('Helvetica-Bold', 8, '#FFFFFF');
        const w = doc.widthOfString(t(label)) + 10;
        doc.roundedRect(x, y, w, 13, 2).fill(color);
        doc.fillColor('#FFFFFF').text(t(label), x + 5, y + 3, { lineBreak: false });
        return w;
    };
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
                font(c.bold ? 'Helvetica-Bold' : c.mono ? 'Courier' : 'Helvetica', c.mono ? size - 0.5 : size);
                return doc.heightOfString(cells[i] || ' ', { width: c.w - pad * 2 });
            })) + pad * 2;
            if (doc.y + hgt > bottom()) { doc.addPage(); header(); }
            const y = doc.y;
            let x = L;
            cols.forEach((c, i) => {
                font(c.bold ? 'Helvetica-Bold' : c.mono ? 'Courier' : 'Helvetica', c.mono ? size - 0.5 : size, c.color ? c.color(row) : C.ink);
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
    const sevColor = (row) => C.sev[row.severity] || C.ink;

    const imp = r.meta.import;

    // ── Portada ─────────────────────────────────────────────────────────────
    doc.rect(0, 0, doc.page.width, 8).fill(C.brand);
    doc.y = 140;
    font('Helvetica-Bold', 11, C.brand).text('SIEM NEXUS · AUDITORÍA', L, doc.y, { characterSpacing: 2 });
    doc.moveDown(0.6);
    font('Helvetica-Bold', 24).text(t(r.meta.title), L, doc.y, { width: W });
    doc.moveDown(0.4);
    font('Helvetica', 12, C.muted).text(t(`Criterio: ISO/IEC 27001:2022, Anexo A · Referencia técnica: CIS Controls v8`), { width: W });
    doc.moveDown(1.6);
    kv([
        ['Archivo evaluado', `${imp.file_name} (hoja «${imp.sheet_name || '—'}»)`],
        ['Importación', `#${imp.id} · ${imp.rows_valid} eventos (${imp.rows_rejected} filas rechazadas)`],
        ['Periodo de los registros', `${fmtLocal(r.meta.period.first_at)} - ${fmtLocal(r.meta.period.last_at)} (hora de Panamá)`],
        ['Hallazgos', `${r.totals.total} (${r.totals.deficiencies} deficiencias, ${r.totals.indicators} indicadores) en ${r.controls.length} controles`],
        ['Generado', `${fmtLocal(r.meta.generated_at)}${r.meta.generated_by ? ` por ${r.meta.generated_by}` : ''}`],
        ['SHA-256 del archivo', imp.file_sha256 || '—'],
        ['Huella de los hallazgos (SHA-256)', r.meta.fingerprint],
    ], 160);
    doc.moveDown(0.6);
    para('Las huellas permiten comprobar que el archivo evaluado y los hallazgos no se modificaron después de emitir este informe. Este documento evalúa controles a partir de evidencia registrada; no es una certificación ni una opinión sobre el sistema de gestión en su conjunto.', { size: 9, color: C.muted });

    // ── 1. Conclusión general ───────────────────────────────────────────────
    doc.addPage();
    h1('1. Conclusión general');
    r.conclusion.forEach((p) => para(p, { size: 10.5 }));
    table([
        { label: 'Criticidad', get: (x) => SEV_LABEL[x.severity], w: 80, bold: true, color: sevColor },
        { label: 'Hallazgos', key: 'count', w: 65 },
        { label: 'Códigos', get: (x) => x.codes.join(', '), w: W - 245, mono: true },
        { label: 'Primer vencimiento', key: 'due', w: 100 },
    ], r.bySev);

    // ── 2. Objetivo, alcance y criterios ────────────────────────────────────
    h1('2. Objetivo, alcance y criterios');
    r.scope.forEach((s) => bullet(s));
    doc.moveDown(0.4);
    font('Helvetica-Bold', 11.5).text('Limitaciones', L, doc.y);
    doc.moveDown(0.35);
    r.limitations.forEach((s) => bullet(s));

    // ── 3. Metodología ──────────────────────────────────────────────────────
    h1('3. Metodología');
    r.methodology.forEach((m, i) => para(`${i + 1}. ${m}`));

    // ── 4. Conclusión por dominio ───────────────────────────────────────────
    h1('4. Conclusión por dominio de control');
    r.domains.forEach((d) => {
        ensure(80);
        const y = doc.y;
        const w = tag(SEV_LABEL[d.worst], C.sev[d.worst], L, y);
        font('Helvetica-Bold', 11.5).text(t(d.name), L + w + 8, y, { width: W - w - 8 });
        doc.moveDown(0.35);
        para(`Valoración: ${d.rating}`, { bold: true, size: 10 });
        para(d.text);
    });
    para('La valoración de cada dominio se limita a los controles con evidencia en los registros.', { size: 8.5, color: C.faint });

    // ── 5. Matriz de controles ──────────────────────────────────────────────
    h1('5. Matriz de controles con hallazgos');
    table([
        { label: 'Control', key: 'id', w: 50, mono: true, bold: true },
        { label: 'Título (ISO/IEC 27001:2022)', key: 'title', w: W - 245 },
        { label: 'Criticidad', get: (c) => SEV_LABEL[c.severity], w: 70, bold: true, color: sevColor },
        { label: 'Hallazgos', get: (c) => c.findings.join(', '), w: 125, mono: true },
    ], r.controls);

    // ── 6. Hallazgos ────────────────────────────────────────────────────────
    h1('6. Hallazgos de auditoría');
    r.findings.forEach((f, idx) => {
        ensure(150);
        if (idx) doc.moveDown(0.5);
        const y = doc.y;
        const w = tag(SEV_LABEL[f.severity], C.sev[f.severity], L, y);
        const w2 = tag(f.finding_type === 'indicador' ? 'Indicador' : 'Deficiencia', C.muted, L + w + 6, y);
        font('Helvetica-Bold', 11.5).text(t(`${f.code} · ${f.iso_detail.map((c) => `${c.id} ${c.title}`).join(' · ')}`),
            L + w + w2 + 14, y, { width: W - w - w2 - 14 });
        doc.moveDown(0.3);
        para(`Estado: ${STATUS[f.status] || f.status} · Responsable: ${f.owner || 'sin asignar'} · Fecha límite: ${fmtDate(f.due_date)} · Catálogo v${f.mapping_version}`,
            { size: 8.5, color: C.muted, after: 0.3 });
        table([
            { label: 'Atributo', key: 'k', w: 130, bold: true },
            { label: 'Detalle', key: 'v', w: W - 130 },
        ], [
            { k: 'Condición (probada)', v: f.condition },
            { k: 'Criterio', v: `ISO/IEC 27001:2022: ${f.iso_detail.map((c) => `${c.id} ${c.title}`).join('; ')}. CIS Controls v8: ${f.cis_safeguards.join(', ')}.` },
            { k: 'Causa probable (hipótesis)', v: f.probable_cause },
            { k: 'Efecto', v: f.effect || '—' },
            { k: 'Recomendación', v: f.recommendation },
            { k: 'Verificación', v: f.verification },
            { k: 'Trazabilidad', v: `${f.incident_ids.length ? `${f.incident_ids.length === 1 ? 'Incidente' : 'Incidentes'} ${f.incident_ids.map((i) => `#${i}`).join(', ')}. ` : ''}` +
                                    `${f.alert_ids.length ? `${f.alert_ids.length === 1 ? 'Alerta' : 'Alertas'} ${f.alert_ids.map((i) => `#${i}`).join(', ')}. ` : ''}` +
                                    `Evidencia: ${pl(f.evidence_log_ids.length, 'registro', 'registros')}, detallados en el anexo.` },
        ], { size: 8.8 });
    });

    // ── 7. Plan de verificación ─────────────────────────────────────────────
    h1('7. Plan de verificación y remediación');
    para('Antes de cerrar cada hallazgo debe ejecutarse su procedimiento de verificación y conservarse la evidencia del cierre.', { size: 9.5, color: C.muted });
    table([
        { label: 'Hallazgo', key: 'code', w: 55, mono: true, bold: true },
        { label: 'Crit.', get: (f) => SEV_LABEL[f.severity], w: 50, bold: true, color: sevColor },
        { label: 'Procedimiento de verificación', key: 'verification', w: W - 245 },
        { label: 'Responsable', get: (f) => f.owner || 'Sin asignar', w: 75 },
        { label: 'Fecha límite', get: (f) => fmtDate(f.due_date), w: 65 },
    ], r.findings, { size: 8 });

    // ── Anexo ───────────────────────────────────────────────────────────────
    doc.addPage();
    h1('Anexo. Evidencia por hallazgo');
    para('Log_ID de los registros del archivo original que sustentan cada hallazgo. La fila completa puede consultarse en la aplicación (Eventos).', { size: 9, color: C.muted });
    r.findings.forEach((f) => {
        ensure(40);
        font('Helvetica-Bold', 9.5).text(t(`${f.code} (${pl(f.evidence_log_ids.length, 'registro', 'registros')})`), L, doc.y);
        doc.moveDown(0.15);
        font('Courier', 7.6, C.muted).text(t(f.evidence_log_ids.join(', ') || '—'), L, doc.y, { width: W, lineGap: 1.5 });
        doc.moveDown(0.6);
    });

    // ── Pie de página ───────────────────────────────────────────────────────
    const range = doc.bufferedPageRange();
    for (let i = range.start; i < range.start + range.count; i++) {
        doc.switchToPage(i);
        doc.page.margins.bottom = 0;
        const y = doc.page.height - 38;
        doc.moveTo(L, y - 6).lineTo(L + W, y - 6).lineWidth(0.4).strokeColor(C.rule).stroke();
        font('Helvetica', 7.5, C.faint);
        doc.text(t(`SIEM NEXUS · Informe de auditoría · Importación #${imp.id} · Huella ${r.meta.fingerprint.slice(0, 16)}`), L, y, { width: W * 0.7, lineBreak: false });
        doc.text(`Página ${i + 1} de ${range.count}`, L + W * 0.7, y, { width: W * 0.3, align: 'right', lineBreak: false });
    }
    doc.end();
};

module.exports = { buildAuditReport, renderAuditPdf };
