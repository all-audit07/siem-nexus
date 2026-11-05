// src/controllers/auditController.js
// v2.0 · Modo auditoría: generación y consulta de hallazgos de auditoría.
const audit = require('../services/auditService');
const { buildAuditReport, renderAuditPdf } = require('../services/auditReportService');
const db    = require('../services/dbAdapter');

const { AuditError } = audit;

const handle = (fn) => async (req, res) => {
    try {
        await fn(req, res);
    } catch (err) {
        if (err instanceof AuditError) return res.status(err.status).json({ error: err.message });
        console.error('[audit]', err.message);
        return res.status(500).json({ error: 'Error interno del servidor' });
    }
};

const parseId = (value) => {
    if (!/^\d+$/.test(String(value))) throw new AuditError('ID inválido', 400);
    return Number(value);
};

// POST /api/imports/:id/audit — genera (o actualiza) los hallazgos de auditoría
const generate = handle(async (req, res) => {
    const importId = parseId(req.params.id);
    const result = await audit.generateFindings(importId);
    try {
        await db.logAuditAction({
            userUuid: req.user.uuid, action: 'audit.generate', targetType: 'log_imports',
            targetId: importId, oldValues: null,
            newValues: { findings: result.total, controls: result.controls.length }, ipAddress: req.ip,
        });
    } catch (e) {
        console.log('Audit log skipped:', e.message);
    }
    res.json(result);
});

// GET /api/imports/:id/audit-findings
const list = handle(async (req, res) => {
    res.json(await audit.listFindings(parseId(req.params.id)));
});

// GET /api/imports/:id/audit-report.pdf — informe de auditoría con los hallazgos actuales
const reportPdf = handle(async (req, res) => {
    const importId = parseId(req.params.id);
    const report = await buildAuditReport(importId, req.user.username);
    try {
        await db.logAuditAction({
            userUuid: req.user.uuid, action: 'audit.report_pdf', targetType: 'log_imports',
            targetId: importId, oldValues: null,
            newValues: { findings: report.totals.total, fingerprint: report.meta.fingerprint }, ipAddress: req.ip,
        });
    } catch (e) {
        console.log('Audit log skipped:', e.message);
    }
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="informe-auditoria-importacion-${importId}.pdf"`);
    res.setHeader('X-Audit-Fingerprint', report.meta.fingerprint);
    renderAuditPdf(report, res);
});

module.exports = { generate, list, reportPdf };
