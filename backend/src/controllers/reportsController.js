// src/controllers/reportsController.js
const reports = require('../services/reportService');
const { renderReportPdf } = require('../services/pdfService');
const db = require('../services/dbAdapter');

const { ReportError } = reports;

const handle = (fn) => async (req, res) => {
    try {
        await fn(req, res);
    } catch (err) {
        if (err instanceof ReportError || err.status) return res.status(err.status || 400).json({ error: err.message });
        console.error('[reports]', err.message);
        if (!res.headersSent) res.status(500).json({ error: 'Error interno del servidor' });
    }
};

const parseId = (value) => {
    if (!/^\d+$/.test(String(value))) throw new ReportError('ID inválido', 400);
    return Number(value);
};

// POST /api/imports/:id/reports  { useAi: boolean }
const create = handle(async (req, res) => {
    const importId = parseId(req.params.id);
    const report = await reports.createReport(importId, { useAi: req.body?.useAi === true, user: req.user });
    try {
        await db.logAuditAction({
            userUuid: req.user.uuid, action: 'report.create', targetType: 'reports', targetId: report.id,
            oldValues: null, newValues: { importId, ai: report.content.ai.used }, ipAddress: req.ip,
        });
    } catch (e) {
        console.log('Audit log skipped:', e.message);
    }
    res.status(201).json({ id: report.id, uuid: report.uuid, created_at: report.created_at, ai: report.content.ai });
});

// GET /api/imports/:id/reports
const list = handle(async (req, res) => {
    res.json(await reports.listReports(parseId(req.params.id)));
});

// GET /api/analysis/reports/:id
const getOne = handle(async (req, res) => {
    const report = await reports.getReport(parseId(req.params.id));
    if (!report) return res.status(404).json({ error: 'Informe no encontrado' });
    res.json(report);
});

// GET /api/analysis/reports/:id/pdf
const pdf = handle(async (req, res) => {
    const report = await reports.getReport(parseId(req.params.id));
    if (!report) return res.status(404).json({ error: 'Informe no encontrado' });
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="informe-siem-${report.id}-importacion-${report.import_id}.pdf"`);
    renderReportPdf(report, res);
});

module.exports = { create, list, getOne, pdf };
