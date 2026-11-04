// src/controllers/analysisController.js
const analysis = require('../services/analysisService');
const db       = require('../services/dbAdapter');

const { AnalysisError } = analysis;

const SEVERITIES = { bajo: 2, medio: 3, alto: 4, critico: 5, 'crítico': 5 };
const CATEGORIES = ['brute_force', 'suspicious_login', 'privilege_escalation',
                    'process_execution', 'lateral_movement', 'anomaly'];

const handle = (fn) => async (req, res) => {
    try {
        await fn(req, res);
    } catch (err) {
        if (err instanceof AnalysisError) return res.status(err.status).json({ error: err.message });
        console.error('[analysis]', err.message);
        return res.status(500).json({ error: 'Error interno del servidor' });
    }
};

const parseId = (value) => {
    if (!/^\d+$/.test(String(value))) throw new AnalysisError('ID inválido', 400);
    return Number(value);
};

// POST /api/imports/:id/analyze — ejecuta las reglas y guarda alertas e incidentes
const analyze = handle(async (req, res) => {
    const importId = parseId(req.params.id);
    const result = await analysis.analyzeImport(importId);
    try {
        await db.logAuditAction({
            userUuid: req.user.uuid, action: 'import.analyze', targetType: 'log_imports',
            targetId: importId, oldValues: null,
            newValues: { alerts: result.alerts, incidents: result.incidents }, ipAddress: req.ip,
        });
    } catch (e) {
        console.log('Audit log skipped:', e.message);
    }
    res.json(result);
});

// GET /api/imports/:id/alerts?severity=alto&category=brute_force&incident=3
const alerts = handle(async (req, res) => {
    const importId = parseId(req.params.id);
    const filters = {};
    if (req.query.severity) {
        const sev = SEVERITIES[String(req.query.severity).toLowerCase()] || Number(req.query.severity);
        if (![2, 3, 4, 5].includes(sev)) throw new AnalysisError('severity debe ser bajo, medio, alto o critico', 400);
        filters.severity = sev;
    }
    if (req.query.category) {
        if (!CATEGORIES.includes(req.query.category)) throw new AnalysisError(`category debe ser: ${CATEGORIES.join(', ')}`, 400);
        filters.category = req.query.category;
    }
    if (req.query.incident) filters.incidentId = parseId(req.query.incident);
    res.json(await analysis.listAlerts(importId, filters));
});

// GET /api/imports/:id/incidents
const incidents = handle(async (req, res) => {
    res.json(await analysis.listIncidents(parseId(req.params.id)));
});

// GET /api/analysis/alerts/:id — detalle con evidencia completa
const alertDetail = handle(async (req, res) => {
    const alert = await analysis.getAlert(parseId(req.params.id));
    if (!alert) return res.status(404).json({ error: 'Alerta no encontrada' });
    res.json(alert);
});

// GET /api/analysis/rules — reglas, umbrales y versiones
const rules = handle(async (req, res) => {
    res.json(await analysis.listRules());
});

module.exports = { analyze, alerts, incidents, alertDetail, rules };
