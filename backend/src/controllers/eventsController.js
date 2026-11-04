// src/controllers/eventsController.js
const svc = require('../services/eventsService');

const { QueryError } = svc;

const handle = (fn) => async (req, res) => {
    try {
        await fn(req, res);
    } catch (err) {
        if (err instanceof QueryError) return res.status(err.status).json({ error: err.message });
        console.error('[events]', err.message);
        return res.status(500).json({ error: 'Error interno del servidor' });
    }
};

const parseId = (value) => {
    if (!/^\d+$/.test(String(value))) throw new QueryError('ID inválido', 400);
    return Number(value);
};

const text = (v, max = 200) => (typeof v === 'string' && v.trim() ? v.trim().slice(0, max) : null);

// GET /api/imports/:id/events?q=&type=&host=&user=&ip=&source=&severity=&flagged=&page=&limit=
const events = handle(async (req, res) => {
    const importId = parseId(req.params.id);
    const page  = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(200, Math.max(1, parseInt(req.query.limit, 10) || 50));
    let severity = null;
    if (req.query.severity) {
        severity = Number(req.query.severity);
        if (![1, 2, 3, 4, 5].includes(severity)) throw new QueryError('severity debe estar entre 1 y 5', 400);
    }
    const flagged = req.query.flagged === 'true' ? true : req.query.flagged === 'false' ? false : null;
    res.json(await svc.listEvents(importId, {
        q: text(req.query.q), type: text(req.query.type), host: text(req.query.host),
        user: text(req.query.user), ip: text(req.query.ip, 45), source: text(req.query.source),
        severity, flagged, page, limit,
    }));
});

// GET /api/imports/:id/summary — datos del dashboard
const summary = handle(async (req, res) => {
    res.json(await svc.getSummary(parseId(req.params.id)));
});

module.exports = { events, summary };
