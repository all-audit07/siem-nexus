const db = require('../services/dbAdapter');

const getSummary = async (req, res) => {
    try {
        const summary = await db.getDashboardSummary();
        return res.json(summary);
    } catch (err) {
        console.error('[getSummary]', err.message);
        return res.status(500).json({ error: err.message });
    }
};

const getIncidents = async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 10;
        const data = await db.getRecentIncidents(limit);
        return res.json(data);
    } catch (err) {
        console.error('[getIncidents]', err.message);
        return res.status(500).json({ error: err.message });
    }
};

const getAlerts = async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 20;
        const data = await db.getOpenAlertsWithAnalyst(limit);
        return res.json(data);
    } catch (err) {
        console.error('[getAlerts]', err.message);
        return res.status(500).json({ error: err.message });
    }
};

const updateAlertStatus = async (req, res) => {
    try {
        const { id } = req.params;
        const { status } = req.body;
        const validStatuses = ['open','acknowledged','investigating','resolved','false_positive'];
        if (!validStatuses.includes(status)) {
            return res.status(400).json({ error: 'Estado inválido' });
        }
        const updated = await db.updateAlertStatus(parseInt(id), status, req.user.uuid, req.ip);
        return res.json(updated);
    } catch (err) {
        console.error('[updateAlertStatus]', err.message);
        return res.status(500).json({ error: err.message });
    }
};

const getEvents = async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 20;
        const data = await db.getCriticalEvents(limit);
        return res.json(data);
    } catch (err) {
        console.error('[getEvents]', err.message);
        return res.status(500).json({ error: err.message });
    }
};

const getVulnerabilities = async (req, res) => {
    try {
        const data = await db.getCriticalVulnerabilities();
        return res.json(data);
    } catch (err) {
        console.error('[getVulnerabilities]', err.message);
        return res.status(500).json({ error: err.message });
    }
};

const getActivity = async (req, res) => {
    try {
        const data = await db.getAnalystActivity();
        return res.json(data);
    } catch (err) {
        console.error('[getActivity]', err.message);
        return res.status(500).json({ error: err.message });
    }
};

const getAuditLogs = async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 15;
        const data = await db.getRecentAuditLogs(limit);
        return res.json(data);
    } catch (err) {
        console.error('[getAuditLogs]', err.message);
        return res.status(500).json({ error: err.message });
    }
};

const getAnalystProfile = async (req, res) => {
    try {
        const { uuid } = req.params;
        const data = await db.getAnalystCrossMotorProfile(uuid);
        if (!data) return res.status(404).json({ error: 'Analista no encontrado' });
        return res.json(data);
    } catch (err) {
        console.error('[getAnalystProfile]', err.message);
        return res.status(500).json({ error: err.message });
    }
};

module.exports = {
    getSummary, getIncidents, getAlerts, updateAlertStatus,
    getEvents, getVulnerabilities, getActivity, getAuditLogs, getAnalystProfile,
};
