// src/services/analysisService.js
// Ejecuta las reglas de detección sobre una importación y guarda los resultados:
//   correlation_rules (definición y versión de cada regla)
//   alerts + alert_evidence (cada alerta con los Log_ID que la sustentan)
//   incidents (alertas relacionadas agrupadas por actor: IP externa o cuenta)
// Re-analizar una importación reemplaza sus resultados anteriores (idempotente).

const { pool } = require('../config/postgres');
const { RULES, runRules, SEVERITY_LABEL } = require('./detectionRules');

class AnalysisError extends Error {
    constructor(message, status = 400) {
        super(message);
        this.status = status;
    }
}

const toIso = (ms) => new Date(ms).toISOString();

const loadEvents = async (client, importId) => {
    const { rows } = await client.query(
        `SELECT id, source_log_id, event_type, event_code, severity,
                host(source_ip) AS source_ip, host(dest_ip) AS dest_ip, dest_port,
                hostname, user_name, destination, log_source, description,
                command_line, result, occurred_at
         FROM security_events
         WHERE import_id = $1
         ORDER BY occurred_at, id`, [importId]);
    return rows.map((r) => ({
        id: String(r.id), logId: r.source_log_id, type: r.event_type, code: r.event_code, sev: r.severity,
        srcIp: r.source_ip, destIp: r.dest_ip, destPort: r.dest_port, host: r.hostname, user: r.user_name,
        dest: r.destination, logSource: r.log_source, desc: r.description, cmd: r.command_line,
        result: r.result, at: new Date(r.occurred_at).getTime(),
    }));
};

// Inserta o actualiza cada regla por su código. Devuelve { code: { id, version } }
const upsertRules = async (client) => {
    const map = {};
    for (const r of RULES) {
        const { rows } = await client.query(
            `INSERT INTO correlation_rules
               (code, name, description, pattern, event_types, time_window_secs, threshold,
                is_active, category, severity, version, mitre_techniques)
             VALUES ($1,$2,$3,$4,$5,$6,$7,true,$8,$9,$10,$11)
             ON CONFLICT (code) DO UPDATE SET
               name = EXCLUDED.name, description = EXCLUDED.description, pattern = EXCLUDED.pattern,
               event_types = EXCLUDED.event_types, time_window_secs = EXCLUDED.time_window_secs,
               threshold = EXCLUDED.threshold, category = EXCLUDED.category, severity = EXCLUDED.severity,
               version = EXCLUDED.version, mitre_techniques = EXCLUDED.mitre_techniques
             RETURNING id, version, is_active`,
            [
                r.code,
                `${r.code} · ${r.name}`.slice(0, 100),
                r.description.slice(0, 500),
                JSON.stringify({ params: r.params, tactic: r.tactic }),
                r.eventTypes,
                windowSecs(r.params),
                thresholdOf(r.params),
                r.category, r.severity, r.version, r.mitre,
            ],
        );
        map[r.code] = rows[0];
    }
    return map;
};

const windowSecs = (p) => {
    const min = p.lookbackMin || p.maxGapMin || p.groupGapMin || p.followMin;
    return min ? min * 60 : null;
};
const thresholdOf = (p) => p.minFailures || p.minAccesses || p.minUploads || p.minRequests || p.minPriorFailures || null;

const insertEvidence = async (client, alertId, evidence) => {
    const values = [];
    const ph = evidence.map((ev, i) => {
        values.push(alertId, ev.event.id, ev.role);
        return `($${i * 3 + 1},$${i * 3 + 2},$${i * 3 + 3})`;
    });
    await client.query(
        `INSERT INTO alert_evidence (alert_id, event_id, role) VALUES ${ph.join(',')}`, values);
};

const analyzeImport = async (importId) => {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const imp = await client.query('SELECT id FROM log_imports WHERE id = $1 FOR UPDATE', [importId]);
        if (!imp.rowCount) throw new AnalysisError('Importación no encontrada', 404);

        const events = await loadEvents(client, importId);
        if (!events.length) throw new AnalysisError('La importación no tiene eventos', 422);

        const { findings, incidents } = runRules(events);

        // Reemplaza resultados anteriores de esta importación
        await client.query('DELETE FROM alerts    WHERE import_id = $1', [importId]);
        await client.query('DELETE FROM incidents WHERE import_id = $1', [importId]);

        const rules = await upsertRules(client);
        const analyzedAt = new Date().toISOString();

        // Solo se guardan hallazgos de reglas activas (permite desactivar reglas desde la BD)
        const active = (f) => rules[f.rule.code]?.is_active !== false;

        for (const inc of incidents) {
            const list = inc.findings.filter(active);
            if (!list.length) continue;

            const { rows: [incRow] } = await client.query(
                `INSERT INTO incidents
                   (import_id, rule_id, title, severity, affected_assets, mitre_tactics, timeline, metadata)
                 VALUES ($1,$2,$3,$4,$5,$6,
                         tsrange(($7::timestamptz AT TIME ZONE 'UTC'), ($8::timestamptz AT TIME ZONE 'UTC'), '[]'),
                         $9)
                 RETURNING id`,
                [importId, rules[inc.rule.code].id, inc.title, Math.max(...list.map((f) => f.severity)),
                 inc.affectedAssets, inc.mitreTactics, toIso(inc.start), toIso(inc.end),
                 JSON.stringify({ ...inc.metadata, alert_count: list.length, timezone: 'UTC' })],
            );

            for (const f of list) {
                const trigger = f.evidence.find((e) => e.role === 'trigger').event;
                const { rows: [alertRow] } = await client.query(
                    `INSERT INTO alerts
                       (import_id, event_id, title, description, severity, status, rule_id, rule_version,
                        incident_id, justification, window_start, window_end, analyzed_at)
                     VALUES ($1,$2,$3,$4,$5,'open',$6,$7,$8,$9,$10,$11,$12)
                     RETURNING id`,
                    [importId, trigger.id, f.title.slice(0, 150), f.rule.name.slice(0, 2000), f.severity,
                     rules[f.rule.code].id, rules[f.rule.code].version, incRow.id, f.justification,
                     toIso(f.windowStart), toIso(f.windowEnd), analyzedAt],
                );
                await insertEvidence(client, alertRow.id, f.evidence);
            }
        }

        await client.query(
            `UPDATE log_imports SET status = 'analyzed', analyzed_at = $2 WHERE id = $1`, [importId, analyzedAt]);

        await client.query('COMMIT');

        const saved = findings.filter(active);
        const bySeverity = {};
        for (const f of saved) {
            const label = SEVERITY_LABEL[f.severity];
            bySeverity[label] = (bySeverity[label] || 0) + 1;
        }
        return {
            importId,
            analyzedAt,
            eventsAnalyzed: events.length,
            alerts: saved.length,
            incidents: incidents.filter((i) => i.findings.some(active)).length,
            alertsBySeverity: bySeverity,
            rulesEvaluated: RULES.filter((r) => rules[r.code]?.is_active !== false).map((r) => r.code),
        };
    } catch (err) {
        await client.query('ROLLBACK');
        throw err;
    } finally {
        client.release();
    }
};

// ── Consultas para la interfaz ───────────────────────────────────────────────

const ALERT_SELECT = `
    SELECT a.id, a.uuid, a.title, a.description, a.severity, a.status, a.justification,
           a.window_start, a.window_end, a.analyzed_at, a.incident_id, a.rule_version,
           r.code AS rule_code, r.name AS rule_name, r.category, r.mitre_techniques,
           COALESCE(json_agg(json_build_object(
               'log_id', se.source_log_id, 'event_id', se.id, 'role', ae.role,
               'occurred_at', se.occurred_at, 'event_type', se.event_type, 'hostname', se.hostname,
               'user_name', se.user_name, 'source_ip', host(se.source_ip), 'description', se.description,
               'command_line', se.command_line
           ) ORDER BY se.occurred_at, se.id) FILTER (WHERE se.id IS NOT NULL), '[]') AS evidence
    FROM alerts a
    LEFT JOIN correlation_rules r ON r.id = a.rule_id
    LEFT JOIN alert_evidence ae   ON ae.alert_id = a.id
    LEFT JOIN security_events se  ON se.id = ae.event_id`;

const listAlerts = async (importId, { severity, category, incidentId } = {}) => {
    const where = ['a.import_id = $1'];
    const params = [importId];
    if (severity)   { params.push(severity);   where.push(`a.severity = $${params.length}`); }
    if (category)   { params.push(category);   where.push(`r.category = $${params.length}`); }
    if (incidentId) { params.push(incidentId); where.push(`a.incident_id = $${params.length}`); }
    const { rows } = await pool.query(
        `${ALERT_SELECT} WHERE ${where.join(' AND ')}
         GROUP BY a.id, r.id ORDER BY a.severity DESC, a.window_start`, params);
    return rows;
};

const getAlert = async (alertId) => {
    const { rows } = await pool.query(`${ALERT_SELECT} WHERE a.id = $1 GROUP BY a.id, r.id`, [alertId]);
    return rows[0] || null;
};

const listIncidents = async (importId) => {
    const { rows } = await pool.query(
        `SELECT i.id, i.uuid, i.title, i.severity, i.status, i.affected_assets, i.mitre_tactics,
                (lower(i.timeline) AT TIME ZONE 'UTC') AS start_at,
                (upper(i.timeline) AT TIME ZONE 'UTC') AS end_at, i.metadata, i.created_at,
                count(a.id)::int AS alert_count,
                COALESCE(json_agg(json_build_object('id', a.id, 'title', a.title, 'severity', a.severity)
                         ORDER BY a.window_start) FILTER (WHERE a.id IS NOT NULL), '[]') AS alerts
         FROM incidents i
         LEFT JOIN alerts a ON a.incident_id = i.id
         WHERE i.import_id = $1
         GROUP BY i.id
         ORDER BY i.severity DESC, lower(i.timeline)`, [importId]);
    return rows;
};

const listRules = async () => {
    const { rows } = await pool.query(
        `SELECT id, code, name, description, category, severity, version, mitre_techniques,
                pattern, event_types, time_window_secs, threshold, is_active
         FROM correlation_rules WHERE code IS NOT NULL ORDER BY code`);
    return rows;
};

module.exports = { AnalysisError, analyzeImport, listAlerts, getAlert, listIncidents, listRules };
