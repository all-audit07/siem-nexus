// src/services/eventsService.js
// Consultas de lectura sobre una importación: explorador de eventos y resumen del dashboard.
// Todo se calcula a partir de los registros importados y de los resultados del análisis.

const { pool } = require('../config/postgres');

class QueryError extends Error {
    constructor(message, status = 400) { super(message); this.status = status; }
}

const PRIVATE_NET = `(%s << inet '10.0.0.0/8' OR %s << inet '172.16.0.0/12' OR %s << inet '192.168.0.0/16'
                      OR %s << inet '127.0.0.0/8' OR family(%s) = 6)`;
const isPrivate = (col) => PRIVATE_NET.replace(/%s/g, col);

const assertImport = async (importId) => {
    const { rows } = await pool.query(
        `SELECT id, file_name, sheet_name, source_timezone, rows_total, rows_valid, rows_rejected,
                status, imported_at, analyzed_at
         FROM log_imports WHERE id = $1`, [importId]);
    if (!rows.length) throw new QueryError('Importación no encontrada', 404);
    return rows[0];
};

// ── Explorador de eventos ────────────────────────────────────────────────────

const listEvents = async (importId, f) => {
    await assertImport(importId);

    const params = [importId];
    const where = ['se.import_id = $1'];
    const add = (sql, value) => { params.push(value); where.push(sql.replace('?', `$${params.length}`)); };

    if (f.type)     add('se.event_type = ?', f.type);
    if (f.host)     add('se.hostname = ?', f.host);
    if (f.user)     add('se.user_name = ?', f.user);
    if (f.source)   add('se.log_source = ?', f.source);
    if (f.severity) add('se.severity = ?', f.severity);
    if (f.ip) {
        params.push(f.ip);
        const n = params.length;
        where.push(`(host(se.source_ip) = $${n} OR host(se.dest_ip) = $${n} OR se.destination ILIKE '%' || $${n} || '%')`);
    }
    if (f.q) {
        params.push(`%${f.q}%`);
        const n = params.length;
        where.push(`(se.source_log_id ILIKE $${n} OR se.description ILIKE $${n} OR se.command_line ILIKE $${n}
                     OR se.user_name ILIKE $${n} OR se.hostname ILIKE $${n} OR se.destination ILIKE $${n}
                     OR host(se.source_ip) ILIKE $${n})`);
    }
    if (f.flagged === true)  where.push('EXISTS (SELECT 1 FROM alert_evidence ae WHERE ae.event_id = se.id)');
    if (f.flagged === false) where.push('NOT EXISTS (SELECT 1 FROM alert_evidence ae WHERE ae.event_id = se.id)');

    const whereSql = where.join(' AND ');
    const total = Number((await pool.query(`SELECT count(*) FROM security_events se WHERE ${whereSql}`, params)).rows[0].count);

    params.push(f.limit, (f.page - 1) * f.limit);
    const { rows } = await pool.query(
        `SELECT se.id, se.source_log_id AS log_id, se.occurred_at, se.event_type, se.event_code, se.severity,
                se.source_severity, se.hostname, se.user_name, host(se.source_ip) AS source_ip,
                se.destination, se.log_source, se.description, se.command_line, se.result, se.raw_payload,
                COALESCE((SELECT json_agg(json_build_object('id', a.id, 'title', a.title, 'severity', a.severity,
                                                            'role', ae.role, 'rule_code', r.code)
                                          ORDER BY a.severity DESC, a.id)
                          FROM alert_evidence ae
                          JOIN alerts a ON a.id = ae.alert_id
                          LEFT JOIN correlation_rules r ON r.id = a.rule_id
                          WHERE ae.event_id = se.id), '[]') AS alerts
         FROM security_events se
         WHERE ${whereSql}
         ORDER BY se.occurred_at, se.id
         LIMIT $${params.length - 1} OFFSET $${params.length}`, params);

    const facet = async (col) => (await pool.query(
        `SELECT ${col} AS value, count(*)::int AS total FROM security_events
         WHERE import_id = $1 AND ${col} IS NOT NULL GROUP BY 1 ORDER BY 2 DESC, 1`, [importId])).rows;

    return {
        total, page: f.page, limit: f.limit, rows,
        facets: {
            event_types: await facet('event_type'),
            hosts:       await facet('hostname'),
            users:       await facet('user_name'),
            log_sources: await facet('log_source'),
        },
    };
};

// ── Resumen para el dashboard ────────────────────────────────────────────────

const getSummary = async (importId) => {
    const imp = await assertImport(importId);
    const q = async (sql, p = [importId]) => (await pool.query(sql, p)).rows;

    const [events] = await q(
        `SELECT count(*)::int AS total, min(occurred_at) AS first_at, max(occurred_at) AS last_at,
                count(DISTINCT hostname)::int AS hosts, count(DISTINCT user_name)::int AS users,
                count(DISTINCT source_ip) FILTER (WHERE source_ip IS NOT NULL AND NOT ${isPrivate('source_ip')})::int AS external_sources,
                count(*) FILTER (WHERE event_type = 'logon_failure')::int AS logon_failures
         FROM security_events WHERE import_id = $1`);

    const byType = await q(
        `SELECT event_type, count(*)::int AS total FROM security_events
         WHERE import_id = $1 GROUP BY 1 ORDER BY 2 DESC`);

    const bySensor = await q(
        `SELECT severity, source_severity AS label, count(*)::int AS total FROM security_events
         WHERE import_id = $1 GROUP BY 1, 2 ORDER BY 1 DESC`);

    // Eventos cada 10 minutos (incluye intervalos vacíos) y cuántos de ellos son evidencia de alertas
    const timeline = events.total ? await q(
        `WITH b AS (
             SELECT generate_series(date_bin('10 minutes', min(occurred_at), timestamptz '2000-01-01'),
                                    max(occurred_at), interval '10 minutes') AS bucket
             FROM security_events WHERE import_id = $1)
         SELECT b.bucket,
                count(se.id)::int AS total,
                count(se.id) FILTER (WHERE EXISTS (SELECT 1 FROM alert_evidence ae WHERE ae.event_id = se.id))::int AS flagged
         FROM b
         LEFT JOIN security_events se
                ON se.import_id = $1 AND se.occurred_at >= b.bucket AND se.occurred_at < b.bucket + interval '10 minutes'
         GROUP BY b.bucket ORDER BY b.bucket`) : [];

    const alerts = await q(
        `SELECT a.id, a.title, a.severity, a.window_start, a.window_end, a.incident_id,
                r.code AS rule_code, r.category
         FROM alerts a LEFT JOIN correlation_rules r ON r.id = a.rule_id
         WHERE a.import_id = $1 ORDER BY a.window_start, a.id`);

    const incidents = await q(
        `SELECT i.id, i.title, i.severity, i.status,
                (lower(i.timeline) AT TIME ZONE 'UTC') AS start_at,
                (upper(i.timeline) AT TIME ZONE 'UTC') AS end_at,
                (SELECT count(*)::int FROM alerts a WHERE a.incident_id = i.id) AS alert_count
         FROM incidents i WHERE i.import_id = $1 ORDER BY i.severity DESC, lower(i.timeline)`);

    // Entidades presentes en la evidencia de las alertas (disparador o soporte; no contexto)
    const topEntity = (expr, extra = '') => q(
        `SELECT ${expr} AS value, count(DISTINCT a.id)::int AS alerts, max(a.severity)::int AS max_severity
         FROM alerts a
         JOIN alert_evidence ae ON ae.alert_id = a.id AND ae.role <> 'context'
         JOIN security_events se ON se.id = ae.event_id
         WHERE a.import_id = $1 AND ${expr} IS NOT NULL ${extra}
         GROUP BY 1 ORDER BY 2 DESC, 3 DESC, 1 LIMIT 8`);

    const topExternalIps = await q(
        `SELECT ip AS value, count(DISTINCT alert_id)::int AS alerts, max(severity)::int AS max_severity
         FROM (
             SELECT a.id AS alert_id, a.severity, host(se.source_ip) AS ip
             FROM alerts a JOIN alert_evidence ae ON ae.alert_id = a.id
             JOIN security_events se ON se.id = ae.event_id
             WHERE a.import_id = $1 AND se.source_ip IS NOT NULL AND NOT ${isPrivate('se.source_ip')}
             UNION ALL
             SELECT a.id, a.severity, host(se.dest_ip)
             FROM alerts a JOIN alert_evidence ae ON ae.alert_id = a.id
             JOIN security_events se ON se.id = ae.event_id
             WHERE a.import_id = $1 AND se.dest_ip IS NOT NULL AND NOT ${isPrivate('se.dest_ip')}
         ) x GROUP BY 1 ORDER BY 2 DESC, 3 DESC, 1 LIMIT 8`);

    const severityCount = (list) => {
        const out = { 5: 0, 4: 0, 3: 0, 2: 0 };
        list.forEach((x) => { out[x.severity] = (out[x.severity] || 0) + 1; });
        return out;
    };
    const byCategory = {};
    alerts.forEach((a) => { byCategory[a.category] = (byCategory[a.category] || 0) + 1; });

    return {
        import: imp,
        events: { ...events, by_type: byType, by_sensor_severity: bySensor },
        timeline,
        alerts: {
            total: alerts.length,
            by_severity: severityCount(alerts),
            by_category: Object.entries(byCategory).map(([category, total]) => ({ category, total }))
                .sort((x, y) => y.total - x.total),
            list: alerts,
        },
        incidents: { total: incidents.length, by_severity: severityCount(incidents), list: incidents },
        top: {
            hosts:        await topEntity('se.hostname'),
            users:        await topEntity('se.user_name'),
            external_ips: topExternalIps,
        },
    };
};

module.exports = { QueryError, listEvents, getSummary };
