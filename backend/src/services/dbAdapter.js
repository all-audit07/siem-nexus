const mysql = require('../config/mysql');
const pg    = require('../config/postgres');
const mssql = require('../config/sqlserver');

// ── MySQL ────────────────────────────────────────────────────

const getUserByUsername = async (username) => {
    const [rows] = await mysql.pool.execute(
        `SELECT u.uuid, u.username, u.email, u.password_hash, u.full_name, u.birth_date, u.avatar_path, u.status,
                COALESCE((
                    SELECT r.name FROM user_roles ur
                    JOIN roles r ON r.id = ur.role_id
                    WHERE ur.user_id = u.id AND ur.is_active = 1
                    ORDER BY FIELD(r.name,'admin','responder','analyst','auditor','viewer')
                    LIMIT 1
                ), 'analyst') AS role
         FROM users u WHERE u.username = ? LIMIT 1`,
        [username]
    );
    return rows[0] || null;
};

const getUserByUUID = async (uuid) => {
    const [rows] = await mysql.pool.execute(
        `SELECT u.uuid, u.username, u.email, u.full_name, u.status,
                COALESCE((
                    SELECT r.name FROM user_roles ur
                    JOIN roles r ON r.id = ur.role_id
                    WHERE ur.user_id = u.id AND ur.is_active = 1
                    ORDER BY FIELD(r.name,'admin','responder','analyst','auditor','viewer')
                    LIMIT 1
                ), 'analyst') AS role
         FROM users u WHERE u.uuid = ? LIMIT 1`,
        [uuid]
    );
    return rows[0] || null;
};

const getAllUsers = async () => {
    const [rows] = await mysql.pool.execute(
        `SELECT u.uuid, u.username, u.email, u.full_name, u.status, u.created_at,
                COALESCE((
                    SELECT r.name FROM user_roles ur
                    JOIN roles r ON r.id = ur.role_id
                    WHERE ur.user_id = u.id AND ur.is_active = 1
                    ORDER BY FIELD(r.name,'admin','responder','analyst','auditor','viewer')
                    LIMIT 1
                ), 'analyst') AS role
         FROM users u WHERE u.status = 'active' ORDER BY u.created_at DESC`
    );
    return rows;
};

// ── PostgreSQL ───────────────────────────────────────────────

const getDashboardSummary = async () => {
    const client = await pg.pool.connect();
    try {
        const [incidents, alerts, events, vulns] = await Promise.all([
            client.query(`
                SELECT
                    COUNT(*) FILTER (WHERE status = 'open')          AS open_incidents,
                    COUNT(*) FILTER (WHERE status = 'investigating')  AS investigating,
                    COUNT(*) FILTER (WHERE status = 'contained')      AS contained,
                    COUNT(*) FILTER (WHERE status = 'resolved')       AS resolved,
                    COUNT(*)                                           AS total
                FROM incidents
            `),
            client.query(`
                SELECT
                    COUNT(*) FILTER (WHERE status = 'open')           AS open_alerts,
                    COUNT(*) FILTER (WHERE severity >= 4)              AS critical_alerts,
                    COUNT(*) FILTER (WHERE false_positive = true)      AS false_positives,
                    COUNT(*)                                            AS total
                FROM alerts
            `),
            client.query(`
                SELECT
                    COUNT(*) FILTER (WHERE occurred_at >= NOW() - INTERVAL '24 hours') AS last_24h,
                    COUNT(*) FILTER (WHERE severity = 5)               AS critical,
                    COUNT(*) FILTER (WHERE severity = 4)               AS high,
                    COUNT(*)                                            AS total
                FROM security_events
            `),
            client.query(`
                SELECT
                    COUNT(*) FILTER (WHERE status = 'open' AND cvss_score >= 7) AS critical_open,
                    COUNT(*) FILTER (WHERE status = 'open')            AS total_open,
                    COUNT(*)                                            AS total
                FROM vulnerabilities
            `)
        ]);
        return {
            incidents:       incidents.rows[0],
            alerts:          alerts.rows[0],
            security_events: events.rows[0],
            vulnerabilities: vulns.rows[0],
        };
    } finally {
        client.release();
    }
};

const getRecentIncidents = async (limit = 10) => {
    const { rows } = await pg.pool.query(
        `SELECT * FROM v_incidents_summary ORDER BY created_at DESC LIMIT $1`,
        [limit]
    );
    return rows;
};

const getOpenAlertsWithAnalyst = async (limit = 20) => {
    const { rows: alerts } = await pg.pool.query(`
        SELECT a.id, a.uuid, a.title, a.severity, a.status,
               a.assigned_to_uuid, a.false_positive, a.created_at,
               se.event_type, se.source_ip::TEXT AS source_ip
        FROM alerts a
        LEFT JOIN security_events se ON se.id = a.event_id
        WHERE a.status NOT IN ('resolved', 'false_positive')
        ORDER BY a.severity DESC, a.created_at DESC
        LIMIT $1
    `, [limit]);

    if (alerts.length === 0) return [];

    const uuids = [...new Set(alerts.filter(a => a.assigned_to_uuid).map(a => a.assigned_to_uuid))];
    let analystMap = {};
    if (uuids.length > 0) {
        const placeholders = uuids.map(() => '?').join(',');
        const [users] = await mysql.pool.execute(
            `SELECT uuid, username, full_name FROM users WHERE uuid IN (${placeholders})`,
            uuids
        );
        users.forEach(u => { analystMap[u.uuid] = u; });
    }

    return alerts.map(alert => ({
        ...alert,
        analyst: alert.assigned_to_uuid ? analystMap[alert.assigned_to_uuid] || null : null,
    }));
};

const getRecentAuditLogs = async (limit = 15) => {
    const { rows: logs } = await pg.pool.query(`
        SELECT id, user_uuid, action, target_type, target_id,
               new_values, ip_address::TEXT AS ip_address, occurred_at
        FROM audit_logs ORDER BY occurred_at DESC LIMIT $1
    `, [limit]);

    if (logs.length === 0) return [];

    const uuids = [...new Set(logs.filter(l => l.user_uuid).map(l => l.user_uuid))];
    let analystMap = {};
    if (uuids.length > 0) {
        const placeholders = uuids.map(() => '?').join(',');
        const [users] = await mysql.pool.execute(
            `SELECT uuid, username, full_name FROM users WHERE uuid IN (${placeholders})`,
            uuids
        );
        users.forEach(u => { analystMap[u.uuid] = u; });
    }

    return logs.map(log => ({
        ...log,
        analyst: log.user_uuid ? analystMap[log.user_uuid] || null : null,
    }));
};

const getCriticalVulnerabilities = async (limit = 10) => {
    const { rows } = await pg.pool.query(
        `SELECT * FROM v_open_vulnerabilities WHERE cvss_score >= 7.0 ORDER BY cvss_score DESC LIMIT $1`,
        [limit]
    );
    return rows;
};

const getCriticalEvents = async (limit = 20) => {
    const { rows } = await pg.pool.query(
        `SELECT * FROM v_critical_events ORDER BY occurred_at DESC LIMIT $1`,
        [limit]
    );
    return rows;
};

const getAnalystActivity = async () => {
    const { rows } = await pg.pool.query(
        `SELECT * FROM v_analyst_activity ORDER BY total_actions DESC LIMIT 10`
    );
    if (rows.length === 0) return [];

    const uuids = rows.filter(r => r.user_uuid).map(r => r.user_uuid);
    let analystMap = {};
    if (uuids.length > 0) {
        const placeholders = uuids.map(() => '?').join(',');
        const [users] = await mysql.pool.execute(
            `SELECT uuid, username, full_name FROM users WHERE uuid IN (${placeholders})`,
            uuids
        );
        users.forEach(u => { analystMap[u.uuid] = u; });
    }
    return rows.map(row => ({ ...row, analyst: analystMap[row.user_uuid] || null }));
};

const getAnalystCrossMotorProfile = async (uuid) => {
    const client = await pg.pool.connect();
    try {
        const [mysqlRows] = await mysql.pool.execute(
            `SELECT u.uuid, u.username, u.email, u.full_name, u.status, u.created_at,
                    COALESCE((
                        SELECT r.name FROM user_roles ur
                        JOIN roles r ON r.id = ur.role_id
                        WHERE ur.user_id = u.id AND ur.is_active = 1
                        ORDER BY FIELD(r.name,'admin','responder','analyst','auditor','viewer')
                        LIMIT 1
                    ), 'analyst') AS role
             FROM users u WHERE u.uuid = ? LIMIT 1`,
            [uuid]
        );
        const analyst = mysqlRows[0] || null;
        if (!analyst) return null;

        const [alertsRes, incidentsRes, auditRes] = await Promise.all([
            client.query(`SELECT title, severity, status, created_at FROM alerts WHERE assigned_to_uuid = $1 ORDER BY created_at DESC LIMIT 5`, [uuid]),
            client.query(`SELECT title, severity, status::TEXT, correlation_score, created_at FROM incidents WHERE assigned_to_uuid = $1 ORDER BY created_at DESC LIMIT 5`, [uuid]),
            client.query(`SELECT action, target_type, target_id, occurred_at FROM audit_logs WHERE user_uuid = $1 ORDER BY occurred_at DESC LIMIT 10`, [uuid]),
        ]);

        return {
            analyst,
            postgres: {
                alerts:     alertsRes.rows,
                incidents:  incidentsRes.rows,
                audit_logs: auditRes.rows,
            },
            meta: {
                cross_motor_key: uuid,
                mysql_source:    'siem_benchmark.users',
                pg_targets:      ['alerts', 'incidents', 'audit_logs'],
            }
        };
    } finally {
        client.release();
    }
};

// ── Escritura ─────────────────────────────────────────────────

const logAuditAction = async ({ userUuid, action, targetType, targetId, oldValues, newValues, ipAddress }) => {
    await pg.pool.query(`
        INSERT INTO audit_logs (user_uuid, action, target_type, target_id, old_values, new_values, ip_address)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
    `, [
        userUuid, action, targetType || null, targetId || null,
        oldValues ? JSON.stringify(oldValues) : null,
        newValues ? JSON.stringify(newValues) : null,
        ipAddress || null,
    ]);
};

const updateAlertStatus = async (alertId, newStatus, userUuid, ipAddress) => {
    const { rows } = await pg.pool.query(`SELECT status FROM alerts WHERE id = $1`, [alertId]);
    if (!rows.length) throw new Error('Alerta no encontrada');
    const oldStatus = rows[0].status;
    const { rows: updated } = await pg.pool.query(`
        UPDATE alerts SET status = $1,
            resolved_at = CASE WHEN $1 IN ('resolved','false_positive') THEN NOW() ELSE resolved_at END
        WHERE id = $2 RETURNING *
    `, [newStatus, alertId]);
    await logAuditAction({ userUuid, action: 'alert_status_change', targetType: 'alerts', targetId: alertId, oldValues: { status: oldStatus }, newValues: { status: newStatus }, ipAddress });
    return updated[0];
};

const getUserByEmail = async (email) => {
    const [rows] = await mysql.pool.execute(
        `SELECT uuid, username, email FROM users WHERE email = ? LIMIT 1`,
        [email]
    );
    return rows[0] || null;
};

const createUser = async ({ username, email, password_hash, full_name, birth_date, avatar_path }) => {
    const uuid = require('crypto').randomUUID();
    await mysql.pool.execute(
        `INSERT INTO users (uuid, username, email, password_hash, full_name, birth_date, avatar_path, status)
         VALUES (?, ?, ?, ?, ?, ?, ?, 'active')`,
        [uuid, username, email, password_hash, full_name, birth_date, avatar_path || null]
    );

    const [roleRows] = await mysql.pool.execute(
        `SELECT id FROM roles WHERE name = 'analyst' LIMIT 1`
    );
    if (roleRows.length > 0) {
        const [userRows] = await mysql.pool.execute(
            `SELECT id FROM users WHERE uuid = ? LIMIT 1`, [uuid]
        );
        await mysql.pool.execute(
            `INSERT INTO user_roles (user_id, role_id, is_active) VALUES (?, ?, 1)`,
            [userRows[0].id, roleRows[0].id]
        );
    }

    return { uuid, username, email, full_name };
};

const getRecentRawEvents = async (limit = 20) => {
    const result = await mssql.queryWithDecryption(`
        SELECT TOP (@limit)
            id, event_uuid, event_type, severity, source_ip, dest_ip,
            user_uuid, description,
            CONVERT(NVARCHAR(MAX), DECRYPTBYKEY(raw_payload))     AS raw_payload,
            CONVERT(NVARCHAR(MAX), DECRYPTBYKEY(enrichment_data)) AS enrichment_data,
            occurred_at, ingested_at, version, is_enriched
        FROM security_events
        ORDER BY occurred_at DESC
    `, { limit });
    return result.recordset;
};
 
const getCriticalRawEvents = async (minSeverity = 4) => {
    const result = await mssql.queryWithDecryption(`
        SELECT
            id, event_type, severity, source_ip, dest_ip,
            CONVERT(NVARCHAR(MAX), DECRYPTBYKEY(raw_payload)) AS raw_payload,
            occurred_at
        FROM security_events
        WHERE severity >= @minSeverity
        ORDER BY occurred_at DESC
    `, { minSeverity });
    return result.recordset;
};
 
const getRawEventById = async (eventId) => {
    const result = await mssql.queryWithDecryption(`
        SELECT
            id, event_uuid, event_type, severity, source_ip, dest_ip, user_uuid,
            description,
            CONVERT(NVARCHAR(MAX), DECRYPTBYKEY(raw_payload))     AS raw_payload,
            CONVERT(NVARCHAR(MAX), DECRYPTBYKEY(enrichment_data)) AS enrichment_data,
            occurred_at, ingested_at, version, original_event_id, is_enriched
        FROM security_events
        WHERE id = @eventId
    `, { eventId });
    return result.recordset[0] || null;
};
 
// Inserta un evento nuevo, ya cifrando raw_payload internamente
// (ver insertEncryptedEvent en config/sqlserver.js)
const ingestRawEvent = async ({ eventType, severity, sourceIp, destIp, userUuid, description, rawPayload, occurredAt }) => {
    const newId = await mssql.insertEncryptedEvent({
        eventType, severity, sourceIp, destIp, userUuid,
        description, rawPayload, occurredAt: occurredAt || new Date(),
    });
    return newId;
};
 
// Cola de procesamiento pendiente (event_queue) -- útil para un panel
// de "eventos sin correlacionar todavía"
const getPendingQueueCount = async () => {
    const result = await mssql.query(`
        SELECT COUNT(*) AS pending
        FROM event_queue
        WHERE processed = 0
    `);
    return result.recordset[0].pending;
};
 
// Auditoría propia de SQL Server (acciones sobre el motor de eventos,
// separada de audit_logs de PostgreSQL que audita incidentes/alertas)
const getSqlServerAuditLogs = async (limit = 15) => {
    const result = await mssql.query(`
        SELECT TOP (@limit)
            id, user_uuid, action, target_table, target_id, ip_address, occurred_at
        FROM audit_logs
        ORDER BY occurred_at DESC
    `, { limit });
    return result.recordset;
};
 
const logSqlServerAuditAction = async ({ userUuid, action, targetTable, targetId, oldValues, newValues, ipAddress }) => {
    await mssql.query(`
        INSERT INTO audit_logs (user_uuid, action, target_table, target_id, old_values, new_values, ip_address)
        VALUES (@userUuid, @action, @targetTable, @targetId, @oldValues, @newValues, @ipAddress)
    `, {
        userUuid, action,
        targetTable: targetTable || null,
        targetId: targetId || null,
        oldValues: oldValues ? JSON.stringify(oldValues) : null,
        newValues: newValues ? JSON.stringify(newValues) : null,
        ipAddress: ipAddress || null,
    });
};

module.exports = {
    getUserByUsername, getUserByUUID, getAllUsers,
    getDashboardSummary, getRecentIncidents, getOpenAlertsWithAnalyst,
    getRecentAuditLogs, getCriticalVulnerabilities, getCriticalEvents,
    getAnalystActivity, getAnalystCrossMotorProfile,
    logAuditAction, updateAlertStatus, getUserByEmail, createUser,

    // SQL Server —
    getRecentRawEvents, getCriticalRawEvents, getRawEventById,
    ingestRawEvent, getPendingQueueCount,
    getSqlServerAuditLogs, logSqlServerAuditAction,
};
