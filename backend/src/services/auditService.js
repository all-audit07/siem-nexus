// src/services/auditService.js
// v2.0 · Modo auditoría. Convierte los resultados del análisis en hallazgos de auditoría:
//   condición (probada por la evidencia), criterio (ISO 27001:2022 / CIS v8),
//   causa probable (hipótesis a verificar), efecto, verificación y recomendación.
// Es determinista: la IA no participa en la elección de controles.
// Regenerar conserva el seguimiento (estado, responsable, fecha) de los hallazgos existentes.

const { pool } = require('../config/postgres');
const { SEVERITY_LABEL } = require('./detectionRules');

class AuditError extends Error {
    constructor(message, status = 400) {
        super(message);
        this.status = status;
    }
}

const TZ = 'America/Panama';
const fmt = (iso, withDate = true) => {
    if (!iso) return '—';
    const p = Object.fromEntries(new Intl.DateTimeFormat('en-GB', {
        timeZone: TZ, day: '2-digit', month: '2-digit', year: 'numeric',
        hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23',
    }).formatToParts(new Date(iso)).map((x) => [x.type, x.value]));
    const time = `${p.hour}:${p.minute}:${p.second}`;
    return withDate ? `${p.day}/${p.month}/${p.year} ${time}` : time;
};
const uniq = (a) => [...new Set(a.filter((x) => x !== null && x !== undefined))];
const sortLogIds = (a) => uniq(a).sort((x, y) => x.localeCompare(y, 'en', { numeric: true }));
const evidenceText = (ids) => (ids.length <= 2 ? ids.join(', ') : `${ids[0]} … ${ids[ids.length - 1]}`);
const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
const incidentText = (ids) => (!ids.length ? 'sin incidente asociado'
    : ids.length === 1 ? `en el incidente #${ids[0]}`
    : `en los incidentes ${ids.slice(0, -1).map((i) => `#${i}`).join(', ')} y #${ids[ids.length - 1]}`);

const EFFECT = {
    5: 'Compromiso probable o acción destructiva observada en la evidencia.',
    4: 'Actividad maliciosa clara; la evidencia no confirma impacto.',
    3: 'Actividad sospechosa que requiere contexto para valorar su impacto.',
    2: 'Debilidad de control sin actividad maliciosa asociada en la evidencia.',
};
const EFFECT_INDICATOR = 'Agrava los hallazgos con los que coincide; por sí solo no demuestra un fallo de control.';
const EFFECT_BY_CODE = {
    'T-01': 'Sin esos eventos no se puede demostrar si existe bloqueo de cuentas ni reconstruir cómo respondió el sistema al ataque.',
    'T-02': 'Dificulta correlacionar la evidencia y atribuir cada evento al activo correcto.',
};

// ── Construcción de hallazgos ────────────────────────────────────────────────

// Un hallazgo por regla que generó alertas en la importación
const ruleFindings = async (client, importId) => {
    const { rows } = await client.query(
        `SELECT r.code, r.name, a.id, a.severity, a.incident_id, a.title, a.window_start, a.window_end,
                COALESCE(array_agg(se.source_log_id) FILTER (WHERE se.id IS NOT NULL), '{}') AS log_ids
           FROM alerts a
           JOIN correlation_rules r ON r.id = a.rule_id
           LEFT JOIN alert_evidence ae ON ae.alert_id = a.id
           LEFT JOIN security_events se ON se.id = ae.event_id
          WHERE a.import_id = $1
          GROUP BY r.code, r.name, a.id
          ORDER BY r.code, a.window_start`, [importId]);

    const byCode = new Map();
    for (const row of rows) {
        if (!byCode.has(row.code)) byCode.set(row.code, { code: row.code, name: row.name.replace(/^[A-Z]{2}-\d{3}\s*·\s*/, ''), alerts: [] });
        byCode.get(row.code).alerts.push(row);
    }

    return [...byCode.values()].map(({ code, name, alerts }) => {
        const logIds = sortLogIds(alerts.flatMap((a) => a.log_ids));
        const incidents = uniq(alerts.map((a) => a.incident_id)).sort((x, y) => x - y);
        const start = alerts.reduce((m, a) => (a.window_start < m ? a.window_start : m), alerts[0].window_start);
        const end = alerts.reduce((m, a) => (a.window_end > m ? a.window_end : m), alerts[0].window_end);
        const titles = alerts.map((a) => a.title).join('; ');
        return {
            code,
            severity: Math.max(...alerts.map((a) => a.severity)),
            condition:
                `${plural(alerts.length, 'alerta', 'alertas')} de la regla ${code} (${name}) entre el ${fmt(start)} y el ${fmt(end)} ` +
                `(hora de Panamá), ${incidentText(incidents)}: ${titles}. ` +
                `Evidencia: ${plural(logIds.length, 'registro', 'registros')} (${evidenceText(logIds)}).`,
            alertIds: alerts.map((a) => a.id),
            incidentIds: incidents,
            logIds,
        };
    });
};

// T-01: fuerza bruta registrada sin ningún evento de bloqueo de cuenta (4740)
const loggingGapFinding = async (client, importId) => {
    const { rows: [lock] } = await client.query(
        `SELECT count(*)::int AS n FROM security_events WHERE import_id = $1 AND event_code = '4740'`, [importId]);
    if (lock.n > 0) return null;

    const { rows } = await client.query(
        `SELECT a.id, a.incident_id, a.severity,
                COALESCE(array_agg(se.source_log_id) FILTER (WHERE se.event_code = '4625'), '{}') AS fail_ids
           FROM alerts a
           JOIN correlation_rules r ON r.id = a.rule_id
           LEFT JOIN alert_evidence ae ON ae.alert_id = a.id
           LEFT JOIN security_events se ON se.id = ae.event_id
          WHERE a.import_id = $1 AND r.code IN ('BF-001', 'BF-002', 'SL-001')
          GROUP BY a.id`, [importId]);
    if (!rows.length) return null;

    const failIds = sortLogIds(rows.flatMap((r) => r.fail_ids));
    return {
        code: 'T-01',
        severity: 3,
        condition:
            `Las alertas de fuerza bruta citan ${plural(failIds.length, 'inicio de sesión fallido', 'inicios de sesión fallidos')} (4625; ${evidenceText(failIds)}) ` +
            'y la importación no contiene ningún evento de bloqueo de cuenta (4740).',
        alertIds: rows.map((r) => r.id),
        incidentIds: uniq(rows.map((r) => r.incident_id)).sort((x, y) => x - y),
        logIds: failIds,
    };
};

// T-02: un mismo nombre de equipo escrito de varias formas (DC01 / DC-01)
const inventoryFinding = async (client, importId) => {
    const { rows } = await client.query(
        `WITH names AS (
             SELECT hostname AS name, source_log_id FROM security_events WHERE import_id = $1 AND hostname IS NOT NULL
             UNION ALL
             SELECT destination, source_log_id FROM security_events
              WHERE import_id = $1 AND destination ~ '^[A-Za-z][A-Za-z0-9-]*$'
         )
         , per AS (
             SELECT lower(regexp_replace(name, '[^A-Za-z0-9]', '', 'g')) AS key, name,
                    count(DISTINCT source_log_id)::int AS n, min(source_log_id) AS first_id
               FROM names GROUP BY 1, 2
         )
         SELECT key, json_agg(json_build_object('name', name, 'n', n, 'first', first_id) ORDER BY name) AS variants
           FROM per
          GROUP BY key
         HAVING count(*) > 1`, [importId]);
    if (!rows.length) return null;

    const groups = rows.map((r) => r.variants
        .map((v) => `${v.name} (${plural(v.n, 'registro', 'registros')}, p. ej. ${v.first})`).join(' / '));
    const logIds = sortLogIds(rows.flatMap((r) => r.variants.map((v) => v.first)));
    return {
        code: 'T-02',
        severity: 2,
        condition:
            `Los registros usan nombres distintos que podrían corresponder al mismo equipo: ${groups.join('; ')}.`,
        alertIds: [],
        incidentIds: [],
        logIds,
    };
};

// ── API del servicio ─────────────────────────────────────────────────────────

const generateFindings = async (importId) => {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const imp = await client.query('SELECT id, status FROM log_imports WHERE id = $1 FOR UPDATE', [importId]);
        if (!imp.rowCount) throw new AuditError('Importación no encontrada', 404);
        if (imp.rows[0].status !== 'analyzed') throw new AuditError('Analiza la importación antes de auditarla', 409);

        const mapping = Object.fromEntries((await client.query('SELECT * FROM audit_rule_mapping')).rows.map((m) => [m.code, m]));
        const sla = Object.fromEntries((await client.query('SELECT severity, days FROM audit_remediation_sla')).rows.map((s) => [s.severity, s.days]));

        const drafts = [
            ...(await ruleFindings(client, importId)),
            await loggingGapFinding(client, importId),
            await inventoryFinding(client, importId),
        ].filter((f) => f && mapping[f.code]);

        for (const f of drafts) {
            const m = mapping[f.code];
            await client.query(
                `INSERT INTO audit_findings
                   (import_id, code, mapping_version, finding_type, severity, iso_controls, cis_safeguards,
                    condition, effect, probable_cause, verification, recommendation,
                    alert_ids, incident_ids, evidence_log_ids, due_date)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15, CURRENT_DATE + $16::int)
                 ON CONFLICT (import_id, code) DO UPDATE SET
                    mapping_version = EXCLUDED.mapping_version, finding_type = EXCLUDED.finding_type,
                    severity = EXCLUDED.severity, iso_controls = EXCLUDED.iso_controls,
                    cis_safeguards = EXCLUDED.cis_safeguards, condition = EXCLUDED.condition,
                    effect = EXCLUDED.effect, probable_cause = EXCLUDED.probable_cause,
                    verification = EXCLUDED.verification, recommendation = EXCLUDED.recommendation,
                    alert_ids = EXCLUDED.alert_ids, incident_ids = EXCLUDED.incident_ids,
                    evidence_log_ids = EXCLUDED.evidence_log_ids`,
                [importId, f.code, m.version, m.finding_type, f.severity, m.iso_controls, m.cis_safeguards,
                 f.condition, EFFECT_BY_CODE[f.code] || (m.finding_type === 'indicador' ? EFFECT_INDICATOR : EFFECT[f.severity]),
                 m.probable_cause, m.verification, m.recommendation,
                 f.alertIds, f.incidentIds, f.logIds, sla[f.severity] || 90],
            );
        }

        // Hallazgos que ya no se sostienen: se eliminan solo si nadie empezó su seguimiento
        await client.query(
            `DELETE FROM audit_findings
              WHERE import_id = $1 AND status = 'abierto' AND owner IS NULL AND NOT (code = ANY($2::text[]))`,
            [importId, drafts.map((f) => f.code)]);

        await client.query('COMMIT');
        return listFindings(importId);
    } catch (err) {
        await client.query('ROLLBACK');
        throw err;
    } finally {
        client.release();
    }
};

const listFindings = async (importId) => {
    const { rows } = await pool.query(
        `SELECT f.*,
                COALESCE((SELECT json_agg(json_build_object('id', c.control_id, 'title', c.title) ORDER BY c.control_id)
                            FROM audit_controls c
                           WHERE c.framework = 'ISO27001' AND c.control_id = ANY(f.iso_controls)), '[]') AS iso_detail
           FROM audit_findings f
          WHERE f.import_id = $1
          ORDER BY f.severity DESC, f.code`, [importId]);

    const findings = rows.map((r) => ({ ...r, severity_label: SEVERITY_LABEL[r.severity] }));

    // Vista por control: qué hallazgos evidencian la deficiencia de cada control ISO
    const byControl = {};
    for (const f of findings) {
        for (const c of f.iso_detail) {
            if (!byControl[c.id]) byControl[c.id] = { id: c.id, title: c.title, severity: 0, findings: [] };
            byControl[c.id].findings.push(f.code);
            byControl[c.id].severity = Math.max(byControl[c.id].severity, f.severity);
        }
    }
    const controls = Object.values(byControl).sort((a, b) =>
        b.severity - a.severity || a.id.localeCompare(b.id, 'en', { numeric: true }));

    return {
        importId,
        total: findings.length,
        deficiencies: findings.filter((f) => f.finding_type === 'deficiencia').length,
        indicators: findings.filter((f) => f.finding_type === 'indicador').length,
        controls,
        findings,
    };
};

module.exports = { AuditError, generateFindings, listFindings };

