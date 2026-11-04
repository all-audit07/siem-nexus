// src/services/reportService.js
// Informe técnico. La versión base se construye SOLO con datos de la base:
// eventos importados, alertas (con su justificación y evidencia) e incidentes.
// La IA (opcional) solo puede reescribir el resumen ejecutivo y las narrativas,
// y su texto se valida contra estos mismos datos antes de aceptarse.

const { pool } = require('../config/postgres');
const analysis = require('./analysisService');
const { getSummary } = require('./eventsService');
const { RULES } = require('./detectionRules');
const ai = require('./aiService');

class ReportError extends Error {
    constructor(message, status = 400) { super(message); this.status = status; }
}

const SEV = { 5: 'Crítico', 4: 'Alto', 3: 'Medio', 2: 'Bajo', 1: 'Info' };
const CATEGORY = {
    brute_force: 'Fuerza bruta',
    suspicious_login: 'Inicios sospechosos',
    privilege_escalation: 'Escalamiento de privilegios',
    process_execution: 'Comandos y procesos',
    lateral_movement: 'Movimiento lateral',
    anomaly: 'Otras anomalías',
};
const TZ = 'America/Panama';
const BUSINESS_HOURS = { start: 7, end: 19 };   // supuesto declarado en el informe

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const DOC_NETS = /^(192\.0\.2|198\.51\.100|203\.0\.113)\./;   // RFC 5737

const fmt = (iso, withDate = true) => {
    if (!iso) return '—';
    const p = Object.fromEntries(new Intl.DateTimeFormat('en-GB', {
        timeZone: TZ, day: '2-digit', month: '2-digit', year: 'numeric',
        hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23',
    }).formatToParts(new Date(iso)).map((x) => [x.type, x.value]));
    const time = `${p.hour}:${p.minute}:${p.second}`;
    return withDate ? `${p.day}/${p.month}/${p.year} ${time}` : time;
};
const localHour = (iso) => Number(new Intl.DateTimeFormat('en-GB', { timeZone: TZ, hour: '2-digit', hourCycle: 'h23' }).format(new Date(iso)));
const uniq = (a) => [...new Set(a.filter(Boolean))];
const list = (a) => (a.length <= 1 ? a.join('') : `${a.slice(0, -1).join(', ')} y ${a[a.length - 1]}`);

// ── Recomendaciones por regla (se rellenan con las entidades de la evidencia) ──
const RECOMMENDATIONS = {
    'BF-001': (x) => `Bloquear en el perímetro la IP ${list(x.ips)}, forzar el cambio de contraseña de las cuentas atacadas (${list(x.users)}) y aplicar bloqueo por intentos fallidos junto con MFA.`,
    'BF-002': (x) => `Restringir el acceso remoto expuesto a Internet (RDP) mediante VPN o lista de IPs permitidas, bloquear ${list(x.ips)} y exigir MFA a ${list(x.users)}.`,
    'SL-001': (x) => `Tratar la cuenta ${list(x.users)} como comprometida: restablecer credenciales, revocar sesiones activas y revisar toda su actividad posterior al inicio de sesión.`,
    'SL-002': (x) => `Confirmar con el titular de ${list(x.users)} si el acceso desde ${list(x.ips)} fue legítimo.`,
    'PE-001': (x) => `Revisar los privilegios de ${list(x.users)} y aplicar mínimo privilegio: las cuentas administrativas no deberían poder usarse desde Internet.`,
    'PX-001': (x) => `Recuperar y decodificar el comando PowerShell ejecutado en ${list(x.hosts)} para el análisis forense, y restringir PowerShell (modo de lenguaje restringido, AMSI).`,
    'PX-002': (x) => `Aislar ${list(x.hosts)}, verificar la integridad de las copias de seguridad fuera de línea y buscar indicios de cifrado de archivos.`,
    'PX-003': (x) => `Aislar el servidor web ${list(x.hosts)}, localizar y eliminar la web shell en el directorio de subidas y revisar los permisos del pool de IIS.`,
    'PX-004': (x) => `Revisar la sesión de ${list(x.users)} en ${list(x.hosts)} que ejecutó comandos de reconocimiento y determinar su origen.`,
    'PX-005': (x) => `Localizar y analizar el archivo comprimido creado en ${list(x.hosts)} para determinar qué datos contiene.`,
    'PX-006': (x) => `Eliminar la tarea programada creada en ${list(x.hosts)} y conservar el script referenciado para su análisis.`,
    'PX-007': (x) => `Eliminar el servicio instalado en ${list(x.hosts)}, conservar el binario y calcular su hash para análisis.`,
    'PX-008': (x) => `Detener el ejecutable lanzado desde una ruta escribible en ${list(x.hosts)} y obtener su hash para análisis.`,
    'LM-001': (x) => `Revisar los accesos de ${list(x.users)} entre ${list(x.hosts)} y restringir el tráfico SMB entre servidores mediante segmentación.`,
    'AN-001': (x) => `Comprobar si ${list(x.users)} necesita acceder a esos recursos y revisar sus permisos sobre ${list(x.hosts)}.`,
    'AN-002': (x) => `Bloquear el destino ${list(x.ips)}, determinar qué datos se enviaron y valorar controles de prevención de fuga de datos (DLP).`,
    'AN-003': (x) => `Bloquear ${list(x.ips)} y limitar la salida directa a Internet desde servidores.`,
    'AN-004': (x) => `Revisar los registros del servidor web ${list(x.hosts)}, aplicar un WAF y corregir las rutas expuestas.`,
};

const entitiesOf = (alert, includeContext = false) => {
    const ev = alert.evidence.filter((e) => includeContext || e.role !== 'context');
    const ips = uniq([
        ...ev.map((e) => e.source_ip),
        ...(alert.title.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) || []),
    ]).filter((ip) => !/^(10|127)\.|^192\.168\.|^172\.(1[6-9]|2\d|3[01])\./.test(ip));
    return { ips, users: uniq(ev.map((e) => e.user_name)), hosts: uniq(ev.map((e) => e.hostname)) };
};

// ── Construcción del informe determinista ────────────────────────────────────

const buildBaseReport = async (importId, user) => {
    const summary = await getSummary(importId);
    if (summary.import.status !== 'analyzed') {
        throw new ReportError('La importación aún no se ha analizado. Ejecuta el análisis antes de generar el informe.', 409);
    }
    const alerts = await analysis.listAlerts(importId);
    const incidents = await analysis.listIncidents(importId);
    const ev = summary.events;
    const sevCount = summary.alerts.by_severity;

    // Resumen ejecutivo (base)
    const topInc = incidents.filter((i) => i.severity >= 4);
    const executive =
        `Se analizaron ${ev.total} eventos del archivo «${summary.import.file_name}», registrados entre el ` +
        `${fmt(ev.first_at)} y el ${fmt(ev.last_at)} (hora de Panamá). Las reglas de detección generaron ` +
        `${summary.alerts.total} alertas (${sevCount[5] || 0} críticas, ${sevCount[4] || 0} altas, ${sevCount[3] || 0} medias ` +
        `y ${sevCount[2] || 0} bajas), agrupadas en ${incidents.length} incidentes. ` +
        (topInc.length
            ? `Los incidentes de mayor criticidad son: ${topInc.map((i) => `${i.title} (${SEV[i.severity]})`).join('; ')}. `
            : 'Ningún incidente alcanzó criticidad alta o crítica. ') +
        'Todas las conclusiones se basan exclusivamente en los registros importados; cada hallazgo indica los Log_ID que lo sustentan.';

    // Cobertura de las seis detecciones solicitadas
    const hours = uniq([ev.first_at, ev.last_at].filter(Boolean).map(localHour));
    const offHours = (await pool.query(
        `SELECT count(*)::int AS n FROM security_events WHERE import_id = $1
           AND (EXTRACT(HOUR FROM occurred_at AT TIME ZONE '${TZ}') < $2 OR EXTRACT(HOUR FROM occurred_at AT TIME ZONE '${TZ}') >= $3)`,
        [importId, BUSINESS_HOURS.start, BUSINESS_HOURS.end])).rows[0].n;

    const coverage = Object.entries(CATEGORY).map(([cat, label]) => {
        const rules = RULES.filter((r) => r.category === cat);
        const found = alerts.filter((a) => a.category === cat);
        let note = found.length
            ? `${found.length} alerta(s): ${uniq(found.map((a) => a.rule_code)).join(', ')}.`
            : 'Las reglas se evaluaron y no encontraron evidencia suficiente en los registros.';
        if (cat === 'suspicious_login') {
            note += offHours
                ? ` Se registraron ${offHours} eventos fuera del horario de referencia (${BUSINESS_HOURS.start}:00–${BUSINESS_HOURS.end}:00).`
                : ` Criterio de horario: todos los eventos ocurren entre ${fmt(ev.first_at, false)} y ${fmt(ev.last_at, false)}, dentro del horario de referencia (${BUSINESS_HOURS.start}:00–${BUSINESS_HOURS.end}:00); no hay actividad fuera de horario que evaluar.`;
        }
        return { category: cat, label, rules: rules.map((r) => r.code), alerts: found.length, note };
    });

    // Hallazgos por incidente
    const findings = incidents.map((inc) => {
        const incAlerts = alerts.filter((a) => a.incident_id === inc.id)
            .sort((a, b) => new Date(a.window_start) - new Date(b.window_start));
        const narrative = incAlerts.map((a) => a.justification).join(' ');
        const recs = uniq(incAlerts.map((a) => {
            const fn = RECOMMENDATIONS[a.rule_code];
            return fn ? fn(entitiesOf(a)) : null;
        }));
        return {
            id: inc.id,
            title: inc.title,
            severity: inc.severity,
            severity_label: SEV[inc.severity],
            period: { start: inc.start_at, end: inc.end_at, text: `${fmt(inc.start_at)} → ${fmt(inc.end_at, false)}` },
            entities: {
                external_ips: inc.metadata?.external_ips || [],
                actors: inc.metadata?.users || [],
                targeted: inc.metadata?.targeted_users || [],
                hosts: inc.affected_assets || [],
            },
            mitre_tactics: inc.mitre_tactics || [],
            narrative,
            narrative_source: 'reglas',
            alerts: incAlerts.map((a) => ({
                id: a.id, rule_code: a.rule_code, rule_name: a.rule_name.replace(/^[A-Z]{2}-\d{3} · /, ''),
                rule_version: a.rule_version, category: CATEGORY[a.category] || a.category,
                severity: a.severity, severity_label: SEV[a.severity], title: a.title,
                justification: a.justification, mitre: a.mitre_techniques || [],
                window: `${fmt(a.window_start)} → ${fmt(a.window_end, false)}`,
                evidence: a.evidence.map((e) => ({ log_id: e.log_id, role: e.role })),
            })),
            recommendations: recs,
        };
    });

    // Limitaciones calculadas a partir de los datos
    const limitations = [
        `Las marcas de tiempo del Excel no indican zona horaria; se interpretaron como hora de Panamá (UTC−05:00).`,
        `La severidad incluida en cada fila (Informational, Warning, Medium, High) es la del sensor de origen. La criticidad de las alertas la asignan las reglas a partir de la evidencia combinada.`,
        `El conjunto cubre un único periodo de ${Math.round((new Date(ev.last_at) - new Date(ev.first_at)) / 3600000 * 10) / 10} horas; no existe una línea base histórica, por lo que los umbrales de las reglas son fijos y se documentan en el anexo.`,
    ];
    const docIps = summary.top.external_ips.map((r) => r.value).filter((ip) => DOC_NETS.test(ip));
    if (docIps.length) {
        limitations.push(`Las IPs externas ${list(docIps)} pertenecen a rangos reservados para documentación (RFC 5737). No tienen ubicación real, por lo que no se geolocalizan ni se atribuyen a ningún país o actor.`);
    }
    const hostRows = (await pool.query(
        `SELECT DISTINCT hostname FROM security_events WHERE import_id = $1 AND hostname IS NOT NULL`, [importId])).rows.map((r) => r.hostname);
    const byNorm = {};
    hostRows.forEach((h) => { const k = h.toLowerCase().replace(/[^a-z0-9]/g, ''); (byNorm[k] = byNorm[k] || []).push(h); });
    Object.values(byNorm).filter((g) => g.length > 1).forEach((g) => {
        limitations.push(`Los nombres de equipo ${list(g)} podrían corresponder al mismo equipo escrito de distinta forma. No se unificaron, porque los registros no permiten confirmarlo.`);
    });
    if (summary.import.rows_rejected) {
        limitations.push(`${summary.import.rows_rejected} filas del archivo se rechazaron en la validación y no forman parte del análisis.`);
    }

    // Hipótesis: cuentas atacadas en un incidente que actúan en otro (no confirmadas)
    const hypotheses = [];
    incidents.forEach((a) => (a.metadata?.targeted_users || []).forEach((u) => {
        incidents.filter((b) => b.id !== a.id && (b.metadata?.users || []).includes(u)).forEach((b) => {
            hypotheses.push(`La cuenta ${u} fue objetivo del incidente #${a.id} y después actúa en el incidente #${b.id}. Los registros no muestran que el ataque del incidente #${a.id} lograra acceder con esa cuenta, por lo que la relación entre ambos es una hipótesis a investigar, no un hallazgo.`);
        });
    }));

    // Anexo: reglas aplicadas
    const rules = RULES.map((r) => ({
        code: r.code, name: r.name, category: CATEGORY[r.category], severity: SEV[r.severity], version: r.version,
        params: r.params, mitre: r.mitre, triggered: alerts.filter((a) => a.rule_code === r.code).length,
    }));

    // Anexo: registros citados como evidencia
    const evidence = (await pool.query(
        `SELECT DISTINCT ON (se.occurred_at, se.id) se.source_log_id AS log_id, se.occurred_at, se.hostname, se.user_name,
                host(se.source_ip) AS source_ip, se.event_code, COALESCE(se.command_line, se.description) AS detail
         FROM alert_evidence ae
         JOIN alerts a ON a.id = ae.alert_id
         JOIN security_events se ON se.id = ae.event_id
         WHERE a.import_id = $1
         ORDER BY se.occurred_at, se.id`, [importId])).rows.map((r) => ({ ...r, time: fmt(r.occurred_at) }));

    return {
        meta: {
            title: 'Informe técnico de análisis de seguridad',
            generated_at: new Date().toISOString(),
            generated_by: user?.username || user?.name || null,
            timezone: TZ,
            import: {
                id: summary.import.id, file_name: summary.import.file_name, sheet: summary.import.sheet_name,
                imported_at: summary.import.imported_at, analyzed_at: summary.import.analyzed_at,
                rows_valid: summary.import.rows_valid, rows_rejected: summary.import.rows_rejected,
            },
            period: { start: ev.first_at, end: ev.last_at, text: `${fmt(ev.first_at)} – ${fmt(ev.last_at)}` },
        },
        executive_summary: { text: executive, source: 'reglas' },
        scope: {
            events: ev.total, hosts: ev.hosts, users: ev.users, external_sources: ev.external_sources,
            logon_failures: ev.logon_failures,
            evidence_events: summary.timeline.reduce((s, b) => s + b.flagged, 0),
            by_type: ev.by_type, by_sensor_severity: ev.by_sensor_severity,
        },
        methodology: [
            'Importación: el archivo Excel se validó fila por fila (columnas obligatorias, fecha, IP, severidad y Log_ID único). Cada evento se guardó en PostgreSQL junto con su fila original sin modificar.',
            'Normalización: el Event_ID se asignó a un tipo de evento (por ejemplo, 4625 → logon_failure). Del campo de destino se extrajeron la IP y el puerto, y del texto de la descripción el LogonType cuando aparece.',
            `Detección: se aplicaron ${RULES.length} reglas deterministas agrupadas en las seis categorías solicitadas. Cada regla tiene umbrales y ventanas de tiempo fijos (anexo A) y guarda los eventos exactos que la activan.`,
            'Correlación: las alertas que comparten una IP externa o una cuenta que actúa se agrupan en un incidente. La criticidad del incidente es la de su alerta más grave.',
            'Clasificación: Crítico = compromiso probable o acción destructiva; Alto = actividad maliciosa clara sin confirmación de impacto; Medio = actividad sospechosa que requiere contexto; Bajo = señal débil.',
            'Rigor: una alerta es una sospecha fundada en evidencia, no una confirmación. Ningún hallazgo procede de fuentes externas a los registros importados.',
        ],
        risk_overview: { alerts: sevCount, incidents: summary.incidents.by_severity },
        coverage,
        findings,
        hypotheses,
        limitations,
        appendix: { rules, evidence },
        ai: { requested: false, used: false, model: null, errors: [] },
    };
};

// ── Generación y almacenamiento ──────────────────────────────────────────────

const createReport = async (importId, { useAi, user }) => {
    const content = await buildBaseReport(importId, user);
    let aiSections = [];

    if (useAi) {
        content.ai.requested = true;
        const result = await ai.improveReport(content);
        content.ai = { requested: true, used: result.accepted.length > 0, model: result.model, errors: result.errors, note: result.note || null };
        aiSections = result.accepted;
    }

    const { rows } = await pool.query(
        `INSERT INTO reports (import_id, title, content, ai_model, ai_generated_sections,
                              validation_status, validation_errors, generated_by_uuid)
         VALUES ($1,$2,$3,$4,$5,'valid',$6,$7)
         RETURNING id, uuid, created_at`,
        [importId, `${content.meta.title} — importación #${importId}`, JSON.stringify(content),
         content.ai.used ? content.ai.model : null, aiSections,
         content.ai.errors.length ? JSON.stringify(content.ai.errors) : null,
         UUID_REGEX.test(user?.uuid || '') ? user.uuid : null],
    );
    return { ...rows[0], content };
};

const listReports = async (importId) => (await pool.query(
    `SELECT id, uuid, title, ai_model, ai_generated_sections, validation_status, created_at
     FROM reports WHERE import_id = $1 ORDER BY created_at DESC`, [importId])).rows;

const getReport = async (id) => {
    const { rows } = await pool.query(
        `SELECT id, uuid, import_id, title, content, ai_model, ai_generated_sections,
                validation_status, validation_errors, created_at
         FROM reports WHERE id = $1`, [id]);
    return rows[0] || null;
};

module.exports = { ReportError, buildBaseReport, createReport, listReports, getReport, SEV, CATEGORY };
