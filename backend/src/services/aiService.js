// src/services/aiService.js
// Redacción asistida por Claude (Anthropic Messages API).
//
// Reglas de diseño:
//   - La IA recibe SOLO los hallazgos ya calculados por las reglas (no el Excel).
//   - Solo puede reescribir el resumen ejecutivo y la narrativa de cada incidente.
//   - Cada texto se valida: cualquier Log_ID, IP, cuenta o equipo que no esté en
//     los datos de esa sección hace que se rechace y se conserve el texto de las reglas.
//   - Sin API key, o ante cualquier error, el informe se genera igualmente sin IA.

const API_URL = 'https://api.anthropic.com/v1/messages';
const MODEL = process.env.ANTHROPIC_MODEL || 'claude-sonnet-5-5';
const TIMEOUT_MS = Number(process.env.ANTHROPIC_TIMEOUT_MS) || 90000;

const SYSTEM_PROMPT = `Eres un analista de un SOC (nivel 2) que redacta en español la parte narrativa de un informe técnico de seguridad.

Recibirás en JSON los hallazgos ya calculados por un motor de reglas a partir de registros reales. Tu única tarea es redactar con claridad lo que esos datos ya dicen.

Reglas obligatorias:
1. Usa solo hechos presentes en el JSON. No añadas eventos, cuentas, IPs, equipos, horas, cifras, malware, actores ni motivaciones que no aparezcan en él.
2. Cada afirmación factual debe citar entre paréntesis los Log_ID (formato EVT-00000) que la sustentan, tomados de la justificación o la evidencia de ese incidente.
3. Habla en términos de sospecha fundada ("consistente con", "indica", "sugiere"). No afirmes un compromiso que los datos no confirman.
4. No incluyas recomendaciones: el informe ya tiene su propia sección.
5. No uses Markdown, viñetas ni títulos. Escribe prosa en párrafos.
6. Conserva las horas tal como aparecen (hora de Panamá).

Responde ÚNICAMENTE con un objeto JSON válido con esta forma exacta:
{"executive_summary": "texto de 120 a 200 palabras", "incidents": [{"id": "<id del incidente>", "narrative": "texto de 80 a 180 palabras"}]}`;

// ── Extracción de entidades para validar ─────────────────────────────────────
const RX = {
    logId: /\bEVT-\d{3,}\b/g,
    ip:    /\b\d{1,3}(?:\.\d{1,3}){3}\b/g,
    acct:  /\b[A-Z][A-Z0-9 ]*\\[A-Za-z0-9._$-]+/g,       // CORP\usuario, IIS APPPOOL\DefaultAppPool
    host:  /\b[A-Z]{2,}(?:-[A-Z]+)*-?\d{2,}\b/g,         // APP-SRV01, WS-023, DC-01
};
// Tokens con forma de equipo que no lo son: Log_ID, zona horaria, algoritmos
const NOT_HOSTS = /^(EVT-|UTC-|GMT-|SHA-|MD-|RFC-?|ISO-)/;
const grab = (text, rx) => [...new Set((String(text).match(rx) || []).map((s) => s.trim()))];

const allowedFor = (texts) => {
    const blob = texts.join(' \n ');
    return {
        logId: new Set(grab(blob, RX.logId)),
        ip:    new Set(grab(blob, RX.ip)),
        acct:  new Set(grab(blob, RX.acct).map((s) => s.toLowerCase())),
        host:  new Set(grab(blob, RX.host)),
    };
};

// Devuelve la lista de problemas (vacía = texto aceptado)
const validate = (text, allowed, { minLogIds = 1, minWords = 40, maxWords = 320 } = {}) => {
    const problems = [];
    if (typeof text !== 'string' || !text.trim()) return ['texto vacío'];
    const words = text.trim().split(/\s+/).length;
    if (words < minWords) problems.push(`demasiado corto (${words} palabras)`);
    if (words > maxWords) problems.push(`demasiado largo (${words} palabras)`);
    const ids = grab(text, RX.logId);
    if (ids.length < minLogIds) problems.push('no cita ningún Log_ID');
    ids.filter((x) => !allowed.logId.has(x)).forEach((x) => problems.push(`cita un Log_ID inexistente en la evidencia: ${x}`));
    grab(text, RX.ip).filter((x) => !allowed.ip.has(x)).forEach((x) => problems.push(`menciona una IP que no está en los datos: ${x}`));
    grab(text, RX.acct).filter((x) => !allowed.acct.has(x.toLowerCase())).forEach((x) => problems.push(`menciona una cuenta que no está en los datos: ${x}`));
    grab(text, RX.host).filter((x) => !allowed.host.has(x) && !NOT_HOSTS.test(x))
        .forEach((x) => problems.push(`menciona un equipo que no está en los datos: ${x}`));
    if (/^\s*[#*-]/m.test(text)) problems.push('usa formato Markdown');
    return problems;
};

// Todos los textos de un objeto (sin pasar por JSON, que escaparía las barras de CORP\\usuario)
const flattenStrings = (v) => (v === null || v === undefined ? []
    : Array.isArray(v) ? v.flatMap(flattenStrings)
    : typeof v === 'object' ? Object.values(v).flatMap(flattenStrings)
    : [String(v)]);

// ── Datos que se envían a la IA (solo hallazgos calculados) ──────────────────
const factsFrom = (report) => ({
    archivo: report.meta.import.file_name,
    periodo: report.meta.period.text,
    zona_horaria: 'hora de Panamá (UTC-05:00)',
    alcance: {
        eventos: report.scope.events, equipos: report.scope.hosts, cuentas: report.scope.users,
        ips_externas_de_origen: report.scope.external_sources,
    },
    alertas_por_criticidad: { critico: report.risk_overview.alerts[5] || 0, alto: report.risk_overview.alerts[4] || 0,
        medio: report.risk_overview.alerts[3] || 0, bajo: report.risk_overview.alerts[2] || 0 },
    incidentes: report.findings.map((f) => ({
        id: String(f.id),
        criticidad: f.severity_label,
        titulo: f.title,
        periodo: f.period.text,
        ips_externas: f.entities.external_ips,
        cuentas_que_actuan: f.entities.actors,
        cuentas_atacadas: f.entities.targeted,
        equipos: f.entities.hosts,
        alertas: f.alerts.map((a) => ({
            regla: a.rule_code, criticidad: a.severity_label, titulo: a.title,
            justificacion: a.justification, evidencia: a.evidence.map((e) => e.log_id),
        })),
    })),
    limitaciones: report.limitations,
});

const callClaude = async (facts) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
    try {
        const res = await fetch(API_URL, {
            method: 'POST',
            signal: controller.signal,
            headers: {
                'content-type': 'application/json',
                'x-api-key': process.env.ANTHROPIC_API_KEY,
                'anthropic-version': '2023-06-01',
            },
            body: JSON.stringify({
                model: MODEL,
                max_tokens: 8000,
                system: SYSTEM_PROMPT,
                messages: [{ role: 'user', content: `Hallazgos calculados (JSON):\n${JSON.stringify(facts)}` }],
            }),
        });
        const body = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(`API ${res.status}: ${body?.error?.message || 'error desconocido'}`);
        const text = (body.content || []).filter((c) => c.type === 'text').map((c) => c.text).join('');
        const start = text.indexOf('{'), end = text.lastIndexOf('}');
        if (start < 0 || end <= start) throw new Error('la respuesta no contiene JSON');
        return { json: JSON.parse(text.slice(start, end + 1)), model: body.model || MODEL };
    } finally {
        clearTimeout(timer);
    }
};

// Mejora el informe in situ. Devuelve qué secciones se aceptaron y los errores.
const improveReport = async (report) => {
    if (!process.env.ANTHROPIC_API_KEY) {
        return { accepted: [], errors: [], model: null, note: 'IA no configurada (falta ANTHROPIC_API_KEY); se usó solo la redacción de las reglas.' };
    }

    let out;
    try {
        out = await callClaude(factsFrom(report));
    } catch (err) {
        const reason = err.name === 'AbortError' ? 'tiempo de espera agotado' : err.message;
        console.error('[ai]', reason);
        return { accepted: [], errors: [{ section: 'general', problems: [reason] }], model: MODEL, note: 'La IA no respondió correctamente; se usó solo la redacción de las reglas.' };
    }

    const accepted = [];
    const errors = [];

    // Resumen ejecutivo: puede citar cualquier dato del informe
    const allAllowed = allowedFor([
        ...flattenStrings(factsFrom(report)),
        ...report.findings.flatMap((f) => f.alerts.flatMap((a) => a.evidence.map((e) => e.log_id))),
    ]);
    const summaryProblems = validate(out.json.executive_summary, allAllowed, { minWords: 60, maxWords: 300 });
    if (!summaryProblems.length) {
        report.executive_summary = { text: out.json.executive_summary.trim(), source: 'ia', model: out.model };
        accepted.push('executive_summary');
    } else {
        errors.push({ section: 'executive_summary', problems: summaryProblems });
    }

    // Narrativa de cada incidente: solo puede citar datos de ESE incidente
    for (const f of report.findings) {
        const item = (out.json.incidents || []).find((x) => String(x.id) === String(f.id));
        if (!item) { errors.push({ section: `incident:${f.id}`, problems: ['la IA no devolvió narrativa'] }); continue; }
        const allowed = allowedFor([
            f.title, f.period.text,
            ...f.entities.external_ips, ...f.entities.actors, ...f.entities.targeted, ...f.entities.hosts,
            ...f.alerts.flatMap((a) => [a.rule_code, a.title, a.justification, ...a.evidence.map((e) => e.log_id)]),
        ]);
        const problems = validate(item.narrative, allowed);
        if (!problems.length) {
            f.narrative = item.narrative.trim();
            f.narrative_source = 'ia';
            accepted.push(`incident:${f.id}`);
        } else {
            errors.push({ section: `incident:${f.id}`, problems });
        }
    }

    return { accepted, errors, model: out.model };
};

module.exports = { improveReport, validate, allowedFor, factsFrom, MODEL };
