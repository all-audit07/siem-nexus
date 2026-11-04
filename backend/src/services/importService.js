// src/services/importService.js
// Importación de logs desde Excel (.xlsx) hacia PostgreSQL (security_events).
// Reglas de rigor:
//   - Nunca se modifica ni se descarta información en silencio.
//   - Cada fila inválida se reporta con su número de fila, Log_ID y motivo.
//   - La fila original completa se guarda intacta en raw_payload.

const JSZip         = require('jszip');
const { XMLParser } = require('fast-xml-parser');
const path          = require('path');
const crypto        = require('crypto');
const net      = require('net');
const { pool } = require('../config/postgres');

// ── Configuración ────────────────────────────────────────────────────────────

const SOURCE_TIMEZONE   = 'America/Panama';
const SOURCE_UTC_OFFSET = '-05:00';          // Panamá no usa horario de verano
const OFFSET_MS         = -5 * 60 * 60 * 1000;
const INSERT_CHUNK_SIZE = 200;

const REQUIRED_HEADERS = [
    'Log_ID', 'Timestamp', 'Hostname', 'Event_ID', 'User', 'Source_IP',
    'Destination', 'Log_Source', 'Event_Description', 'Process_CommandLine',
    'Result', 'Severity',
];

// Severidad del sensor → escala 1-5. El nivel 5 (crítico) solo lo asignan las reglas.
const SEVERITY_MAP = { informational: 1, warning: 2, medium: 3, high: 4 };

// Event_ID original → categoría normalizada (event_type)
const EVENT_TYPE_MAP = {
    '4624': 'logon_success',
    '4625': 'logon_failure',
    '4634': 'logoff',
    '4663': 'object_access',
    '4672': 'special_privileges',
    '4688': 'process_creation',
    '4698': 'scheduled_task_created',
    '4104': 'powershell_scriptblock',
    '5140': 'share_access',
    '5145': 'share_access_detailed',
    '5156': 'network_connection_allowed',
    '7036': 'service_state_change',
    '7045': 'service_installed',
    'PROXY_ACCESS': 'proxy_request',
    'HTTP_ACCESS':  'http_request',
};

// Longitudes máximas de las columnas de security_events
const MAX_LEN = {
    source_log_id: 40, event_code: 40, hostname: 253, user_name: 150,
    destination: 255, log_source: 40, description: 1000, result: 20,
    source_severity: 20,
};

const EVENT_COLUMNS = [
    'import_id', 'source_log_id', 'event_type', 'event_code', 'severity',
    'source_ip', 'dest_ip', 'dest_port', 'hostname', 'user_name', 'destination',
    'log_source', 'description', 'command_line', 'result', 'source_severity',
    'raw_payload', 'occurred_at',
];

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const TS_REGEX   = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})$/;

// ── Error controlado (se devuelve al cliente con su código HTTP) ─────────────

class ImportError extends Error {
    constructor(message, status = 400, details = {}) {
        super(message);
        this.status  = status;
        this.details = details;
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

const sha256 = (buffer) => crypto.createHash('sha256').update(buffer).digest('hex');

// Fecha serial de Excel (días desde 1899-12-30) → "AAAA-MM-DD HH:MM:SS" (hora de pared)
const excelSerialToText = (serial) => {
    const d = new Date(Math.round((serial - 25569) * 86400000));
    const p = (n) => String(n).padStart(2, '0');
    return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ` +
           `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`;
};

// "2026-10-23 07:46:07" (hora de Panamá) → ISO con offset, o null si es inválida
const parseTimestamp = (value) => {
    const text = /^\d+(\.\d+)?$/.test(value) && +value > 20000 ? excelSerialToText(+value) : value;
    const m = TS_REGEX.exec(text);
    if (!m) return null;
    const iso = `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}${SOURCE_UTC_OFFSET}`;
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return null;
    // Rechaza fechas imposibles (p. ej. 2026-02-31) que JavaScript ajustaría solo
    const local = new Date(d.getTime() + OFFSET_MS);
    if (local.getUTCFullYear() !== +m[1] || local.getUTCMonth() + 1 !== +m[2] ||
        local.getUTCDate() !== +m[3]     || local.getUTCHours() !== +m[4]) return null;
    return iso;
};

// "203.0.113.88:443" → IP + puerto · "WEB-01:443" → solo puerto · "DC-01" → nada
const parseDestination = (text) => {
    if (!text) return { destIp: null, destPort: null };
    if (net.isIP(text)) return { destIp: text, destPort: null };
    const m = /^(.+):(\d{1,5})$/.exec(text);
    if (m && +m[2] <= 65535) {
        return { destIp: net.isIP(m[1]) ? m[1] : null, destPort: +m[2] };
    }
    return { destIp: null, destPort: null };
};

// ── Normalización de una fila ────────────────────────────────────────────────

const normalizeRow = (raw) => {
    const errors = [];

    if (!raw.Log_ID) errors.push('Log_ID vacío');

    const occurredAt = parseTimestamp(raw.Timestamp);
    if (!occurredAt) errors.push(`Timestamp inválido: "${raw.Timestamp}"`);

    if (!raw.Event_ID) errors.push('Event_ID vacío');

    const severity = SEVERITY_MAP[(raw.Severity || '').toLowerCase()];
    if (!severity) errors.push(`Severity no reconocida: "${raw.Severity}"`);

    let sourceIp = null;
    if (raw.Source_IP) {
        if (net.isIP(raw.Source_IP)) sourceIp = raw.Source_IP;
        else errors.push(`Source_IP inválida: "${raw.Source_IP}"`);
    }

    const { destIp, destPort } = parseDestination(raw.Destination);

    const event = {
        source_log_id:   raw.Log_ID,
        event_type:      EVENT_TYPE_MAP[raw.Event_ID] || 'other',
        event_code:      raw.Event_ID,
        severity,
        source_ip:       sourceIp,
        dest_ip:         destIp,
        dest_port:       destPort,
        hostname:        raw.Hostname || null,            // sin unificar alias (DC-01 / DC01)
        user_name:       raw.User && raw.User !== '-' ? raw.User : null,
        destination:     raw.Destination || null,
        log_source:      raw.Log_Source || null,
        description:     raw.Event_Description || null,
        command_line:    raw.Process_CommandLine || null,
        result:          raw.Result || null,
        source_severity: raw.Severity || null,
        occurred_at:     occurredAt,
        raw_payload:     raw,                               // fila original intacta
    };

    for (const [field, max] of Object.entries(MAX_LEN)) {
        if (event[field] && String(event[field]).length > max) {
            errors.push(`${field} supera ${max} caracteres`);
        }
    }

    return { event, errors };
};

// ── Lectura del libro (.xlsx) ────────────────────────────────────────────────
// Lector propio sobre JSZip + fast-xml-parser. Soporta archivos generados por
// Excel, LibreOffice y herramientas .NET/OpenXML (prefijos "x:" y rutas internas
// absolutas), que algunas librerías no reconocen. Solo lee valores; no ejecuta
// fórmulas ni macros.

const XML = new XMLParser({
    ignoreAttributes:    false,
    attributeNamePrefix: '@_',
    removeNSPrefix:      true,      // <x:row> → row, r:id → id
    parseTagValue:       false,     // conserva todo como texto (sin convertir "007" en 7)
    parseAttributeValue: false,
    trimValues:          false,
    textNodeName:        '#text',
    isArray: (name) => ['sheet', 'Relationship', 'si', 'r', 'row', 'c'].includes(name),
});

const textOf = (node) => {
    if (node === null || node === undefined) return '';
    if (typeof node === 'string') return node;
    if (Array.isArray(node)) return node.map(textOf).join('');
    return node['#text'] !== undefined ? String(node['#text']) : '';
};

// "AB12" → índice de columna 1-based (A=1, Z=26, AA=27...)
const columnIndex = (ref) => {
    const letters = /^([A-Z]+)/.exec(ref || '');
    if (!letters) return null;
    return [...letters[1]].reduce((acc, ch) => acc * 26 + (ch.charCodeAt(0) - 64), 0);
};

const resolvePart = (baseDir, target) =>
    target.startsWith('/') ? target.slice(1) : path.posix.normalize(path.posix.join(baseDir, target));

const relsPathOf = (partPath) =>
    path.posix.join(path.posix.dirname(partPath), '_rels', path.posix.basename(partPath) + '.rels');

const readXml = async (zip, partPath) => {
    const file = zip.file(partPath);
    return file ? XML.parse(await file.async('string')) : null;
};

const readRels = async (zip, partPath) => {
    const doc = await readXml(zip, relsPathOf(partPath));
    const list = doc?.Relationships?.Relationship || [];
    const baseDir = path.posix.dirname(partPath);
    return list.map((r) => ({
        id: r['@_Id'], type: r['@_Type'] || '', target: resolvePart(baseDir === '.' ? '' : baseDir, r['@_Target'] || ''),
    }));
};

const openWorkbook = async (buffer) => {
    let zip;
    try {
        zip = await JSZip.loadAsync(buffer);
    } catch {
        throw new ImportError('El archivo no es un .xlsx válido o está dañado', 422);
    }

    const rootRels = await readRels(zip, '');           // _rels/.rels
    const wbPath = rootRels.find((r) => r.type.endsWith('/officeDocument'))?.target || 'xl/workbook.xml';
    const wb = await readXml(zip, wbPath);
    if (!wb?.workbook) throw new ImportError('El archivo no contiene un libro de Excel válido', 422);

    const wbRels = await readRels(zip, wbPath);
    const relById = Object.fromEntries(wbRels.map((r) => [r.id, r]));
    const sheets = (wb.workbook.sheets?.sheet || []).map((s) => ({
        name: s['@_name'],
        path: relById[s['@_id']]?.target,
    }));

    // Cadenas compartidas (si existen)
    const sstRel = wbRels.find((r) => r.type.endsWith('/sharedStrings'));
    const sstDoc = sstRel ? await readXml(zip, sstRel.target) : null;
    const sharedStrings = (sstDoc?.sst?.si || []).map((si) =>
        si.t !== undefined ? textOf(si.t) : (si.r || []).map((run) => textOf(run.t)).join(''));

    return { zip, sheets, sharedStrings };
};

const cellValue = (c, sharedStrings) => {
    const type = c['@_t'];
    if (type === 's')         return sharedStrings[Number(textOf(c.v))] ?? '';
    if (type === 'inlineStr') return c.is?.t !== undefined ? textOf(c.is.t) : (c.is?.r || []).map((r) => textOf(r.t)).join('');
    if (type === 'b')         return textOf(c.v) === '1' ? 'TRUE' : 'FALSE';
    return textOf(c.v);      // n, str, e, d o sin tipo
};

// Devuelve las filas de la hoja como arrays 1-based de textos
const readSheetRows = async ({ zip, sharedStrings }, sheet) => {
    const doc = await readXml(zip, sheet.path);
    const rows = doc?.worksheet?.sheetData?.row || [];
    const result = [];
    rows.forEach((row, i) => {
        const rowNumber = Number(row['@_r']) || i + 1;
        const values = [];
        (row.c || []).forEach((c, j) => {
            const col = columnIndex(c['@_r']) || j + 1;
            values[col] = cellValue(c, sharedStrings);
        });
        result.push({ rowNumber, values });
    });
    return result;
};

const parseWorkbook = async (buffer, requestedSheet) => {
    const book = await openWorkbook(buffer);
    const sheetNames = book.sheets.map((s) => s.name);
    const sheet = requestedSheet ? book.sheets.find((s) => s.name === requestedSheet) : book.sheets[0];
    if (!sheet || !sheet.path) {
        throw new ImportError(`La hoja "${requestedSheet || ''}" no existe`, 400, { sheetNames });
    }

    const rows = await readSheetRows(book, sheet);
    if (!rows.length) throw new ImportError('La hoja está vacía', 422, { sheetNames });

    // Encabezados = primera fila
    const headerValues = rows[0].values;
    const colIndex = {};
    headerValues.forEach((h, i) => { const name = (h || '').trim(); if (name) colIndex[name] = i; });
    const headers = Object.keys(colIndex);

    const missing = REQUIRED_HEADERS.filter((h) => !(h in colIndex));
    if (missing.length) {
        throw new ImportError(`Faltan columnas obligatorias: ${missing.join(', ')}`, 422, { sheetNames, headers });
    }

    const valid = [];
    const rejected = [];
    const seenLogIds = new Set();
    let total = 0;

    for (const { rowNumber, values } of rows.slice(1)) {
        const raw = {};
        for (const [header, col] of Object.entries(colIndex)) raw[header] = (values[col] ?? '').trim();
        if (Object.values(raw).every((v) => v === '')) continue;   // fila vacía
        total++;

        const { event, errors } = normalizeRow(raw);
        if (!errors.length && seenLogIds.has(raw.Log_ID)) errors.push('Log_ID duplicado en el archivo');

        if (errors.length) {
            rejected.push({ row: rowNumber, log_id: raw.Log_ID || null, motivos: errors });
            continue;
        }
        seenLogIds.add(raw.Log_ID);
        valid.push(event);
    }

    return { sheetNames, sheetName: sheet.name, headers, total, valid, rejected };
};

// ── Operaciones públicas ─────────────────────────────────────────────────────

const findImportByHash = async (hash) => {
    const { rows } = await pool.query(
        'SELECT id, uuid, file_name, imported_at FROM log_imports WHERE file_sha256 = $1', [hash]);
    return rows[0] || null;
};

// Vista previa: no escribe nada en la base de datos
const previewImport = async ({ buffer, sheetName }) => {
    const parsed   = await parseWorkbook(buffer, sheetName);
    const existing = await findImportByHash(sha256(buffer));
    return {
        sheetNames:      parsed.sheetNames,
        sheetName:       parsed.sheetName,
        headers:         parsed.headers,
        sourceTimezone:  SOURCE_TIMEZONE,
        rowsTotal:       parsed.total,
        rowsValid:       parsed.valid.length,
        rowsRejected:    parsed.rejected.length,
        rejected:        parsed.rejected.slice(0, 100),
        sample:          parsed.valid.slice(0, 20).map(({ raw_payload, ...rest }) => rest),
        alreadyImported: existing,
    };
};

const insertChunk = async (client, importId, events) => {
    const values = [];
    const placeholders = events.map((e, idx) => {
        const base = idx * EVENT_COLUMNS.length;
        values.push(
            importId, e.source_log_id, e.event_type, e.event_code, e.severity,
            e.source_ip, e.dest_ip, e.dest_port, e.hostname, e.user_name, e.destination,
            e.log_source, e.description, e.command_line, e.result, e.source_severity,
            JSON.stringify(e.raw_payload), e.occurred_at,
        );
        return '(' + EVENT_COLUMNS.map((_, j) => `$${base + j + 1}`).join(',') + ')';
    });
    await client.query(
        `INSERT INTO security_events (${EVENT_COLUMNS.join(',')}) VALUES ${placeholders.join(',')}`,
        values,
    );
};

// Importación: todo o nada (una transacción)
const saveImport = async ({ buffer, fileName, sheetName, userUuid }) => {
    const hash = sha256(buffer);
    const existing = await findImportByHash(hash);
    if (existing) throw new ImportError('Este archivo ya fue importado', 409, { existing });

    const parsed = await parseWorkbook(buffer, sheetName);
    if (!parsed.valid.length) {
        throw new ImportError('El archivo no contiene filas válidas', 422, {
            rowsTotal: parsed.total, rejected: parsed.rejected.slice(0, 100),
        });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const { rows } = await client.query(
            `INSERT INTO log_imports
               (file_name, file_sha256, sheet_name, source_timezone, rows_total,
                rows_valid, rows_rejected, rejected_details, status, imported_by_uuid)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'imported',$9)
             RETURNING id, uuid, imported_at`,
            [fileName, hash, parsed.sheetName, SOURCE_TIMEZONE, parsed.total,
             parsed.valid.length, parsed.rejected.length, JSON.stringify(parsed.rejected),
             UUID_REGEX.test(userUuid || '') ? userUuid : null],
        );
        const importRow = rows[0];

        for (let i = 0; i < parsed.valid.length; i += INSERT_CHUNK_SIZE) {
            await insertChunk(client, importRow.id, parsed.valid.slice(i, i + INSERT_CHUNK_SIZE));
        }

        await client.query('COMMIT');

        return {
            id:             importRow.id,
            uuid:           importRow.uuid,
            importedAt:     importRow.imported_at,
            fileName,
            sheetName:      parsed.sheetName,
            sourceTimezone: SOURCE_TIMEZONE,
            rowsTotal:      parsed.total,
            rowsValid:      parsed.valid.length,
            rowsRejected:   parsed.rejected.length,
            rejected:       parsed.rejected.slice(0, 100),
        };
    } catch (err) {
        await client.query('ROLLBACK');
        if (err.code === '23505') throw new ImportError('Este archivo ya fue importado', 409);
        throw err;
    } finally {
        client.release();
    }
};

const listImports = async () => {
    const { rows } = await pool.query(
        `SELECT id, uuid, file_name, sheet_name, source_timezone, rows_total, rows_valid,
                rows_rejected, status, imported_by_uuid, imported_at, analyzed_at
         FROM log_imports ORDER BY imported_at DESC`);
    return rows;
};

const getImport = async (id) => {
    const { rows } = await pool.query('SELECT * FROM log_imports WHERE id = $1', [id]);
    if (!rows.length) return null;
    const stats = await pool.query(
        `SELECT event_type, count(*)::int AS total
         FROM security_events WHERE import_id = $1
         GROUP BY event_type ORDER BY total DESC`, [id]);
    return { ...rows[0], eventsByType: stats.rows };
};

// Borra la importación y, en cascada, sus eventos, alertas, incidentes e informes
const deleteImport = async (id) => {
    const { rowCount } = await pool.query('DELETE FROM log_imports WHERE id = $1', [id]);
    return rowCount > 0;
};

module.exports = {
    ImportError,
    previewImport,
    saveImport,
    listImports,
    getImport,
    deleteImport,
    SOURCE_TIMEZONE,
};
