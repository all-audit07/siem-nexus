// src/controllers/importController.js
const importService = require('../services/importService');
const db            = require('../services/dbAdapter');

const { ImportError } = importService;

// Envuelve cada handler: errores controlados → su código HTTP; el resto → 500
const handle = (fn) => async (req, res) => {
    try {
        await fn(req, res);
    } catch (err) {
        if (err instanceof ImportError) {
            return res.status(err.status).json({ error: err.message, ...err.details });
        }
        console.error('[imports]', err.message);
        return res.status(500).json({ error: 'Error interno del servidor' });
    }
};

const requireFile = (req) => {
    if (!req.file) throw new ImportError('Debes adjuntar un archivo .xlsx en el campo "file"', 400);
};

// Multer entrega el nombre en latin1; se convierte a UTF-8 (acentos, ñ)
const fileNameOf = (file) => Buffer.from(file.originalname, 'latin1').toString('utf8');

const parseId = (req) => {
    if (!/^\d+$/.test(req.params.id)) throw new ImportError('ID inválido', 400);
    return Number(req.params.id);
};

const audit = async (req, action, targetId, newValues) => {
    try {
        await db.logAuditAction({
            userUuid:   req.user.uuid,
            action,
            targetType: 'log_imports',
            targetId,
            oldValues:  null,
            newValues,
            ipAddress:  req.ip,
        });
    } catch (e) {
        console.log('Audit log skipped:', e.message);
    }
};

// POST /api/imports/preview — valida y muestra, sin guardar
const preview = handle(async (req, res) => {
    requireFile(req);
    const result = await importService.previewImport({
        buffer:    req.file.buffer,
        sheetName: req.body.sheet || null,
    });
    res.json({ fileName: fileNameOf(req.file), ...result });
});

// POST /api/imports — importa a PostgreSQL
const create = handle(async (req, res) => {
    requireFile(req);
    const result = await importService.saveImport({
        buffer:    req.file.buffer,
        fileName:  fileNameOf(req.file),
        sheetName: req.body.sheet || null,
        userUuid:  req.user.uuid,
    });
    await audit(req, 'import.create', result.id, {
        file: result.fileName, rowsValid: result.rowsValid, rowsRejected: result.rowsRejected,
    });
    res.status(201).json(result);
});

// GET /api/imports
const list = handle(async (req, res) => {
    res.json(await importService.listImports());
});

// GET /api/imports/:id
const getOne = handle(async (req, res) => {
    const item = await importService.getImport(parseId(req));
    if (!item) return res.status(404).json({ error: 'Importación no encontrada' });
    res.json(item);
});

// DELETE /api/imports/:id — solo admin
const remove = handle(async (req, res) => {
    const id = parseId(req);
    const deleted = await importService.deleteImport(id);
    if (!deleted) return res.status(404).json({ error: 'Importación no encontrada' });
    await audit(req, 'import.delete', id, null);
    res.json({ deleted: true, id });
});

module.exports = { preview, create, list, getOne, remove };
