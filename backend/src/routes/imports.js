// src/routes/imports.js
const express = require('express');
const multer  = require('multer');
const router  = express.Router();

const ctrl     = require('../controllers/importController');
const analysis = require('../controllers/analysisController');
const events   = require('../controllers/eventsController');
const reports  = require('../controllers/reportsController');
const { authMiddleware, requireRole } = require('../middleware/auth');

const MAX_FILE_MB = 10;

const upload = multer({
    storage: multer.memoryStorage(),
    limits:  { fileSize: MAX_FILE_MB * 1024 * 1024, files: 1 },
    fileFilter: (req, file, cb) => {
        if (/\.xlsx$/i.test(file.originalname)) return cb(null, true);
        cb(Object.assign(new Error('Solo se aceptan archivos .xlsx'), { code: 'INVALID_TYPE' }));
    },
});

// Traduce los errores de subida a respuestas claras
const uploadSingle = (req, res, next) => {
    upload.single('file')(req, res, (err) => {
        if (!err) return next();
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(413).json({ error: `El archivo supera ${MAX_FILE_MB} MB` });
        }
        return res.status(400).json({ error: err.message });
    });
};

router.use(authMiddleware);

router.post('/preview', requireRole('admin', 'analyst'), uploadSingle, ctrl.preview);
router.post('/',        requireRole('admin', 'analyst'), uploadSingle, ctrl.create);
router.get('/',         ctrl.list);
router.get('/:id',      ctrl.getOne);
router.delete('/:id',   requireRole('admin'), ctrl.remove);

// Análisis de seguridad sobre una importación
router.post('/:id/analyze',  requireRole('admin', 'analyst'), analysis.analyze);
router.get('/:id/alerts',    analysis.alerts);
router.get('/:id/incidents', analysis.incidents);

// Consulta de eventos y resumen para el dashboard
router.get('/:id/events',    events.events);
router.get('/:id/summary',   events.summary);

// Informes técnicos
router.post('/:id/reports',  requireRole('admin', 'analyst'), reports.create);
router.get('/:id/reports',   reports.list);

module.exports = router;
