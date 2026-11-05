// src/routes/analysis.js — montado en /api/analysis
const express = require('express');
const router  = express.Router();

const ctrl    = require('../controllers/analysisController');
const reports = require('../controllers/reportsController');
const auditCtl = require('../controllers/auditController');
const { authMiddleware } = require('../middleware/auth');

router.use(authMiddleware);

router.get('/rules',      ctrl.rules);
router.get('/alerts/:id', ctrl.alertDetail);
router.get('/reports/:id',     reports.getOne);
router.get('/reports/:id/pdf', reports.pdf);

// v2.0 · Seguimiento de hallazgos de auditoría (las reglas de rol se aplican en el servicio)
router.patch('/audit-findings/:id',        auditCtl.update);
router.get('/audit-findings/:id/history',  auditCtl.history);

module.exports = router;
