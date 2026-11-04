// src/routes/analysis.js — montado en /api/analysis
const express = require('express');
const router  = express.Router();

const ctrl    = require('../controllers/analysisController');
const reports = require('../controllers/reportsController');
const { authMiddleware } = require('../middleware/auth');

router.use(authMiddleware);

router.get('/rules',      ctrl.rules);
router.get('/alerts/:id', ctrl.alertDetail);
router.get('/reports/:id',     reports.getOne);
router.get('/reports/:id/pdf', reports.pdf);

module.exports = router;
