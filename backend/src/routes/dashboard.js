const express = require('express');
const router  = express.Router();
const ctrl    = require('../controllers/dashboardController');
const { authMiddleware } = require('../middleware/auth');

router.use(authMiddleware);

router.get('/summary',             ctrl.getSummary);
router.get('/incidents',           ctrl.getIncidents);
router.get('/alerts',              ctrl.getAlerts);
router.patch('/alerts/:id/status', ctrl.updateAlertStatus);
router.get('/events',              ctrl.getEvents);
router.get('/vulnerabilities',     ctrl.getVulnerabilities);
router.get('/activity',            ctrl.getActivity);
router.get('/audit',               ctrl.getAuditLogs);
router.get('/analyst/:uuid',       ctrl.getAnalystProfile);

module.exports = router;
