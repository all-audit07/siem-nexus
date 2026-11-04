const express  = require('express');
const router   = express.Router();
const { login, getMe, register, checkUsername, checkEmail } = require('../controllers/authController');
const { authMiddleware } = require('../middleware/auth');

router.post('/login',            login);
router.post('/register',         register);
router.get('/check-username',    checkUsername);
router.get('/check-email',       checkEmail);
router.get('/me',                authMiddleware, getMe);

module.exports = router;
