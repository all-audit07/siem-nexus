require('dotenv').config();
const express     = require('express');
const cors        = require('cors');
const helmet      = require('helmet');
const morgan      = require('morgan');
const path        = require('path');
const rateLimit   = require('express-rate-limit');

const authRoutes      = require('./routes/auth');
const dashboardRoutes = require('./routes/dashboard');
const importRoutes    = require('./routes/imports');
const analysisRoutes  = require('./routes/analysis');

const app = express();

app.use(helmet());
app.use(cors({
    origin: ['http://localhost:5173', 'http://localhost:3001', 'http://localhost:8080', 'http://192.168.106.132:3000', 'null'],
    credentials: true,
}));

// Límite de intentos SOLO para el login (no para registro ni comprobaciones de disponibilidad)
const loginLimiter = rateLimit({
    windowMs: 2 * 60 * 1000,
    max: 10,
    message: { error: 'Demasiados intentos. Espera 2 minutos.' },
});

// 4 MB: el avatar (máx. 2 MB) llega en base64, que ocupa ~33 % más
app.use(express.json({ limit: '4mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(morgan('dev'));

app.use('/api/auth/login', loginLimiter);
app.use('/api/auth',      authRoutes);
app.use('/api/dashboard', dashboardRoutes);
app.use('/api/imports',   importRoutes);
app.use('/api/analysis',  analysisRoutes);

// Avatares de usuario (nombres aleatorios, solo imágenes ya validadas en el registro)
app.use('/api/uploads/avatars', express.static(path.join('/app/uploads/avatars'), {
    fallthrough: false, maxAge: '1d', index: false, dotfiles: 'deny',
}));

app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString(), motors: ['mysql', 'postgresql', 'sqlserver'] });
});

app.use((req, res) => res.status(404).json({ error: 'Ruta no encontrada' }));
app.use((err, req, res, next) => {
    if (err.type === 'entity.too.large') return res.status(413).json({ error: 'La solicitud es demasiado grande' });
    if (err.status === 404 || err.statusCode === 404) return res.status(404).json({ error: 'Archivo no encontrado' });
    console.error('[ERROR]', err.message);
    res.status(500).json({ error: 'Error interno del servidor' });
});

module.exports = app;
