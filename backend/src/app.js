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

// v2.1 · H-21: NO se confía en X-Forwarded-For. El proxy de Next.js no añade la IP real del cliente:
// solo reenvía la cabecera si el cliente la envía, así que confiar en ella permitiría falsear la IP.
// Riesgo aceptado: req.ip es la IP del proxy. Corrección prevista: un proxy inverso que fije la IP real.
app.set('trust proxy', false);

const limiter = (windowMin, max, message, extra = {}) => rateLimit({
    windowMs: windowMin * 60 * 1000, max, standardHeaders: true, legacyHeaders: false,
    message: { error: message }, ...extra,
});

// Login: 10 intentos cada 2 minutos por IP (el bloqueo por cuenta está en el servicio de login)
const loginLimiter = limiter(2, 10, 'Demasiados intentos. Espera 2 minutos.');
// v2.1 · H-18: registro, 10 cada 15 minutos por IP (cada registro calcula un bcrypt)
const registerLimiter = limiter(15, 10, 'Demasiados registros desde esta dirección. Espera 15 minutos.');
// v2.1 · H-20: comprobaciones de disponibilidad, 30 por minuto por IP (impide enumerar cuentas en masa)
const checkLimiter = limiter(1, 30, 'Demasiadas comprobaciones. Espera un minuto.');
// v2.1 · H-19: operaciones costosas (análisis, IA, hallazgos y PDF), 30 cada 15 minutos por IP
const HEAVY = /^\/api\/(imports\/\d+\/(analyze|reports|audit|audit-report\.pdf)|analysis\/reports\/\d+\/pdf)(\?|$)/;
const heavyLimiter = limiter(15, 30, 'Demasiadas operaciones costosas. Espera unos minutos.', {
    skip: (req) => !(HEAVY.test(req.originalUrl) && (req.method === 'POST' || req.originalUrl.includes('pdf'))),
});
// v2.1 · H-19: límite general para toda la API, 600 peticiones cada 15 minutos por IP
const apiLimiter = limiter(15, 600, 'Demasiadas peticiones. Espera unos minutos.');

// 4 MB: el avatar (máx. 2 MB) llega en base64, que ocupa ~33 % más
app.use(express.json({ limit: '4mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(morgan(':remote-addr :method :url :status :response-time ms'));

app.use('/api', apiLimiter);
app.use('/api', heavyLimiter);
app.use('/api/auth/login', loginLimiter);
app.use('/api/auth/register', registerLimiter);
app.use(['/api/auth/check-username', '/api/auth/check-email'], checkLimiter);
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
