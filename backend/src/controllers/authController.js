const bcrypt = require('bcryptjs');
const jwt    = require('jsonwebtoken');
const path   = require('path');
const fs     = require('fs');
const db     = require('../services/dbAdapter');
const lockout = require('../services/lockoutService');

// ── Helpers ──────────────────────────────────────────────────

const calcAge = (birthDate) => {
    const today = new Date();
    const birth = new Date(birthDate);
    let age = today.getFullYear() - birth.getFullYear();
    const m = today.getMonth() - birth.getMonth();
    if (m < 0 || (m === 0 && today.getDate() < birth.getDate())) age--;
    return age;
};

const ALLOWED_TYPES = ['image/jpeg', 'image/png', 'image/webp'];
const MAX_SIZE_BYTES = 2 * 1024 * 1024; // 2MB
const DUMMY_HASH = bcrypt.hashSync('equalizador-de-tiempo', 12);

// ── Login ────────────────────────────────────────────────────

const login = async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password)
            return res.status(400).json({ error: 'Username y password son requeridos' });

        const user = await db.getUserByUsername(username.trim());
        const GENERIC = 'Credenciales inválidas o cuenta bloqueada temporalmente';
        const audit = async (action, extra = {}) => {
            try {
                await db.logAuditAction({ userUuid: user ? user.uuid : null, action, targetType: null, targetId: null,
                    oldValues: null, newValues: { username: username.trim(), ...extra }, ipAddress: req.ip });
            } catch (e) { console.log('Audit log skipped:', e.message); }
        };

        // Usuario inexistente: hash ficticio para igualar el tiempo de respuesta (H-10)
        if (!user) {
            await bcrypt.compare(password, DUMMY_HASH);
            await audit('login_failed', { reason: 'unknown_user' });
            return res.status(401).json({ error: GENERIC });
        }

        // Cuenta bloqueada temporalmente por intentos fallidos (H-09)
        if (await lockout.isLocked(user.username)) {
            await bcrypt.compare(password, DUMMY_HASH);
            await audit('login_blocked');
            return res.status(401).json({ error: GENERIC });
        }

        const passwordMatch = await bcrypt.compare(password, user.password_hash);
        if (!passwordMatch) {
            const nowLocked = await lockout.registerFailure(user.username);
            await audit(nowLocked ? 'account_locked' : 'login_failed', nowLocked ? { minutes: lockout.LOCK_MINUTES } : {});
            return res.status(401).json({ error: GENERIC });
        }

        // El estado de la cuenta solo se revela a quien ya conoce la contraseña (H-10)
        if (user.status !== 'active')
            return res.status(403).json({ error: 'Cuenta inactiva o bloqueada' });

        await lockout.reset(user.username);

        const age = user.birth_date ? calcAge(user.birth_date) : null;

        const token = jwt.sign(
            { uuid: user.uuid, username: user.username, role: user.role || 'analyst', name: user.full_name },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN || '8h' }
        );

        try {
            await db.logAuditAction({
                userUuid:   user.uuid,
                action:     'login',
                targetType: null,
                targetId:   null,
                oldValues:  null,
                newValues:  { method: 'password', username: user.username },
                ipAddress:  req.ip,
            });
        } catch(e) {
            console.log('Audit log skipped:', e.message);
        }

        return res.status(200).json({
            token,
            user: {
                uuid:       user.uuid,
                username:   user.username,
                role:       user.role || 'analyst',
                name:       user.full_name,
                email:      user.email,
                age:        age,
                avatar:     user.avatar_path || null,
            },
        });

    } catch (err) {
        console.error('[login]', err.message);
        return res.status(500).json({ error: 'Error interno del servidor' });
    }
};

// ── Register ─────────────────────────────────────────────────

const register = async (req, res) => {
    try {
        const { username, email, password, full_name, birth_date, avatar_base64, avatar_mime } = req.body;

        // Validación campos requeridos
        if (!username || !email || !password || !full_name || !birth_date)
            return res.status(400).json({ error: 'Todos los campos son requeridos' });

        // Validación longitud username
        if (username.length < 3 || username.length > 20)
            return res.status(400).json({ error: 'Username debe tener entre 3 y 20 caracteres' });

        // Validación caracteres username
        if (!/^[a-zA-Z0-9._]+$/.test(username))
            return res.status(400).json({ error: 'Username solo puede contener letras, números, puntos y guiones bajos' });

        // Validación email
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
            return res.status(400).json({ error: 'Email inválido' });

        if (email.length > 254)
            return res.status(400).json({ error: 'Email demasiado largo' });

        // Validación password
        if (password.length < 8 || password.length > 72)
            return res.status(400).json({ error: 'Password debe tener entre 8 y 72 caracteres' });

        // Validación edad mínima 18 años desde birth_date
        const age = calcAge(birth_date);
        if (age < 18)
            return res.status(400).json({ error: 'Debes tener al menos 18 años para registrarte' });

        if (age > 120)
            return res.status(400).json({ error: 'Fecha de nacimiento inválida' });

        // Verificar username duplicado
        const existingUser = await db.getUserByUsername(username.trim());
        if (existingUser)
            return res.status(409).json({ error: `El username "${username}" ya está en uso` });

        // Verificar email duplicado
        const existingEmail = await db.getUserByEmail(email.trim().toLowerCase());
        if (existingEmail)
            return res.status(409).json({ error: `El email "${email}" ya está registrado` });

        // Procesar avatar si viene
        let avatarPath = null;
        if (avatar_base64 && avatar_mime) {
            // Validar tipo
            if (!ALLOWED_TYPES.includes(avatar_mime))
                return res.status(400).json({ error: 'Solo se permiten imágenes JPG, PNG o WebP' });

            // Validar tamaño (base64 ~= 4/3 del tamaño real)
            const buffer = Buffer.from(avatar_base64, 'base64');
            if (buffer.length > MAX_SIZE_BYTES)
                return res.status(400).json({ error: 'La imagen no puede superar 2MB' });

            // Guardar archivo
            const ext = avatar_mime.split('/')[1].replace('jpeg','jpg');
            const filename = `avatar_${Date.now()}_${Math.random().toString(36).slice(2,8)}.${ext}`;
            const uploadDir = path.join('/app/uploads/avatars');
            fs.mkdirSync(uploadDir, { recursive: true });
            fs.writeFileSync(path.join(uploadDir, filename), buffer);
            avatarPath = `uploads/avatars/${filename}`;
        }

        // Hash password
        const password_hash = await bcrypt.hash(password, 10);

        // Insertar usuario
        const newUser = await db.createUser({
            username:      username.trim(),
            email:         email.trim().toLowerCase(),
            password_hash,
            full_name:     full_name.trim().slice(0, 60),
            birth_date,
            avatar_path:   avatarPath,
        });

        return res.status(201).json({
            message: 'Usuario registrado exitosamente',
            user: {
                uuid:     newUser.uuid,
                username: newUser.username,
                email:    newUser.email,
                name:     newUser.full_name,
                age:      age,
            }
        });

    } catch (err) {
        console.error('[register]', err.message);
        return res.status(500).json({ error: 'Error interno del servidor' });
    }
};

// ── Check username disponible ─────────────────────────────────

const checkUsername = async (req, res) => {
    try {
        const { username } = req.query;
        if (!username) return res.status(400).json({ error: 'Username requerido' });
        const exists = await db.getUserByUsername(username.trim());
        return res.json({ available: !exists });
    } catch (err) {
        return res.status(500).json({ error: 'Error interno del servidor' });
    }
};

// ── Check email disponible ────────────────────────────────────

const checkEmail = async (req, res) => {
    try {
        const { email } = req.query;
        if (!email) return res.status(400).json({ error: 'Email requerido' });
        const exists = await db.getUserByEmail(email.trim().toLowerCase());
        return res.json({ available: !exists });
    } catch (err) {
        return res.status(500).json({ error: 'Error interno del servidor' });
    }
};

// ── Get me ────────────────────────────────────────────────────

const getMe = async (req, res) => {
    try {
        const profile = await db.getAnalystCrossMotorProfile(req.user.uuid);
        if (!profile) return res.status(404).json({ error: 'Usuario no encontrado' });
        return res.status(200).json(profile);
    } catch (err) {
        console.error('[getMe]', err.message);
        return res.status(500).json({ error: 'Error interno del servidor' });
    }
};

module.exports = { login, register, checkUsername, checkEmail, getMe };
