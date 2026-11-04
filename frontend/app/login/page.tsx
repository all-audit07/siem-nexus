"use client";

import { useState, useRef, useCallback, useEffect } from "react";
import { useRouter } from "next/navigation";
import { motion, AnimatePresence } from "framer-motion";
import dynamic from "next/dynamic";

const CyberneticGridShader = dynamic(
  () => import("@/components/ui/cybernetic-grid-shader"),
  { ssr: false }
);

const API = "/api";

const demoAccounts = [
  { username: "admin",      password: "",   role: "ADMIN",   roleClass: "text-red-400 bg-red-500/10 border-red-500/20" },
  { username: "ana.gomez",  password: "", role: "ANALYST", roleClass: "text-blue-400 bg-blue-500/10 border-blue-500/20" },
  { username: "lucia.chen", password: "", role: "AUDITOR", roleClass: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20" },
  { username: "pedro.silva",password: "",  role: "VIEWER",  roleClass: "text-green-400 bg-green-500/10 border-green-500/20" },
];

// ── Password strength ─────────────────────────────────────────
function getStrength(pw: string) {
  let s = 0;
  if (pw.length >= 8)          s++;
  if (/[A-Z]/.test(pw))        s++;
  if (/[0-9]/.test(pw))        s++;
  if (/[^a-zA-Z0-9]/.test(pw)) s++;
  const labels = ["Muy débil", "Débil", "Moderada", "Fuerte"];
  const colors = ["#EF4444", "#F97316", "#EAB308", "#22C55E"];
  return { score: s, label: s > 0 ? labels[s - 1] : "", color: s > 0 ? colors[s - 1] : "" };
}

export default function LoginPage() {
  const router = useRouter();
  const [panel, setPanel] = useState<"login" | "register">("login");

  // ── Login state ───────────────────────────────────────────
  const [loginUser, setLoginUser]   = useState("");
  const [loginPass, setLoginPass]   = useState("");
  const [showLoginPw, setShowLoginPw] = useState(false);
  const [loginError, setLoginError] = useState("");
  const [loginLoading, setLoginLoading] = useState(false);

  // ── Register state ────────────────────────────────────────
  const [regFullname,  setRegFullname]  = useState("");
  const [regUsername,  setRegUsername]  = useState("");
  const [regEmail,     setRegEmail]     = useState("");
  const [regBirthdate, setRegBirthdate] = useState("");
  const [regPassword,  setRegPassword]  = useState("");
  const [regConfirm,   setRegConfirm]   = useState("");
  const [showRegPw,    setShowRegPw]    = useState(false);
  const [showRegCf,    setShowRegCf]    = useState(false);
  const [regError,     setRegError]     = useState("");
  const [regSuccess,   setRegSuccess]   = useState("");
  const [regLoading,   setRegLoading]   = useState(false);
  const [usernameStatus, setUsernameStatus] = useState<"idle"|"checking"|"ok"|"taken">("idle");
  const [emailStatus,    setEmailStatus]    = useState<"idle"|"checking"|"ok"|"taken">("idle");
  const [ageHint,        setAgeHint]        = useState("");

  // Avatar
  const avatarRef = useRef<HTMLInputElement>(null);
  const [avatarPreview, setAvatarPreview] = useState<string | null>(null);
  const [avatarB64, setAvatarB64] = useState<string | null>(null);
  const [avatarMime, setAvatarMime] = useState<string | null>(null);
  const [avatarError, setAvatarError] = useState("");

  const strength = getStrength(regPassword);

  // Today max date
  const today = new Date().toISOString().split("T")[0];

  // ── Username debounce ─────────────────────────────────────
  const usernameTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const checkUsername = useCallback((val: string) => {
    if (usernameTimer.current) clearTimeout(usernameTimer.current);
    if (val.length < 3 || !/^[a-zA-Z0-9._]+$/.test(val)) { setUsernameStatus("idle"); return; }
    setUsernameStatus("checking");
    usernameTimer.current = setTimeout(async () => {
      try {
        const r = await fetch(`${API}/auth/check-username?username=${encodeURIComponent(val)}`);
        const d = await r.json();
        setUsernameStatus(d.available ? "ok" : "taken");
      } catch { setUsernameStatus("idle"); }
    }, 600);
  }, []);

  // ── Email debounce ────────────────────────────────────────
  const emailTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const checkEmail = useCallback((val: string) => {
    if (emailTimer.current) clearTimeout(emailTimer.current);
    if (!val.includes("@") || val.length < 5) { setEmailStatus("idle"); return; }
    setEmailStatus("checking");
    emailTimer.current = setTimeout(async () => {
      try {
        const r = await fetch(`${API}/auth/check-email?email=${encodeURIComponent(val)}`);
        const d = await r.json();
        setEmailStatus(d.available ? "ok" : "taken");
      } catch { setEmailStatus("idle"); }
    }, 600);
  }, []);

  // ── Age validation ────────────────────────────────────────
  const validateAge = (val: string) => {
    if (!val) { setAgeHint(""); return; }
    const birth = new Date(val);
    const now   = new Date();
    let age = now.getFullYear() - birth.getFullYear();
    const m = now.getMonth() - birth.getMonth();
    if (m < 0 || (m === 0 && now.getDate() < birth.getDate())) age--;
    if (age < 18) setAgeHint(`Tienes ${age} años — mínimo 18`);
    else           setAgeHint(`Edad: ${age} años`);
  };

  // ── Avatar ────────────────────────────────────────────────
  const handleAvatar = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setAvatarError("");
    const allowed = ["image/jpeg", "image/png", "image/webp"];
    if (!allowed.includes(file.type)) { setAvatarError("Solo JPG, PNG o WebP"); return; }
    if (file.size > 2 * 1024 * 1024)  { setAvatarError("Máximo 2MB"); return; }
    const reader = new FileReader();
    reader.onload = (ev) => {
      const dataUrl = ev.target?.result as string;
      const img = new Image();
      img.onload = () => {
        if (img.width > 400 || img.height > 400) { setAvatarError("Máximo 400×400px"); return; }
        setAvatarPreview(dataUrl);
        setAvatarB64(dataUrl.split(",")[1]);
        setAvatarMime(file.type);
      };
      img.src = dataUrl;
    };
    reader.readAsDataURL(file);
  };

  // ── Login submit ──────────────────────────────────────────
  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoginError("");
    if (!loginUser || !loginPass) { setLoginError("Completa todos los campos"); return; }
    setLoginLoading(true);
    try {
      const res  = await fetch(`${API}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: loginUser, password: loginPass }),
      });
      const data = await res.json();
      if (!res.ok) { setLoginError(data.error || "Error de autenticación"); setLoginLoading(false); return; }
      localStorage.setItem("siem_token", data.token);
      localStorage.setItem("siem_user",  JSON.stringify(data.user));
      router.push("/dashboard");
    } catch {
      setLoginError("No se pudo contactar con el servidor");
      setLoginLoading(false);
    }
  };

  // ── Register submit ───────────────────────────────────────
  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setRegError(""); setRegSuccess("");
    if (!regFullname)               { setRegError("El nombre completo es requerido"); return; }
    if (regUsername.length < 3)     { setRegError("Username muy corto"); return; }
    if (!regEmail.includes("@"))    { setRegError("Email inválido"); return; }
    if (!regBirthdate)              { setRegError("Fecha de nacimiento requerida"); return; }
    if (regPassword.length < 8)     { setRegError("Contraseña mínimo 8 caracteres"); return; }
    if (regPassword !== regConfirm) { setRegError("Las contraseñas no coinciden"); return; }
    setRegLoading(true);
    try {
      const body: Record<string, string> = {
        username: regUsername, email: regEmail, password: regPassword,
        full_name: regFullname, birth_date: regBirthdate,
      };
      if (avatarB64 && avatarMime) { body.avatar_base64 = avatarB64; body.avatar_mime = avatarMime; }
      const res  = await fetch(`${API}/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) { setRegError(data.error || "Error al registrar"); setRegLoading(false); return; }
      setRegSuccess(`¡Cuenta creada! Bienvenido, ${data.user.name}. Inicia sesión.`);
      setTimeout(() => { setPanel("login"); setLoginUser(regUsername); }, 2500);
    } catch {
      setRegError("No se pudo conectar al servidor");
    }
    setRegLoading(false);
  };

  const fillDemo = (u: string, p: string) => {
    setLoginUser(u); setLoginPass(p); setLoginError("");
  };

  // ── Shared input class ────────────────────────────────────
  const inputCls = "w-full bg-white/[0.04] border border-white/[0.09] rounded-[10px] px-[42px] py-[13px] text-sm text-[#E2E8F0] placeholder:text-[#94A3B8]/50 outline-none focus:border-[#3B82F6] focus:bg-blue-500/[0.06] focus:shadow-[0_0_0_3px_rgba(59,130,246,0.15)] transition-all duration-200";

  return (
    <div className="min-h-screen flex bg-[#020817] overflow-hidden relative">
      {/* Shader background */}
      <CyberneticGridShader />

      {/* Grid overlay */}
      <div className="fixed inset-0 pointer-events-none z-0 bg-grid opacity-60" />

      {/* ── LEFT PANEL ─────────────────────────────────────── */}
      <div className="hidden lg:flex flex-1 flex-col items-center justify-center px-14 py-16 relative z-10">
        <motion.div
          initial={{ opacity: 0, y: 24 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, ease: "easeOut" }}
          className="flex flex-col items-center text-center max-w-sm"
        >
          {/* Shield logo */}
          <div className="w-[88px] h-[88px] rounded-3xl bg-gradient-to-br from-blue-500 to-blue-800 flex items-center justify-center mb-8 shadow-[0_0_50px_rgba(59,130,246,0.5)]">
            <svg width="44" height="44" viewBox="0 0 26 26" fill="none">
              <path d="M13 2L3 7v6c0 5.5 4.3 10.7 10 12 5.7-1.3 10-6.5 10-12V7L13 2z"
                fill="rgba(255,255,255,0.15)" stroke="white" strokeWidth="1.5" strokeLinejoin="round"/>
              <path d="M9 13l2.5 2.5L17 10" stroke="white" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </div>

          <h1 className="font-mono text-4xl font-semibold tracking-[0.1em] text-[#E2E8F0] mb-2">SIEM NEXUS</h1>
          <p className="font-mono text-xs text-[#94A3B8] tracking-[0.12em] uppercase mb-10">
            Security Information &amp; Event Management
          </p>

          {/* Feature list */}
          <div className="w-full text-left space-y-4 mb-10">
            {[
              { title: "Control de acceso RBAC", desc: "Roles diferenciados: admin, analyst, auditor y viewer." },
              { title: "Arquitectura dual-motor", desc: "MySQL para autenticación, PostgreSQL para correlación de eventos." },
              { title: "Integridad criptográfica", desc: "Audit logs con hash SHA-256 via pgcrypto en tiempo real." },
            ].map((f) => (
              <div key={f.title} className="flex items-start gap-3.5">
                <div className="w-[22px] h-[22px] rounded-md bg-blue-500/10 border border-blue-500/25 flex items-center justify-center flex-shrink-0 mt-0.5">
                  <svg width="11" height="11" fill="none" viewBox="0 0 24 24" stroke="#3B82F6" strokeWidth={2.5}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7"/>
                  </svg>
                </div>
                <div>
                  <p className="text-sm font-medium text-[#E2E8F0]">{f.title}</p>
                  <p className="text-xs text-[#94A3B8] mt-0.5 leading-relaxed">{f.desc}</p>
                </div>
              </div>
            ))}
          </div>

          {/* Motor badges */}
          <div className="flex gap-2.5">
            {[
              { dot: "#F59E0B", label: "MySQL — Gestión" },
              { dot: "#3B82F6", label: "PostgreSQL — Correlación" },
            ].map((m) => (
              <div key={m.label} className="flex items-center gap-1.5 bg-white/[0.04] border border-white/[0.07] rounded-lg px-3 py-1.5 font-mono text-[11px] text-[#94A3B8]">
                <span className="w-1.5 h-1.5 rounded-full" style={{ background: m.dot, boxShadow: `0 0 6px ${m.dot}` }} />
                {m.label}
              </div>
            ))}
          </div>
        </motion.div>
      </div>

      {/* ── RIGHT PANEL ────────────────────────────────────── */}
      <div className="w-full lg:w-[480px] lg:min-w-[480px] relative z-10 flex items-center justify-center px-6 py-12 bg-[rgba(15,23,42,0.6)] backdrop-blur-[28px] border-l border-white/[0.07] overflow-y-auto">

        <AnimatePresence mode="wait">
          {panel === "login" ? (
            <motion.div
              key="login"
              initial={{ opacity: 0, x: 40 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -40 }}
              transition={{ duration: 0.35 }}
              className="w-full max-w-[392px]"
            >
              <div className="mb-7">
                <h2 className="text-2xl font-semibold tracking-tight text-[#E2E8F0]">Acceso al sistema</h2>
                <p className="text-sm text-[#94A3B8] mt-1.5">Autenticación requerida para continuar</p>
              </div>

              {loginError && (
                <div className="flex items-center gap-2.5 bg-red-500/[0.08] border border-red-500/25 rounded-lg px-4 py-3 mb-4 text-sm text-red-300">
                  <svg width="15" height="15" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
                  </svg>
                  {loginError}
                </div>
              )}

              <form onSubmit={handleLogin} className="space-y-4">
                {/* Username */}
                <div>
                  <label className="block text-[11px] font-medium text-[#94A3B8] tracking-[0.09em] uppercase mb-1.5">Usuario</label>
                  <div className="relative">
                    <span className="absolute left-3.5 top-1/2 -translate-y-1/2 text-[#94A3B8]">
                      <svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/>
                      </svg>
                    </span>
                    <input
                      type="text"
                      value={loginUser}
                      onChange={(e) => setLoginUser(e.target.value)}
                      placeholder="username"
                      autoComplete="username"
                      className={inputCls}
                    />
                  </div>
                </div>

                {/* Password */}
                <div>
                  <label className="block text-[11px] font-medium text-[#94A3B8] tracking-[0.09em] uppercase mb-1.5">Contraseña</label>
                  <div className="relative">
                    <span className="absolute left-3.5 top-1/2 -translate-y-1/2 text-[#94A3B8]">
                      <svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                      </svg>
                    </span>
                    <input
                      type={showLoginPw ? "text" : "password"}
                      value={loginPass}
                      onChange={(e) => setLoginPass(e.target.value)}
                      placeholder="••••••••"
                      autoComplete="current-password"
                      className={inputCls}
                    />
                    <button type="button" onClick={() => setShowLoginPw((v) => !v)} className="absolute right-3.5 top-1/2 -translate-y-1/2 text-[#94A3B8] hover:text-[#E2E8F0] transition-colors">
                      <svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                        {showLoginPw
                          ? <path strokeLinecap="round" strokeLinejoin="round" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21"/>
                          : <><path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/><path strokeLinecap="round" strokeLinejoin="round" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/></>
                        }
                      </svg>
                    </button>
                  </div>
                </div>

                <motion.button
                  type="submit"
                  disabled={loginLoading}
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                  className="w-full py-3.5 rounded-[10px] font-semibold text-[15px] text-white bg-gradient-to-r from-blue-500 to-blue-700 shadow-[0_4px_20px_rgba(59,130,246,0.4)] hover:shadow-[0_6px_28px_rgba(59,130,246,0.6)] transition-shadow duration-200 disabled:opacity-55 disabled:cursor-not-allowed mt-2"
                >
                  {loginLoading ? "Verificando..." : "Ingresar al SIEM"}
                </motion.button>
              </form>

              {/* Divider */}
              <div className="flex items-center gap-3 my-5">
                <div className="flex-1 h-px bg-white/[0.07]" />
                <span className="font-mono text-[10px] text-[#94A3B8] tracking-[0.12em] uppercase">Cuentas de demo</span>
                <div className="flex-1 h-px bg-white/[0.07]" />
              </div>

              <div className="bg-white/[0.025] border border-white/[0.07] rounded-[10px] overflow-hidden">
                <p className="font-mono text-[10px] text-[#94A3B8] tracking-[0.12em] uppercase px-3.5 pt-3 pb-2">Haz clic para autocompletar</p>
                {demoAccounts.map((d) => (
                  <button
                    key={d.username}
                    onClick={() => fillDemo(d.username, d.password)}
                    className="w-full flex items-center justify-between px-3.5 py-2 border-t border-white/[0.05] hover:bg-blue-500/[0.07] transition-colors text-left"
                  >
                    <span className="font-mono text-sm text-[#E2E8F0]">{d.username}</span>
                    <span className={`text-[10px] font-medium border rounded px-2 py-0.5 font-mono tracking-wide ${d.roleClass}`}>{d.role}</span>
                  </button>
                ))}
              </div>

              <p className="text-center mt-5 text-sm text-[#94A3B8]">
                ¿No tienes cuenta?{" "}
                <button onClick={() => setPanel("register")} className="text-[#3B82F6] font-medium hover:text-blue-400 transition-colors">
                  Regístrate aquí
                </button>
              </p>
              <p className="text-center mt-4 font-mono text-[10px] text-[#94A3B8]/45 tracking-[0.08em]">
                SIEM NEXUS v1.0 — MySQL + PostgreSQL — Multi-Motor
              </p>
            </motion.div>
          ) : (
            /* ── REGISTER PANEL ─────────────────────────────── */
            <motion.div
              key="register"
              initial={{ opacity: 0, x: 40 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -40 }}
              transition={{ duration: 0.35 }}
              className="w-full max-w-[392px]"
            >
              <div className="mb-7">
                <h2 className="text-2xl font-semibold tracking-tight text-[#E2E8F0]">Crear cuenta</h2>
                <p className="text-sm text-[#94A3B8] mt-1.5">Completa los datos para registrarte en el SIEM</p>
              </div>

              {regError && (
                <div className="flex items-center gap-2.5 bg-red-500/[0.08] border border-red-500/25 rounded-lg px-4 py-3 mb-4 text-sm text-red-300">{regError}</div>
              )}
              {regSuccess && (
                <div className="flex items-center gap-2.5 bg-green-500/[0.08] border border-green-500/25 rounded-lg px-4 py-3 mb-4 text-sm text-green-300">{regSuccess}</div>
              )}

              <form onSubmit={handleRegister} className="space-y-4" autoComplete="off">
                {/* Avatar */}
                <div>
                  <label className="block text-[11px] font-medium text-[#94A3B8] tracking-[0.09em] uppercase mb-1.5">
                    Foto de perfil <span className="normal-case tracking-normal text-[#94A3B8]/60">(opcional · máx 2MB · 400×400px)</span>
                  </label>
                  <div
                    onClick={() => avatarRef.current?.click()}
                    className={`border-2 border-dashed rounded-xl p-5 text-center cursor-pointer transition-all ${avatarPreview ? "border-green-500/40 bg-green-500/[0.04]" : "border-white/10 hover:border-blue-500/40 hover:bg-blue-500/[0.04]"}`}
                  >
                    {avatarPreview
                      ? <img src={avatarPreview} className="w-16 h-16 rounded-full object-cover mx-auto border-2 border-green-500/50" alt="preview" />
                      : <p className="text-sm text-[#94A3B8]">Haz clic para subir una imagen</p>
                    }
                  </div>
                  {avatarError && <p className="text-xs text-red-400 mt-1">{avatarError}</p>}
                  <input ref={avatarRef} type="file" accept="image/jpeg,image/png,image/webp" className="hidden" onChange={handleAvatar} />
                </div>

                {/* Full name */}
                <div>
                  <label className="block text-[11px] font-medium text-[#94A3B8] tracking-[0.09em] uppercase mb-1.5">Nombre completo</label>
                  <div className="relative">
                    <span className="absolute left-3.5 top-1/2 -translate-y-1/2 text-[#94A3B8]">
                      <svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M5.121 17.804A13.937 13.937 0 0112 16c2.5 0 4.847.655 6.879 1.804M15 10a3 3 0 11-6 0 3 3 0 016 0z"/>
                      </svg>
                    </span>
                    <input type="text" value={regFullname} onChange={(e) => setRegFullname(e.target.value)} placeholder="Juan Pérez" maxLength={60} className={inputCls} />
                  </div>
                </div>

                {/* Username */}
                <div>
                  <label className="block text-[11px] font-medium text-[#94A3B8] tracking-[0.09em] uppercase mb-1.5">Nombre de usuario</label>
                  <div className="relative">
                    <span className="absolute left-3.5 top-1/2 -translate-y-1/2 text-[#94A3B8]">
                      <svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/>
                      </svg>
                    </span>
                    <input
                      type="text" value={regUsername} maxLength={20} placeholder="juan.perez"
                      onChange={(e) => { setRegUsername(e.target.value); checkUsername(e.target.value); }}
                      className={inputCls}
                    />
                    <span className="absolute right-3.5 top-1/2 -translate-y-1/2 text-sm">
                      {usernameStatus === "checking" ? "⏳" : usernameStatus === "ok" ? "✅" : usernameStatus === "taken" ? "❌" : ""}
                    </span>
                  </div>
                  <p className="font-mono text-[11px] text-[#94A3B8] mt-1">3–20 caracteres. Letras, números, puntos y guiones.</p>
                </div>

                {/* Email */}
                <div>
                  <label className="block text-[11px] font-medium text-[#94A3B8] tracking-[0.09em] uppercase mb-1.5">Correo electrónico</label>
                  <div className="relative">
                    <span className="absolute left-3.5 top-1/2 -translate-y-1/2 text-[#94A3B8]">
                      <svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/>
                      </svg>
                    </span>
                    <input
                      type="email" value={regEmail} maxLength={254} placeholder="juan@empresa.com"
                      onChange={(e) => { setRegEmail(e.target.value); checkEmail(e.target.value); }}
                      className={inputCls}
                    />
                    <span className="absolute right-3.5 top-1/2 -translate-y-1/2 text-sm">
                      {emailStatus === "checking" ? "⏳" : emailStatus === "ok" ? "✅" : emailStatus === "taken" ? "❌" : ""}
                    </span>
                  </div>
                </div>

                {/* Birthdate */}
                <div>
                  <label className="block text-[11px] font-medium text-[#94A3B8] tracking-[0.09em] uppercase mb-1.5">Fecha de nacimiento</label>
                  <input
                    type="date" value={regBirthdate} max={today}
                    onChange={(e) => { setRegBirthdate(e.target.value); validateAge(e.target.value); }}
                    className="w-full bg-white/[0.04] border border-white/[0.09] rounded-[10px] px-4 py-[13px] text-sm text-[#E2E8F0] outline-none focus:border-[#3B82F6] transition-all [color-scheme:dark]"
                  />
                  {ageHint && <p className={`font-mono text-[11px] mt-1 ${ageHint.includes("mínimo") ? "text-red-400" : "text-green-400"}`}>{ageHint}</p>}
                </div>

                {/* Password */}
                <div>
                  <label className="block text-[11px] font-medium text-[#94A3B8] tracking-[0.09em] uppercase mb-1.5">Contraseña</label>
                  <div className="relative">
                    <span className="absolute left-3.5 top-1/2 -translate-y-1/2 text-[#94A3B8]">
                      <svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                      </svg>
                    </span>
                    <input type={showRegPw ? "text" : "password"} value={regPassword} onChange={(e) => setRegPassword(e.target.value)} placeholder="Mínimo 8 caracteres" className={inputCls} />
                    <button type="button" onClick={() => setShowRegPw((v) => !v)} className="absolute right-3.5 top-1/2 -translate-y-1/2 text-[#94A3B8] hover:text-[#E2E8F0] transition-colors">
                      <svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/>
                      </svg>
                    </button>
                  </div>
                  {/* Strength bar */}
                  {regPassword && (
                    <div className="mt-2">
                      <div className="flex gap-1">
                        {[1,2,3,4].map((i) => (
                          <div key={i} className="flex-1 h-[3px] rounded-full" style={{ background: i <= strength.score ? strength.color : "rgba(255,255,255,0.08)", transition: "background 0.3s" }} />
                        ))}
                      </div>
                      <p className="font-mono text-[11px] mt-1" style={{ color: strength.color }}>{strength.label}</p>
                    </div>
                  )}
                </div>

                {/* Confirm password */}
                <div>
                  <label className="block text-[11px] font-medium text-[#94A3B8] tracking-[0.09em] uppercase mb-1.5">Confirmar contraseña</label>
                  <div className="relative">
                    <span className="absolute left-3.5 top-1/2 -translate-y-1/2 text-[#94A3B8]">
                      <svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
                      </svg>
                    </span>
                    <input type={showRegCf ? "text" : "password"} value={regConfirm} onChange={(e) => setRegConfirm(e.target.value)} placeholder="Repite tu contraseña" className={inputCls} />
                    <button type="button" onClick={() => setShowRegCf((v) => !v)} className="absolute right-3.5 top-1/2 -translate-y-1/2 text-[#94A3B8] hover:text-[#E2E8F0] transition-colors">
                      <svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/>
                      </svg>
                    </button>
                  </div>
                  {regConfirm && regPassword !== regConfirm && (
                    <p className="text-xs text-red-400 mt-1">Las contraseñas no coinciden</p>
                  )}
                </div>

                <motion.button
                  type="submit"
                  disabled={regLoading}
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                  className="w-full py-3.5 rounded-[10px] font-semibold text-[15px] text-white bg-gradient-to-r from-purple-500 to-purple-700 shadow-[0_4px_20px_rgba(124,58,237,0.4)] hover:shadow-[0_6px_28px_rgba(124,58,237,0.6)] transition-shadow duration-200 disabled:opacity-55 disabled:cursor-not-allowed mt-2"
                >
                  {regLoading ? "Creando cuenta..." : "Crear cuenta"}
                </motion.button>
              </form>

              <p className="text-center mt-5 text-sm text-[#94A3B8]">
                ¿Ya tienes cuenta?{" "}
                <button onClick={() => setPanel("login")} className="text-[#3B82F6] font-medium hover:text-blue-400 transition-colors">
                  Inicia sesión
                </button>
              </p>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}
