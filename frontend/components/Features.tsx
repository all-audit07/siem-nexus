"use client";

import { useRef } from "react";
import { motion, useInView } from "framer-motion";

const features = [
  {
    icon: (
      <svg width="24" height="24" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.955 11.955 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
      </svg>
    ),
    color: "blue",
    title: "Control de acceso RBAC",
    description:
      "Roles diferenciados con permisos granulares: Admin, Analyst, Auditor y Viewer. Gestión centralizada de identidades con soporte MFA.",
    bullets: ["Roles con permisos granulares", "SSO + MFA integrado", "Audit log por usuario"],
    badge: "Seguridad",
  },
  {
    icon: (
      <svg width="24" height="24" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 3v11.25A2.25 2.25 0 006 16.5h2.25M3.75 3h-1.5m1.5 0h16.5m0 0h1.5m-1.5 0v11.25A2.25 2.25 0 0118 16.5h-2.25m-7.5 0h7.5m-7.5 0l-1 3m8.5-3l1 3m0 0l.5 1.5m-.5-1.5h-9.5m0 0l-.5 1.5M9 11.25v1.5M12 9v3.75m3-6v6" />
      </svg>
    ),
    color: "purple",
    title: "Correlación en tiempo real",
    description:
      "Motor PostgreSQL con reglas de correlación avanzadas. Detecta patrones de ataque en millones de eventos por día con latencia menor a 2 segundos.",
    bullets: ["Reglas MITRE ATT&CK", "Machine Learning integrado", "Alertas configurables"],
    badge: "Detección",
  },
  {
    icon: (
      <svg width="24" height="24" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z" />
      </svg>
    ),
    color: "green",
    title: "Auditoría criptográfica",
    description:
      "Logs inmutables con hash SHA-256 generados por pgcrypto en tiempo real. Cumple con ISO 27001, SOC 2 Type II y regulaciones GDPR.",
    bullets: ["Hash SHA-256 por evento", "Cadena de custodia digital", "Exportación forense"],
    badge: "Cumplimiento",
  },
];

const colorMap: Record<string, { glow: string; border: string; badge: string; icon: string }> = {
  blue: {
    glow: "rgba(59,130,246,0.12)",
    border: "rgba(59,130,246,0.2)",
    badge: "bg-blue-500/10 text-blue-400 border-blue-500/20",
    icon: "text-blue-400",
  },
  purple: {
    glow: "rgba(124,58,237,0.12)",
    border: "rgba(124,58,237,0.2)",
    badge: "bg-purple-500/10 text-purple-400 border-purple-500/20",
    icon: "text-purple-400",
  },
  green: {
    glow: "rgba(34,197,94,0.12)",
    border: "rgba(34,197,94,0.2)",
    badge: "bg-green-500/10 text-green-400 border-green-500/20",
    icon: "text-green-400",
  },
};

export default function Features() {
  const ref = useRef(null);
  const inView = useInView(ref, { once: true, margin: "-80px" });

  return (
    <section id="features" className="relative py-24 px-4 overflow-hidden">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <motion.div
          ref={ref}
          initial={{ opacity: 0, y: 32 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
          className="text-center mb-16"
        >
          <div className="inline-flex items-center gap-2 bg-white/[0.04] border border-white/[0.08] rounded-full px-4 py-1.5 mb-5">
            <span className="font-mono text-xs text-[#94A3B8] tracking-widest uppercase">
              Capacidades core
            </span>
          </div>
          <h2 className="text-3xl sm:text-4xl font-bold text-[#E2E8F0] tracking-tight mb-4">
            Todo lo que necesita tu{" "}
            <span className="bg-gradient-to-r from-blue-400 to-purple-400 bg-clip-text text-transparent">
              equipo SOC
            </span>
          </h2>
          <p className="text-[#94A3B8] max-w-xl mx-auto text-base leading-relaxed">
            Arquitectura dual-motor diseñada para escalar desde startups hasta
            infraestructuras enterprise con miles de endpoints.
          </p>
        </motion.div>

        {/* Cards */}
        <div className="grid md:grid-cols-3 gap-6">
          {features.map((feat, i) => {
            const c = colorMap[feat.color];
            return (
              <motion.div
                key={feat.title}
                initial={{ opacity: 0, y: 40 }}
                animate={inView ? { opacity: 1, y: 0 } : {}}
                transition={{ duration: 0.7, delay: i * 0.1 + 0.2, ease: [0.22, 1, 0.36, 1] }}
                whileHover={{ y: -6, transition: { duration: 0.25 } }}
                className="group relative bg-[#0F172A] border border-white/[0.07] rounded-2xl p-7 overflow-hidden cursor-default"
                style={{
                  boxShadow: `0 0 0 1px ${c.border}`,
                }}
              >
                {/* Hover glow */}
                <div
                  className="pointer-events-none absolute inset-0 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-500"
                  style={{ background: `radial-gradient(ellipse at top left, ${c.glow}, transparent 70%)` }}
                />

                {/* Badge */}
                <span className={`inline-flex items-center text-[10px] font-mono font-medium tracking-widest uppercase border rounded-full px-2.5 py-0.5 mb-6 ${c.badge}`}>
                  {feat.badge}
                </span>

                {/* Icon */}
                <div className={`mb-5 ${c.icon}`}>{feat.icon}</div>

                <h3 className="text-[#E2E8F0] font-semibold text-lg mb-3">{feat.title}</h3>
                <p className="text-[#94A3B8] text-sm leading-relaxed mb-6">{feat.description}</p>

                {/* Bullets */}
                <ul className="space-y-2">
                  {feat.bullets.map((b) => (
                    <li key={b} className="flex items-center gap-2.5 text-sm text-[#94A3B8]">
                      <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5} className={c.icon}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                      </svg>
                      {b}
                    </li>
                  ))}
                </ul>
              </motion.div>
            );
          })}
        </div>

        {/* Bottom architecture badge */}
        <motion.div
          initial={{ opacity: 0, y: 24 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.7, delay: 0.6 }}
          className="mt-12 flex flex-col sm:flex-row items-center justify-center gap-4 text-sm text-[#94A3B8]"
        >
          <span className="flex items-center gap-2 bg-white/[0.03] border border-white/[0.07] rounded-lg px-4 py-2 font-mono text-xs">
            <span className="w-2 h-2 rounded-full bg-[#F59E0B] shadow-[0_0_6px_#F59E0B]" />
            MySQL — Autenticación & gestión
          </span>
          <span className="hidden sm:block text-[#334155]">+</span>
          <span className="flex items-center gap-2 bg-white/[0.03] border border-white/[0.07] rounded-lg px-4 py-2 font-mono text-xs">
            <span className="w-2 h-2 rounded-full bg-[#3B82F6] shadow-[0_0_6px_#3B82F6]" />
            PostgreSQL — Correlación & eventos
          </span>
        </motion.div>
      </div>
    </section>
  );
}
