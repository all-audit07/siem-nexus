"use client";

import { useRef } from "react";
import { motion, useInView } from "framer-motion";

const testimonials = [
  {
    quote:
      "SIEM NEXUS redujo nuestro tiempo de respuesta a incidentes en un 70%. La correlación en tiempo real y los dashboards nos dieron visibilidad total del entorno en horas.",
    name: "María Torres",
    role: "CISO · Fintech Latam",
    avatar: "MT",
    avatarColor: "from-blue-500 to-blue-700",
  },
  {
    quote:
      "Implementamos SIEM NEXUS en 48 horas. La arquitectura dual-motor y el control RBAC nos permitieron cumplir con ISO 27001 sin fricciones operativas.",
    name: "Carlos Reyes",
    role: "Head of Security · SaaS Corp",
    avatar: "CR",
    avatarColor: "from-purple-500 to-purple-700",
  },
  {
    quote:
      "Los audit logs con hash SHA-256 fueron clave para nuestra auditoría SOC 2. El equipo de soporte respondió en minutos durante el proceso.",
    name: "Ana Villanueva",
    role: "Security Lead · E-commerce Group",
    avatar: "AV",
    avatarColor: "from-green-500 to-green-700",
  },
];

const logos = [
  { name: "FinSecure", abbr: "FS" },
  { name: "CloudGuard", abbr: "CG" },
  { name: "DataVault", abbr: "DV" },
  { name: "NetShield", abbr: "NS" },
  { name: "TrustOps", abbr: "TO" },
];

export default function SocialProof() {
  const ref = useRef(null);
  const inView = useInView(ref, { once: true, margin: "-80px" });

  return (
    <section id="social" className="relative py-24 px-4 bg-[#0F172A]/40">
      <div className="max-w-7xl mx-auto">
        {/* Trusted by logos */}
        <motion.div
          ref={ref}
          initial={{ opacity: 0, y: 24 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.6 }}
          className="text-center mb-16"
        >
          <p className="font-mono text-xs text-[#94A3B8] tracking-widest uppercase mb-8">
            Confiado por equipos de seguridad en toda LATAM
          </p>
          <div className="flex flex-wrap items-center justify-center gap-8">
            {logos.map((logo, i) => (
              <motion.div
                key={logo.name}
                initial={{ opacity: 0 }}
                animate={inView ? { opacity: 1 } : {}}
                transition={{ delay: i * 0.08 }}
                whileHover={{ scale: 1.05 }}
                className="flex items-center gap-2.5 text-[#334155] hover:text-[#94A3B8] transition-colors cursor-default"
              >
                <div className="w-8 h-8 rounded-lg bg-white/[0.04] border border-white/[0.07] flex items-center justify-center font-mono text-xs font-bold text-[#94A3B8]">
                  {logo.abbr}
                </div>
                <span className="font-semibold text-sm tracking-wide">{logo.name}</span>
              </motion.div>
            ))}
          </div>
        </motion.div>

        {/* Section header */}
        <motion.div
          initial={{ opacity: 0, y: 24 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.6, delay: 0.2 }}
          className="text-center mb-12"
        >
          <h2 className="text-3xl sm:text-4xl font-bold text-[#E2E8F0] tracking-tight mb-3">
            Lo que dicen nuestros{" "}
            <span className="bg-gradient-to-r from-blue-400 to-purple-400 bg-clip-text text-transparent">
              clientes
            </span>
          </h2>
          <p className="text-[#94A3B8] text-sm">
            Equipos SOC que confían en SIEM NEXUS para proteger su infraestructura.
          </p>
        </motion.div>

        {/* Testimonial cards */}
        <div className="grid md:grid-cols-3 gap-6">
          {testimonials.map((t, i) => (
            <motion.div
              key={t.name}
              initial={{ opacity: 0, y: 40 }}
              animate={inView ? { opacity: 1, y: 0 } : {}}
              transition={{ duration: 0.65, delay: i * 0.1 + 0.3 }}
              whileHover={{ y: -4, transition: { duration: 0.2 } }}
              className="bg-[#1E293B]/60 border border-white/[0.07] rounded-2xl p-6 flex flex-col gap-5"
            >
              {/* Stars */}
              <div className="flex gap-1">
                {Array.from({ length: 5 }).map((_, j) => (
                  <svg key={j} width="14" height="14" viewBox="0 0 24 24" fill="#F59E0B">
                    <path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z" />
                  </svg>
                ))}
              </div>

              {/* Quote */}
              <p className="text-[#94A3B8] text-sm leading-relaxed flex-1">"{t.quote}"</p>

              {/* Author */}
              <div className="flex items-center gap-3">
                <div className={`w-10 h-10 rounded-full bg-gradient-to-br ${t.avatarColor} flex items-center justify-center font-mono text-xs font-bold text-white flex-shrink-0`}>
                  {t.avatar}
                </div>
                <div>
                  <div className="text-sm font-semibold text-[#E2E8F0]">{t.name}</div>
                  <div className="text-xs text-[#94A3B8]">{t.role}</div>
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
