"use client";

import { motion, type Variants } from "framer-motion";

const fadeUp: Variants = {
  hidden: { opacity: 0, y: 24 },
  show: (i: number) => ({
    opacity: 1,
    y: 0,
    transition: { duration: 0.7, delay: i * 0.12, ease: "easeOut" },
  }),
};

const stats = [
  { value: "99.9%", label: "Uptime SLA" },
  { value: "<2s", label: "Correlación de eventos" },
  { value: "10M+", label: "Eventos / día" },
  { value: "SOC2", label: "Certified" },
];

export default function Hero() {
  return (
    <section className="relative min-h-screen flex flex-col items-center justify-center overflow-hidden pt-16 pb-24 px-4 bg-grid">
      {/* Orbs */}
      <div className="pointer-events-none absolute inset-0 overflow-hidden">
        <motion.div
          animate={{ y: [0, -40, 20, 0], scale: [1, 1.04, 0.97, 1] }}
          transition={{ duration: 14, repeat: Infinity, ease: "easeInOut" }}
          className="absolute -top-52 -left-52 w-[700px] h-[700px] rounded-full"
          style={{ background: "radial-gradient(circle, rgba(59,130,246,0.18) 0%, transparent 70%)", filter: "blur(80px)" }}
        />
        <motion.div
          animate={{ y: [0, 30, -20, 0], scale: [1, 0.97, 1.04, 1] }}
          transition={{ duration: 18, repeat: Infinity, ease: "easeInOut", delay: 2 }}
          className="absolute -bottom-40 -right-28 w-[600px] h-[600px] rounded-full"
          style={{ background: "radial-gradient(circle, rgba(124,58,237,0.14) 0%, transparent 70%)", filter: "blur(80px)" }}
        />
        <motion.div
          animate={{ y: [0, -20, 30, 0] }}
          transition={{ duration: 22, repeat: Infinity, ease: "easeInOut", delay: 4 }}
          className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[400px] h-[400px] rounded-full"
          style={{ background: "radial-gradient(circle, rgba(16,185,129,0.08) 0%, transparent 70%)", filter: "blur(80px)" }}
        />
      </div>

      <div className="relative z-10 max-w-4xl mx-auto text-center">
        {/* Badge */}
        <motion.div
          custom={0}
          variants={fadeUp}
          initial="hidden"
          animate="show"
          className="inline-flex items-center gap-2 bg-white/[0.04] border border-white/[0.08] rounded-full px-4 py-1.5 mb-8"
        >
          <span className="w-2 h-2 rounded-full bg-[#22C55E] shadow-[0_0_8px_#22C55E]" />
          <span className="font-mono text-xs text-[#94A3B8] tracking-widest uppercase">
            Plataforma SIEM de nivel enterprise
          </span>
        </motion.div>

        {/* Headline */}
        <motion.h1
          custom={1}
          variants={fadeUp}
          initial="hidden"
          animate="show"
          className="text-4xl sm:text-5xl lg:text-6xl font-bold text-[#E2E8F0] leading-[1.12] tracking-tight mb-6"
        >
          Seguridad total.{" "}
          <span className="bg-gradient-to-r from-blue-400 via-blue-500 to-purple-500 bg-clip-text text-transparent">
            Visibilidad completa.
          </span>
          <br />
          Control absoluto.
        </motion.h1>

        {/* Sub */}
        <motion.p
          custom={2}
          variants={fadeUp}
          initial="hidden"
          animate="show"
          className="text-base sm:text-lg text-[#94A3B8] max-w-2xl mx-auto mb-10 leading-relaxed"
        >
          SIEM NEXUS correlaciona millones de eventos en tiempo real, detecta amenazas
          con IA y centraliza la gestión de incidentes — con arquitectura dual-motor
          MySQL + PostgreSQL y auditoría SHA-256.
        </motion.p>

        {/* CTAs */}
        <motion.div
          custom={3}
          variants={fadeUp}
          initial="hidden"
          animate="show"
          className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-16"
        >
          <motion.a
            href="/login"
            whileHover={{ scale: 1.04, boxShadow: "0 0 40px rgba(59,130,246,0.6)" }}
            whileTap={{ scale: 0.97 }}
            className="inline-flex items-center gap-2 bg-gradient-to-r from-blue-500 to-blue-700 text-white font-semibold px-7 py-3.5 rounded-xl shadow-[0_4px_24px_rgba(59,130,246,0.4)] transition-all duration-300 text-sm"
          >
            Solicitar demo gratuita
            <svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6" />
            </svg>
          </motion.a>
          <motion.a
            href="#features"
            whileHover={{ scale: 1.03 }}
            whileTap={{ scale: 0.97 }}
            className="inline-flex items-center gap-2 bg-white/[0.04] border border-white/[0.09] text-[#E2E8F0] font-medium px-7 py-3.5 rounded-xl hover:bg-white/[0.08] transition-all duration-300 text-sm"
          >
            Ver características
          </motion.a>
        </motion.div>

        {/* Stats bar */}
        <motion.div
          custom={4}
          variants={fadeUp}
          initial="hidden"
          animate="show"
          className="grid grid-cols-2 sm:grid-cols-4 gap-px bg-white/[0.06] rounded-2xl overflow-hidden border border-white/[0.06]"
        >
          {stats.map((s) => (
            <div
              key={s.label}
              className="bg-[#0F172A]/80 backdrop-blur-sm py-5 px-4 text-center"
            >
              <div className="font-mono text-xl font-semibold text-[#3B82F6]">{s.value}</div>
              <div className="text-xs text-[#94A3B8] mt-1">{s.label}</div>
            </div>
          ))}
        </motion.div>
      </div>

      {/* Scroll indicator */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 1.5 }}
        className="absolute bottom-8 left-1/2 -translate-x-1/2"
      >
        <motion.div
          animate={{ y: [0, 8, 0] }}
          transition={{ duration: 1.5, repeat: Infinity }}
          className="w-5 h-8 border border-white/20 rounded-full flex items-start justify-center pt-1.5"
        >
          <div className="w-1 h-2 bg-[#3B82F6] rounded-full" />
        </motion.div>
      </motion.div>
    </section>
  );
}
