"use client";

import { useRef, useState } from "react";
import { motion, AnimatePresence, useInView } from "framer-motion";

const faqs = [
  {
    q: "¿Cuánto tiempo toma implementar SIEM NEXUS?",
    a: "La mayoría de los equipos están operativos en menos de 48 horas. Nuestro onboarding guiado cubre la configuración de fuentes de datos, reglas de correlación y dashboards sin necesidad de conocimientos especializados en SIEM.",
  },
  {
    q: "¿Puedo migrar desde otro SIEM?",
    a: "Sí. Ofrecemos migración asistida desde Splunk, IBM QRadar, Microsoft Sentinel y otras plataformas. Nuestro equipo de ingeniería revisa tus reglas y las adapta al motor de correlación de NEXUS sin pérdida de cobertura.",
  },
  {
    q: "¿Cómo funciona la arquitectura dual-motor?",
    a: "MySQL gestiona autenticación, usuarios y configuración del sistema con alta disponibilidad. PostgreSQL con pgcrypto se encarga de la ingestión, correlación y almacenamiento inmutable de eventos de seguridad. Ambos motores operan de forma independiente para maximizar resiliencia.",
  },
  {
    q: "¿Qué normativas cumple SIEM NEXUS?",
    a: "Cumplimos con ISO 27001, SOC 2 Type II, PCI-DSS, HIPAA y GDPR. Los audit logs con hash SHA-256 proveen cadena de custodia digital aceptada en procesos de auditoría forense y revisiones regulatorias.",
  },
  {
    q: "¿Ofrecen deployment on-premise?",
    a: "Sí, en el plan Enterprise. Disponemos de imágenes Docker oficiales, charts de Helm para Kubernetes y playbooks de Ansible. También ofrecemos instalación en air-gap para entornos con restricciones de conectividad.",
  },
  {
    q: "¿Qué sucede si superamos el límite de eventos?",
    a: "Te notificamos al 80% del límite y aplicamos throttling inteligente que prioriza eventos críticos. Nunca se descartan alertas de severidad alta. Puedes escalar tu plan en cualquier momento sin downtime.",
  },
];

function FAQItem({ q, a, index, inView }: { q: string; a: string; index: number; inView: boolean }) {
  const [open, setOpen] = useState(false);

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={inView ? { opacity: 1, y: 0 } : {}}
      transition={{ duration: 0.5, delay: index * 0.07 + 0.2 }}
      className="border border-white/[0.07] rounded-xl overflow-hidden"
    >
      <button
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center justify-between gap-4 px-6 py-5 text-left bg-[#0F172A]/60 hover:bg-[#0F172A]/90 transition-colors duration-200"
      >
        <span className="text-sm font-medium text-[#E2E8F0]">{q}</span>
        <motion.span
          animate={{ rotate: open ? 45 : 0 }}
          transition={{ duration: 0.2 }}
          className="flex-shrink-0 text-[#94A3B8]"
        >
          <svg width="18" height="18" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
          </svg>
        </motion.span>
      </button>

      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.28, ease: [0.22, 1, 0.36, 1] }}
            className="overflow-hidden"
          >
            <p className="px-6 pb-5 text-sm text-[#94A3B8] leading-relaxed border-t border-white/[0.05] pt-4">
              {a}
            </p>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

export default function FAQ() {
  const ref = useRef(null);
  const inView = useInView(ref, { once: true, margin: "-80px" });

  return (
    <section id="faq" className="relative py-24 px-4 bg-[#0F172A]/30">
      <div className="max-w-3xl mx-auto">
        <motion.div
          ref={ref}
          initial={{ opacity: 0, y: 24 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.6 }}
          className="text-center mb-12"
        >
          <div className="inline-flex items-center gap-2 bg-white/[0.04] border border-white/[0.08] rounded-full px-4 py-1.5 mb-5">
            <span className="font-mono text-xs text-[#94A3B8] tracking-widest uppercase">FAQ</span>
          </div>
          <h2 className="text-3xl sm:text-4xl font-bold text-[#E2E8F0] tracking-tight mb-3">
            Preguntas frecuentes
          </h2>
          <p className="text-[#94A3B8] text-sm">
            ¿No encuentras tu respuesta?{" "}
            <a href="mailto:support@siemnexus.io" className="text-[#3B82F6] hover:underline">
              Escríbenos
            </a>
            .
          </p>
        </motion.div>

        <div className="flex flex-col gap-3">
          {faqs.map((item, i) => (
            <FAQItem key={item.q} q={item.q} a={item.a} index={i} inView={inView} />
          ))}
        </div>
      </div>
    </section>
  );
}
