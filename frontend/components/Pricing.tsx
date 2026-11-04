"use client";

import { useRef, useState } from "react";
import { motion, useInView } from "framer-motion";

const plans = [
  {
    name: "Starter",
    price: { monthly: 299, annual: 239 },
    description: "Para equipos pequeños que inician su programa de seguridad.",
    highlight: false,
    color: "blue",
    features: [
      "Hasta 5 usuarios",
      "500K eventos / día",
      "Retención 30 días",
      "Reglas MITRE básicas",
      "Alertas por email",
      "Soporte 8×5",
    ],
    cta: "Empezar gratis",
  },
  {
    name: "Professional",
    price: { monthly: 799, annual: 639 },
    description: "El plan más popular para SOC en crecimiento.",
    highlight: true,
    color: "purple",
    features: [
      "Hasta 25 usuarios",
      "5M eventos / día",
      "Retención 90 días",
      "ML + correlación avanzada",
      "Slack / PagerDuty / JIRA",
      "SLA 99.9% garantizado",
      "Soporte 24×7",
    ],
    cta: "Solicitar demo",
    badge: "Más popular",
  },
  {
    name: "Enterprise",
    price: { monthly: null, annual: null },
    description: "Infraestructura dedicada, SLA personalizado y onboarding.",
    highlight: false,
    color: "green",
    features: [
      "Usuarios ilimitados",
      "Eventos ilimitados",
      "Retención personalizada",
      "Deployment on-premise",
      "Integraciones custom",
      "SSO + MFA enterprise",
      "SLA 99.99% + TAM dedicado",
    ],
    cta: "Contactar ventas",
  },
];

const colorAccent: Record<string, string> = {
  blue: "border-blue-500/30 hover:border-blue-500/50",
  purple: "border-purple-500/40",
  green: "border-green-500/30 hover:border-green-500/50",
};

export default function Pricing() {
  const ref = useRef(null);
  const inView = useInView(ref, { once: true, margin: "-80px" });
  const [annual, setAnnual] = useState(true);

  return (
    <section id="pricing" className="relative py-24 px-4">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <motion.div
          ref={ref}
          initial={{ opacity: 0, y: 32 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.7 }}
          className="text-center mb-12"
        >
          <div className="inline-flex items-center gap-2 bg-white/[0.04] border border-white/[0.08] rounded-full px-4 py-1.5 mb-5">
            <span className="font-mono text-xs text-[#94A3B8] tracking-widest uppercase">Precios</span>
          </div>
          <h2 className="text-3xl sm:text-4xl font-bold text-[#E2E8F0] tracking-tight mb-4">
            Simple, transparente,{" "}
            <span className="bg-gradient-to-r from-blue-400 to-purple-400 bg-clip-text text-transparent">
              sin sorpresas
            </span>
          </h2>
          <p className="text-[#94A3B8] mb-8 text-sm max-w-md mx-auto">
            Comienza gratis 14 días. Sin tarjeta de crédito.
          </p>

          {/* Toggle */}
          <div className="inline-flex items-center gap-3 bg-[#0F172A] border border-white/[0.07] rounded-xl p-1">
            <button
              onClick={() => setAnnual(false)}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${
                !annual ? "bg-white/[0.09] text-[#E2E8F0]" : "text-[#94A3B8]"
              }`}
            >
              Mensual
            </button>
            <button
              onClick={() => setAnnual(true)}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200 flex items-center gap-2 ${
                annual ? "bg-white/[0.09] text-[#E2E8F0]" : "text-[#94A3B8]"
              }`}
            >
              Anual
              <span className="text-[10px] font-mono bg-green-500/15 text-green-400 border border-green-500/20 px-1.5 py-0.5 rounded-md">
                −20%
              </span>
            </button>
          </div>
        </motion.div>

        {/* Cards */}
        <div className="grid md:grid-cols-3 gap-6">
          {plans.map((plan, i) => (
            <motion.div
              key={plan.name}
              initial={{ opacity: 0, y: 40 }}
              animate={inView ? { opacity: 1, y: 0 } : {}}
              transition={{ duration: 0.65, delay: i * 0.1 + 0.2 }}
              whileHover={{ y: plan.highlight ? -6 : -4, transition: { duration: 0.2 } }}
              className={`relative rounded-2xl border p-7 flex flex-col ${
                plan.highlight
                  ? "bg-gradient-to-b from-purple-900/30 to-[#0F172A] border-purple-500/40 shadow-[0_0_48px_rgba(124,58,237,0.18)]"
                  : `bg-[#0F172A] ${colorAccent[plan.color]} transition-colors duration-300`
              }`}
            >
              {plan.badge && (
                <div className="absolute -top-3.5 left-1/2 -translate-x-1/2">
                  <span className="bg-gradient-to-r from-purple-500 to-purple-700 text-white text-[11px] font-mono font-semibold px-3 py-1 rounded-full shadow-[0_0_20px_rgba(124,58,237,0.5)]">
                    {plan.badge}
                  </span>
                </div>
              )}

              <div className="mb-6">
                <h3 className="font-mono text-sm font-semibold tracking-widest uppercase text-[#94A3B8] mb-1">
                  {plan.name}
                </h3>
                <div className="flex items-end gap-1 mt-3 mb-2">
                  {plan.price.monthly !== null ? (
                    <>
                      <span className="text-4xl font-bold text-[#E2E8F0]">
                        ${annual ? plan.price.annual : plan.price.monthly}
                      </span>
                      <span className="text-[#94A3B8] text-sm mb-1">/mes</span>
                    </>
                  ) : (
                    <span className="text-3xl font-bold text-[#E2E8F0]">Custom</span>
                  )}
                </div>
                {annual && plan.price.monthly !== null && (
                  <p className="text-xs text-[#94A3B8]">
                    Facturado anualmente — ${(plan.price.annual! * 12).toLocaleString("en-US")}/año
                  </p>
                )}
                <p className="text-sm text-[#94A3B8] mt-3 leading-relaxed">{plan.description}</p>
              </div>

              <ul className="space-y-3 flex-1 mb-8">
                {plan.features.map((f) => (
                  <li key={f} className="flex items-center gap-2.5 text-sm text-[#94A3B8]">
                    <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke={plan.highlight ? "#A78BFA" : "#3B82F6"} strokeWidth={2.5}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                    </svg>
                    {f}
                  </li>
                ))}
              </ul>

              <motion.a
                href="/login"
                whileHover={{ scale: 1.03 }}
                whileTap={{ scale: 0.97 }}
                className={`text-center text-sm font-semibold py-3 rounded-xl transition-all duration-300 ${
                  plan.highlight
                    ? "bg-gradient-to-r from-purple-500 to-purple-700 text-white shadow-[0_4px_20px_rgba(124,58,237,0.4)] hover:shadow-[0_4px_32px_rgba(124,58,237,0.6)]"
                    : "bg-white/[0.06] border border-white/[0.09] text-[#E2E8F0] hover:bg-white/[0.10]"
                }`}
              >
                {plan.cta}
              </motion.a>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
