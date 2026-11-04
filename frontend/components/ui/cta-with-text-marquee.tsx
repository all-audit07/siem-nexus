"use client";

import { cn } from "@/lib/utils";
import { ReactNode, useEffect, useRef } from "react";
import { motion } from "framer-motion";

interface HorizontalMarqueeProps {
  children: ReactNode;
  reverse?: boolean;
  pauseOnHover?: boolean;
  speed?: number;
  className?: string;
}

function HorizontalMarquee({
  children,
  reverse = false,
  pauseOnHover = false,
  speed = 30,
  className,
}: HorizontalMarqueeProps) {
  return (
    <div
      className={cn("group flex overflow-hidden", className)}
      style={{ "--duration": `${speed}s` } as React.CSSProperties}
    >
      <div
        className={cn(
          "flex shrink-0 animate-marquee",
          reverse && "[animation-direction:reverse]",
          pauseOnHover && "group-hover:[animation-play-state:paused]"
        )}
      >
        {children}
      </div>
      <div
        className={cn(
          "flex shrink-0 animate-marquee",
          reverse && "[animation-direction:reverse]",
          pauseOnHover && "group-hover:[animation-play-state:paused]"
        )}
        aria-hidden="true"
      >
        {children}
      </div>
    </div>
  );
}

const marqueeItems = [
  "SOC Analysts",
  "Security Engineers",
  "CISO & Security Leaders",
  "Incident Responders",
  "Compliance Teams",
  "Threat Hunters",
  "DevSecOps Teams",
];

export default function CTAWithTextMarquee() {
  const marqueeRef = useRef<HTMLDivElement>(null);

  // Fade opacity based on distance from center X
  useEffect(() => {
    const container = marqueeRef.current;
    if (!container) return;

    let frame: number;
    const update = () => {
      const items = container.querySelectorAll<HTMLElement>(".marquee-item-h");
      const rect  = container.getBoundingClientRect();
      const cx    = rect.left + rect.width / 2;

      items.forEach((item) => {
        const ir    = item.getBoundingClientRect();
        const itemCx = ir.left + ir.width / 2;
        const dist   = Math.abs(cx - itemCx);
        const max    = rect.width / 2;
        const op     = 1 - Math.min(dist / max, 1) * 0.78;
        item.style.opacity = String(op);
      });

      frame = requestAnimationFrame(update);
    };

    frame = requestAnimationFrame(update);
    return () => cancelAnimationFrame(frame);
  }, []);

  return (
    <section className="relative bg-[#020817] overflow-hidden border-t border-white/[0.06]">
      {/* Subtle glow */}
      <div
        className="pointer-events-none absolute inset-0"
        style={{ background: "radial-gradient(ellipse at 50% 0%, rgba(59,130,246,0.09) 0%, transparent 65%)" }}
      />

      <div className="relative z-10 max-w-3xl mx-auto px-6 pt-16 pb-10 text-center">
        {/* Badge */}
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.5 }}
          className="inline-flex items-center gap-2 bg-white/[0.04] border border-white/[0.08] rounded-full px-4 py-1.5 mb-6"
        >
          <span className="w-2 h-2 rounded-full bg-[#22C55E] shadow-[0_0_8px_#22C55E]" />
          <span className="font-mono text-xs text-[#94A3B8] tracking-widest uppercase">
            Listo para empezar
          </span>
        </motion.div>

        {/* Headline */}
        <motion.h2
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6, delay: 0.08 }}
          className="text-3xl sm:text-4xl md:text-5xl font-bold leading-tight tracking-tight text-[#E2E8F0] mb-4"
        >
          Protege tu infraestructura{" "}
          <span className="bg-gradient-to-r from-blue-400 to-purple-400 bg-clip-text text-transparent">
            desde hoy
          </span>
        </motion.h2>

        {/* Subtext */}
        <motion.p
          initial={{ opacity: 0, y: 16 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6, delay: 0.15 }}
          className="text-[#94A3B8] text-base leading-relaxed mb-8 max-w-xl mx-auto"
        >
          14 días gratis, sin tarjeta de crédito. Onboarding guiado para tu equipo desde el día uno.
        </motion.p>

        {/* CTAs */}
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.5, delay: 0.22 }}
          className="flex flex-wrap items-center justify-center gap-4 mb-4"
        >
          <a
            href="/login"
            className="group relative px-7 py-3 bg-gradient-to-r from-blue-500 to-blue-700 text-white rounded-lg font-semibold text-sm overflow-hidden transition-all duration-300 hover:scale-105 hover:shadow-[0_0_32px_rgba(59,130,246,0.5)]"
          >
            <span className="relative z-10">COMENZAR GRATIS</span>
            <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent -translate-x-full group-hover:translate-x-full transition-transform duration-700" />
          </a>
          <a
            href="#pricing"
            className="group relative px-7 py-3 bg-white/[0.05] text-[#E2E8F0] rounded-lg font-medium text-sm border border-white/[0.09] overflow-hidden transition-all duration-300 hover:scale-105 hover:bg-white/[0.09]"
          >
            <span className="relative z-10">VER TODOS LOS PLANES</span>
            <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/10 to-transparent -translate-x-full group-hover:translate-x-full transition-transform duration-700" />
          </a>
        </motion.div>

        {/* Trust signals */}
        <motion.div
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.5, delay: 0.3 }}
          className="flex flex-wrap items-center justify-center gap-5"
        >
          {["Sin tarjeta de crédito", "Setup en 48 horas", "Cancela cuando quieras"].map((t) => (
            <span key={t} className="flex items-center gap-1.5 text-xs text-[#94A3B8]">
              <span className="text-[#22C55E] font-bold">✓</span>
              {t}
            </span>
          ))}
        </motion.div>
      </div>

      {/* ── Horizontal marquee ──────────────────────────── */}
      <motion.div
        initial={{ opacity: 0 }}
        whileInView={{ opacity: 1 }}
        viewport={{ once: true }}
        transition={{ duration: 0.7, delay: 0.35 }}
        ref={marqueeRef}
        className="relative w-full pb-14"
      >
        <HorizontalMarquee speed={28} reverse>
          {marqueeItems.map((item, i) => (
            <div
              key={i}
              className="marquee-item-h text-4xl sm:text-5xl md:text-6xl font-light tracking-tight px-10 text-[#E2E8F0] whitespace-nowrap select-none"
            >
              {item}
              {/* Separator dot */}
              <span className="text-[#334155] mx-6 text-2xl align-middle">·</span>
            </div>
          ))}
        </HorizontalMarquee>

        {/* Left vignette */}
        <div className="pointer-events-none absolute top-0 left-0 bottom-0 w-40 bg-gradient-to-r from-[#020817] to-transparent z-10" />
        {/* Right vignette */}
        <div className="pointer-events-none absolute top-0 right-0 bottom-0 w-40 bg-gradient-to-l from-[#020817] to-transparent z-10" />
      </motion.div>
    </section>
  );
}
