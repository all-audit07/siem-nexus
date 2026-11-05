"use client";

// components/siem/AppShell.tsx
// Estructura común de las páginas internas: barra lateral, barra superior y
// control de sesión. Mantiene el mismo estilo visual del dashboard.

import { ReactNode, useEffect, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { SiemUser, clearSession, getToken, getUser } from "@/lib/siem";

type NavItem = { label: string; href?: string; icon: ReactNode };

const I = (d: string) => (
  <svg width="15" height="15" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} aria-hidden>
    <path strokeLinecap="round" strokeLinejoin="round" d={d} />
  </svg>
);

// Las entradas sin href aún no tienen página; se muestran deshabilitadas.
const NAV: { section: string; items: NavItem[] }[] = [
  {
    section: "Principal",
    items: [
      { label: "Dashboard", href: "/dashboard", icon: I("M4 5a1 1 0 011-1h5v7H4V5zm10-1h5a1 1 0 011 1v4h-6V4zM4 13h6v7H5a1 1 0 01-1-1v-6zm10-2h6v8a1 1 0 01-1 1h-5v-9z") },
      { label: "Importar logs", href: "/imports", icon: I("M4 16v2a2 2 0 002 2h12a2 2 0 002-2v-2M12 4v12m0-12l-4 4m4-4l4 4") },
    ],
  },
  {
    section: "Análisis",
    items: [
      { label: "Incidentes", href: "/incidents", icon: I("M12 9v4l3 3M21 12a9 9 0 11-18 0 9 9 0 0118 0z") },
      { label: "Alertas", href: "/alerts", icon: I("M15 17h5l-1.4-1.4A2 2 0 0118 14.2V11a6 6 0 00-4-5.7V5a2 2 0 10-4 0v.3C7.7 6.2 6 8.4 6 11v3.2c0 .5-.2 1-.6 1.4L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9") },
      { label: "Eventos", href: "/events", icon: I("M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.6a1 1 0 01.7.3l5.4 5.4a1 1 0 01.3.7V19a2 2 0 01-2 2z") },
      { label: "Informes", href: "/reports", icon: I("M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.6a1 1 0 01.7.3l5.4 5.4a1 1 0 01.3.7V19a2 2 0 01-2 2z") },
      { label: "Auditoría", href: "/audit", icon: I("M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z") },
    ],
  },
];

interface Props {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
  children: (user: SiemUser | null) => ReactNode;
}

export default function AppShell({ title, subtitle, actions, children }: Props) {
  const router = useRouter();
  const pathname = usePathname();
  const [user, setUser] = useState<SiemUser | null>(null);
  const [ready, setReady] = useState(false);
  const [clock, setClock] = useState("--:--:--");

  useEffect(() => {
    if (!getToken()) { router.replace("/login"); return; }
    setUser(getUser());
    setReady(true);
  }, [router]);

  useEffect(() => {
    const fmt = new Intl.DateTimeFormat("es-PA", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
    const tick = () => setClock(fmt.format(new Date()));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  const logout = () => { clearSession(); router.replace("/login"); };
  const avatar = (user?.name || user?.username || "U")[0].toUpperCase();
  const [avatarError, setAvatarError] = useState(false);
  // avatar_path llega como "uploads/avatars/archivo.jpg" y se sirve en /api/uploads/avatars/
  const avatarUrl = user?.avatar && /^uploads\/avatars\/[\w.-]+$/.test(user.avatar) ? `/api/${user.avatar}` : null;

  if (!ready) {
    return (
      <div className="fixed inset-0 bg-[#020817] flex items-center justify-center">
        <div className="w-9 h-9 border-2 border-white/[0.06] border-t-blue-500 rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <>
      <div className="orb-1" /><div className="orb-2" /><div className="orb-3" />
      <div className="fixed inset-0 bg-grid opacity-40 pointer-events-none z-0" />

      <div className="flex min-h-screen bg-[#020817] text-[#E2E8F0]">
        {/* ── Barra lateral ── */}
        <aside className="fixed top-0 left-0 bottom-0 w-[240px] z-50 flex flex-col bg-[rgba(8,14,28,0.75)] backdrop-blur-xl border-r border-white/[0.07]">
          <div className="flex items-center gap-3 px-5 py-5 border-b border-white/[0.07]">
            <div className="w-9 h-9 rounded-[10px] bg-gradient-to-br from-blue-500 to-blue-700 flex items-center justify-center flex-shrink-0">
              <svg width="20" height="20" viewBox="0 0 26 26" fill="none" aria-hidden>
                <path d="M13 2L3 7v6c0 5.5 4.3 10.7 10 12 5.7-1.3 10-6.5 10-12V7L13 2z" fill="rgba(255,255,255,0.15)" stroke="white" strokeWidth="1.5" strokeLinejoin="round" />
                <path d="M9 13l2.5 2.5L17 10" stroke="white" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            </div>
            <div>
              <div className="font-mono text-sm font-semibold tracking-[0.06em]">SIEM NEXUS</div>
              <div className="text-[10px] text-[#94A3B8] tracking-[0.1em] uppercase mt-0.5">Multi-Motor</div>
            </div>
          </div>

          <nav className="flex-1 overflow-y-auto">
            {NAV.map((group) => (
              <div key={group.section} className="px-3 pt-5 pb-1">
                <p className="font-mono text-[9px] text-[#94A3B8] tracking-[0.14em] uppercase px-2 mb-1.5">{group.section}</p>
                {group.items.map((item) => {
                  const active = item.href && pathname?.startsWith(item.href);
                  const base = "flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-[13px] font-medium mb-0.5 border-l-2 transition-all duration-150";
                  if (!item.href) {
                    return (
                      <span key={item.label} title="Disponible próximamente"
                        className={`${base} border-transparent text-[#94A3B8]/45 cursor-not-allowed`}>
                        {item.icon}{item.label}
                        <span className="ml-auto font-mono text-[9px] uppercase tracking-wider text-[#94A3B8]/40">pronto</span>
                      </span>
                    );
                  }
                  return (
                    <Link key={item.label} href={item.href}
                      className={`${base} ${active
                        ? "bg-blue-500/[0.12] text-[#3B82F6] border-[#3B82F6]"
                        : "text-[#94A3B8] border-transparent hover:bg-blue-500/[0.08] hover:text-[#E2E8F0] hover:border-blue-500/30"}`}>
                      {item.icon}{item.label}
                    </Link>
                  );
                })}
              </div>
            ))}
          </nav>

          <div className="flex items-center gap-2.5 px-4 py-3 border-t border-white/[0.07] bg-white/[0.02]">
            {avatarUrl && !avatarError ? (
              // eslint-disable-next-line @next/next/no-img-element
              <img src={avatarUrl} alt="" onError={() => setAvatarError(true)}
                style={{ width: 32, height: 32, borderRadius: 8, objectFit: "cover", flexShrink: 0 }} />
            ) : (
              <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center font-bold text-[13px] flex-shrink-0">
                {avatar}
              </div>
            )}
            <div className="min-w-0 flex-1">
              <p className="text-[13px] font-semibold truncate">{user?.name || user?.username || "Usuario"}</p>
              <p className="font-mono text-[10px] text-[#94A3B8] uppercase tracking-[0.08em]">{user?.role || "—"}</p>
            </div>
            <button onClick={logout} title="Cerrar sesión" aria-label="Cerrar sesión"
              className="text-[#94A3B8] hover:text-red-400 hover:bg-red-500/[0.08] p-1.5 rounded-md transition-all">
              {I("M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1")}
            </button>
          </div>
        </aside>

        {/* ── Contenido ── */}
        <main className="ml-[240px] flex-1 flex flex-col h-screen overflow-hidden relative z-10">
          <header className="flex items-center justify-between gap-4 px-7 h-[60px] border-b border-white/[0.07] bg-[rgba(8,14,28,0.6)] backdrop-blur-xl flex-shrink-0">
            <div className="min-w-0">
              <h1 className="text-[18px] font-semibold truncate">{title}</h1>
              {subtitle && <p className="text-xs text-[#94A3B8] mt-0.5 truncate">{subtitle}</p>}
            </div>
            <div className="flex items-center gap-3">
              {actions}
              <div className="font-mono text-xs text-[#94A3B8] bg-white/[0.04] px-3 py-1.5 rounded-md border border-white/[0.07] tabular-nums">{clock}</div>
            </div>
          </header>
          <div className="flex-1 overflow-y-auto p-7" style={{ scrollbarWidth: "thin" }}>
            {children(user)}
          </div>
        </main>
      </div>
    </>
  );
}
