const links = {
  Producto: ["Características", "Precios", "Changelog", "Roadmap"],
  Empresa: ["Sobre nosotros", "Blog", "Careers", "Contacto"],
  Legal: ["Privacidad", "Términos de uso", "Seguridad", "Cookies"],
  Soporte: ["Documentación", "API Reference", "Status", "Comunidad"],
};

export default function Footer() {
  return (
    <footer className="relative bg-[#020817]">
      {/* Links grid */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="grid grid-cols-2 md:grid-cols-5 gap-8">
          {/* Brand */}
          <div className="col-span-2 md:col-span-1">
            <a href="#" className="flex items-center gap-2.5 mb-4">
              <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-500 to-blue-700 flex items-center justify-center">
                <svg width="18" height="18" viewBox="0 0 26 26" fill="none">
                  <path
                    d="M13 2L3 7v6c0 5.5 4.3 10.7 10 12 5.7-1.3 10-6.5 10-12V7L13 2z"
                    fill="rgba(255,255,255,0.15)"
                    stroke="white"
                    strokeWidth="1.5"
                    strokeLinejoin="round"
                  />
                  <path d="M9 13l2.5 2.5L17 10" stroke="white" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </div>
              <span className="font-mono font-semibold text-sm tracking-widest text-[#E2E8F0]">
                SIEM NEXUS
              </span>
            </a>
            <p className="text-xs text-[#94A3B8] leading-relaxed mb-4 max-w-[180px]">
              Plataforma SIEM enterprise para equipos de seguridad modernos.
            </p>
            <div className="flex gap-2">
              {["mysql", "pg"].map((db) => (
                <span
                  key={db}
                  className="flex items-center gap-1.5 bg-white/[0.03] border border-white/[0.07] rounded-md px-2 py-1 font-mono text-[10px] text-[#94A3B8]"
                >
                  <span
                    className="w-1.5 h-1.5 rounded-full"
                    style={{
                      background: db === "mysql" ? "#F59E0B" : "#3B82F6",
                      boxShadow: `0 0 5px ${db === "mysql" ? "#F59E0B" : "#3B82F6"}`,
                    }}
                  />
                  {db === "mysql" ? "MySQL" : "PostgreSQL"}
                </span>
              ))}
            </div>
          </div>

          {/* Nav columns */}
          {Object.entries(links).map(([section, items]) => (
            <div key={section}>
              <h4 className="font-mono text-[11px] font-semibold tracking-widest uppercase text-[#94A3B8] mb-4">
                {section}
              </h4>
              <ul className="space-y-2.5">
                {items.map((item) => (
                  <li key={item}>
                    <a
                      href="#"
                      className="text-sm text-[#475569] hover:text-[#94A3B8] transition-colors duration-150"
                    >
                      {item}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>

        {/* Bottom bar */}
        <div className="mt-12 pt-6 border-t border-white/[0.06] flex flex-col sm:flex-row items-center justify-between gap-4">
          <p className="font-mono text-[11px] text-[#475569]">
            © 2026 SIEM NEXUS — MySQL + PostgreSQL Multi-Motor
          </p>
          <div className="flex items-center gap-4">
            <span className="flex items-center gap-1.5 text-[11px] text-[#475569] font-mono">
              <span className="w-1.5 h-1.5 rounded-full bg-[#22C55E] shadow-[0_0_6px_#22C55E]" />
              All systems operational
            </span>
          </div>
        </div>
      </div>
    </footer>
  );
}
