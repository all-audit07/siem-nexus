// lib/siem.ts — utilidades compartidas del SIEM (API, sesión, formato)

export const API = "/api";

export interface SiemUser {
  uuid?: string; username: string; role: string;
  name?: string; email?: string; age?: number | null; avatar?: string | null;
}

// ── Sesión ───────────────────────────────────────────────────────
export const getToken = () => (typeof window === "undefined" ? null : localStorage.getItem("siem_token"));

export const getUser = (): SiemUser | null => {
  if (typeof window === "undefined") return null;
  try { return JSON.parse(localStorage.getItem("siem_user") || "null"); } catch { return null; }
};

export const clearSession = () => {
  localStorage.removeItem("siem_token");
  localStorage.removeItem("siem_user");
};

// ── Llamadas a la API ────────────────────────────────────────────
export class SessionExpiredError extends Error {}

export interface ApiResult<T> { ok: boolean; status: number; data: T & { error?: string } }

// Añade el token, interpreta la respuesta y detecta sesión expirada.
export async function apiFetch<T = unknown>(path: string, init: RequestInit = {}): Promise<ApiResult<T>> {
  const token = getToken();
  const headers = new Headers(init.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (init.body && !(init.body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  let res: Response;
  try {
    res = await fetch(`${API}${path}`, { ...init, headers });
  } catch {
    return { ok: false, status: 0, data: { error: "No se pudo contactar con el backend" } as T & { error?: string } };
  }

  let data: T & { error?: string };
  try { data = await res.json(); }
  catch { data = { error: `Respuesta no válida del servidor (HTTP ${res.status})` } as T & { error?: string }; }

  if (res.status === 401 || (res.status === 403 && /token/i.test(data?.error || ""))) {
    clearSession();
    throw new SessionExpiredError(data?.error || "Sesión expirada");
  }
  return { ok: res.ok, status: res.status, data };
}

// ── Criticidad (escala del proyecto) ─────────────────────────────
export const SEVERITY: Record<number, { label: string; color: string; cls: string }> = {
  5: { label: "Crítico", color: "#EF4444", cls: "bg-red-500/15 text-red-300 border-red-500/25" },
  4: { label: "Alto",    color: "#F97316", cls: "bg-orange-500/15 text-orange-300 border-orange-500/25" },
  3: { label: "Medio",   color: "#EAB308", cls: "bg-yellow-500/15 text-yellow-300 border-yellow-500/25" },
  2: { label: "Bajo",    color: "#3B82F6", cls: "bg-blue-500/15 text-blue-300 border-blue-500/25" },
  1: { label: "Info",    color: "#22C55E", cls: "bg-green-500/15 text-green-300 border-green-500/25" },
};

export const SEVERITY_BY_LABEL: Record<string, number> = { "Crítico": 5, "Alto": 4, "Medio": 3, "Bajo": 2, "Info": 1 };

// ── Fechas (siempre en hora de Panamá, la zona de los logs) ──────
export const TZ = "America/Panama";

const dtf = new Intl.DateTimeFormat("en-GB", {
  timeZone: TZ, day: "2-digit", month: "2-digit", year: "numeric",
  hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23",
});

// Formato fijo DD/MM/AAAA HH:MM:SS, independiente del idioma del navegador
export const fmtDateTime = (value?: string | null) => {
  if (!value) return "—";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  const p = Object.fromEntries(dtf.formatToParts(d).map((x) => [x.type, x.value]));
  return `${p.day}/${p.month}/${p.year} ${p.hour}:${p.minute}:${p.second}`;
};

export const fmtNumber = (n: number) => n.toLocaleString("es-PA");
