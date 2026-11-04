// src/services/detectionRules.js
// Motor de reglas de detección del SIEM.
//
// Principios de rigor analítico:
//   - Cada hallazgo sale de una regla determinista aplicada a los registros importados.
//   - Cada alerta lleva los eventos exactos (Log_ID) que la sustentan.
//   - La justificación se construye solo con hechos observados (conteos, horas, IPs, cuentas).
//   - Una alerta es una SOSPECHA fundada en evidencia, no una confirmación de compromiso.
//
// Este módulo es puro: recibe eventos y devuelve hallazgos. No toca la base de datos.

// ── Escala de criticidad de las alertas ──────────────────────────────────────
const SEVERITY_LABEL = { 2: 'Bajo', 3: 'Medio', 4: 'Alto', 5: 'Crítico' };

// ── Helpers ──────────────────────────────────────────────────────────────────

const MIN = 60 * 1000;

const isPrivateIp = (ip) => {
    if (!ip) return false;
    if (ip.includes(':')) return /^(::1$|f[cd][0-9a-f]{2}:|fe80:)/i.test(ip);
    const [a, b] = ip.split('.').map(Number);
    return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
};
const isExternalIp = (ip) => Boolean(ip) && !isPrivateIp(ip);

const hhmm = (ms) => new Date(ms).toLocaleTimeString('es-PA', {
    timeZone: 'America/Panama', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
});

const groupBy = (items, keyFn) => {
    const map = new Map();
    for (const it of items) {
        const k = keyFn(it);
        if (k === null || k === undefined) continue;
        if (!map.has(k)) map.set(k, []);
        map.get(k).push(it);
    }
    return map;
};

// Agrupa eventos ordenados en ráfagas: un evento entra en la ráfaga si llega
// a menos de `gapMs` del evento anterior.
const bursts = (events, gapMs) => {
    const out = [];
    let current = [];
    for (const e of events) {
        if (current.length && e.at - current[current.length - 1].at > gapMs) {
            out.push(current);
            current = [];
        }
        current.push(e);
    }
    if (current.length) out.push(current);
    return out;
};

const uniq = (arr) => [...new Set(arr.filter(Boolean))];

const logIdRange = (evs) => {
    const ids = evs.map((e) => e.logId);
    return ids.length <= 4 ? ids.join(', ') : `${ids[0]} … ${ids[ids.length - 1]} (${ids.length} eventos)`;
};

// linkUsers: cuentas que ACTÚAN en el hallazgo (se usan para agrupar incidentes).
// Por defecto, todas las cuentas de la evidencia; las reglas cuyas cuentas son
// víctimas (p. ej. password spraying) lo restringen.
const finding = (rule, { title, justification, trigger, supporting = [], context = [], severity, linkUsers }) => {
    const all = [trigger, ...supporting, ...context].filter(Boolean);
    const evidence = [];
    const seen = new Set();
    const add = (e, role) => { if (e && !seen.has(e.id)) { seen.add(e.id); evidence.push({ event: e, role }); } };
    add(trigger, 'trigger');
    supporting.forEach((e) => add(e, 'supporting'));
    context.forEach((e) => add(e, 'context'));
    const times = all.map((e) => e.at);
    return {
        rule,
        title,
        severity: severity || rule.severity,
        justification,
        evidence,
        windowStart: Math.min(...times),
        windowEnd: Math.max(...times),
        entities: {
            users:       uniq(all.map((e) => e.user)),
            linkUsers:   linkUsers !== undefined ? uniq(linkUsers) : uniq(all.map((e) => e.user)),
            externalIps: uniq(all.flatMap((e) => [e.srcIp, e.destIp]).filter(isExternalIp)),
            hosts:       uniq(all.map((e) => e.host)),
        },
    };
};

// Patrones reutilizables
const RX = {
    encodedPs:     /powershell(\.exe)?\b.*\s-(e|ec|enc|encodedcommand)\s/i,
    shadowDelete:  /(vssadmin(\.exe)?\s+delete\s+shadows|wmic(\.exe)?\s+shadowcopy\s+delete)/i,
    shell:         /\b(cmd|powershell|pwsh)(\.exe)?\b/i,
    discovery:     /(\bnet(\.exe)?\s+(view|user|group|localgroup)\b|Get-LocalGroupMember|Get-SmbShare|Get-ADUser|\bwhoami\b|\bnltest\b)/i,
    archive:       /(\btar(\.exe)?\s+.*-[a-z]*c|\b7z(\.exe)?\s+a\b|\brar(\.exe)?\s+a\b|Compress-Archive)/i,
    userWritable:  /\\(ProgramData|Users\\Public|Temp|Windows\\Temp|AppData)\\/i,
    exeInWritable: /^"?[A-Z]:\\(ProgramData|Users\\Public|Temp|Windows\\Temp)\\[^\s"]+\.exe/i,
    scriptEngine:  /\b(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32)(\.exe)?\b/i,
    webAttackUri:  /(cmd=|whoami|\.\.\/|%2e%2e|<script|union\s+select|\/etc\/passwd)/i,
    logonType:     /LogonType=(\d+)/i,
    bytesOut:      /bytes_out=(\d+)/i,
};

// ── Definición de reglas ─────────────────────────────────────────────────────
// Cada regla declara sus metadatos (se guardan en correlation_rules) y su lógica.

const RULES = [
    // ───────────────────────────── FUERZA BRUTA ─────────────────────────────
    {
        code: 'BF-001', category: 'brute_force', severity: 4, version: 1,
        name: 'Password spraying: muchos fallos contra varias cuentas desde una IP',
        description: 'Ráfaga de inicios de sesión fallidos desde una misma IP de origen contra varias cuentas distintas.',
        eventTypes: ['logon_failure'],
        params: { maxGapMin: 5, minFailures: 10, minDistinctUsers: 5 },
        mitre: ['T1110.003'], tactic: 'Credential Access',
        detect(ev, p, ctx) {
            const out = [];
            const fails = ev.filter((e) => e.type === 'logon_failure' && e.srcIp);
            for (const [ip, list] of groupBy(fails, (e) => e.srcIp)) {
                for (const b of bursts(list, p.maxGapMin * MIN)) {
                    const users = uniq(b.map((e) => e.user));
                    if (b.length < p.minFailures || users.length < p.minDistinctUsers) continue;
                    b.forEach((e) => ctx.sprayEventIds.add(e.id));
                    ctx.bruteForceIps.add(ip);
                    out.push(finding(this, {
                        title: `Password spraying desde ${ip} contra ${users.length} cuentas`,
                        justification:
                            `${b.length} inicios de sesión fallidos desde ${ip} contra ${users.length} cuentas distintas ` +
                            `(${users.join(', ')}) entre ${hhmm(b[0].at)} y ${hhmm(b[b.length - 1].at)}. ` +
                            `Supera el umbral de ${p.minFailures} fallos y ${p.minDistinctUsers} cuentas con intervalos ` +
                            `menores a ${p.maxGapMin} min. Evidencia: ${logIdRange(b)}.`,
                        trigger: b[b.length - 1], supporting: b.slice(0, -1),
                        linkUsers: [],                    // las cuentas son víctimas, no actores
                    }));
                }
            }
            return out;
        },
    },
    {
        code: 'BF-002', category: 'brute_force', severity: 4, version: 1,
        name: 'Fuerza bruta contra una cuenta',
        description: 'Varios inicios de sesión fallidos consecutivos para la misma cuenta desde la misma IP.',
        eventTypes: ['logon_failure'],
        params: { maxGapMin: 5, minFailures: 4 },
        mitre: ['T1110.001'], tactic: 'Credential Access',
        detect(ev, p, ctx) {
            const out = [];
            const fails = ev.filter((e) => e.type === 'logon_failure' && e.srcIp && e.user && !ctx.sprayEventIds.has(e.id));
            for (const [, list] of groupBy(fails, (e) => `${e.srcIp}|${e.user}`)) {
                for (const b of bursts(list, p.maxGapMin * MIN)) {
                    if (b.length < p.minFailures) continue;
                    const { srcIp, user } = b[0];
                    const lt = RX.logonType.exec(b[0].desc || '');
                    ctx.bruteForceIps.add(srcIp);
                    out.push(finding(this, {
                        title: `Fuerza bruta contra ${user} desde ${srcIp}`,
                        justification:
                            `${b.length} fallos de inicio de sesión de ${user} desde ${srcIp} hacia ${uniq(b.map((e) => e.host)).join(', ')} ` +
                            `entre ${hhmm(b[0].at)} y ${hhmm(b[b.length - 1].at)}` +
                            `${lt ? ` (LogonType=${lt[1]}${lt[1] === '10' ? ', escritorio remoto' : ''})` : ''}. ` +
                            `Supera el umbral de ${p.minFailures} fallos con intervalos menores a ${p.maxGapMin} min. ` +
                            `Evidencia: ${logIdRange(b)}.`,
                        trigger: b[b.length - 1], supporting: b.slice(0, -1),
                    }));
                }
            }
            return out;
        },
    },

    // ─────────────────────────── INICIO SOSPECHOSO ──────────────────────────
    {
        code: 'SL-001', category: 'suspicious_login', severity: 5, version: 1,
        name: 'Inicio exitoso desde IP externa tras múltiples fallos',
        description: 'Inicio de sesión exitoso desde una IP externa que acumuló fallos previos en la ventana evaluada. Indica posible obtención de credenciales.',
        eventTypes: ['logon_success', 'logon_failure'],
        params: { lookbackMin: 60, minPriorFailures: 3 },
        mitre: ['T1078', 'T1110'], tactic: 'Initial Access',
        detect(ev, p, ctx) {
            const out = [];
            for (const s of ev.filter((e) => e.type === 'logon_success' && isExternalIp(e.srcIp))) {
                const prior = ev.filter((e) => e.type === 'logon_failure' && e.srcIp === s.srcIp &&
                    e.at < s.at && s.at - e.at <= p.lookbackMin * MIN);
                if (prior.length < p.minPriorFailures) continue;
                ctx.compromisedLogons.push(s);
                const users = uniq(prior.map((e) => e.user));
                out.push(finding(this, {
                    title: `Inicio exitoso de ${s.user} desde ${s.srcIp} tras ${prior.length} fallos`,
                    justification:
                        `A las ${hhmm(s.at)} la cuenta ${s.user} inició sesión con éxito en ${s.host} desde la IP externa ${s.srcIp} ` +
                        `(${s.logId}). En los ${p.lookbackMin} min previos esa IP registró ${prior.length} fallos contra ` +
                        `${users.length} cuenta(s) (${logIdRange(prior)}). Es consistente con credenciales obtenidas por ` +
                        `fuerza bruta; los registros no permiten confirmar quién usó la sesión.`,
                    trigger: s, context: prior,
                    linkUsers: [s.user],
                }));
            }
            return out;
        },
    },
    {
        code: 'SL-002', category: 'suspicious_login', severity: 3, version: 1,
        name: 'Inicio exitoso desde IP externa',
        description: 'Inicio de sesión exitoso cuyo origen es una IP pública, sin fallos previos suficientes para SL-001.',
        eventTypes: ['logon_success'],
        params: {},
        mitre: ['T1078'], tactic: 'Initial Access',
        detect(ev, p, ctx) {
            const flagged = new Set(ctx.compromisedLogons.map((e) => e.id));
            return ev.filter((e) => e.type === 'logon_success' && isExternalIp(e.srcIp) && !flagged.has(e.id))
                .map((s) => finding(this, {
                    title: `Inicio exitoso de ${s.user} desde IP externa ${s.srcIp}`,
                    justification:
                        `A las ${hhmm(s.at)} la cuenta ${s.user} inició sesión en ${s.host} desde la IP pública ${s.srcIp} (${s.logId}).`,
                    trigger: s,
                }));
        },
    },

    // ───────────────────────── ESCALAMIENTO DE PRIVILEGIOS ──────────────────
    {
        code: 'PE-001', category: 'privilege_escalation', severity: 4, version: 1,
        name: 'Privilegios especiales asignados a sesión de origen externo',
        description: 'Evento 4672 (privilegios especiales) en una sesión cuyo origen es una IP externa.',
        eventTypes: ['special_privileges'],
        params: { lookbackMin: 15 },
        mitre: ['T1078.002'], tactic: 'Privilege Escalation',
        detect(ev, p) {
            return ev.filter((e) => e.type === 'special_privileges' && isExternalIp(e.srcIp)).map((pr) => {
                const logon = ev.filter((e) => e.type === 'logon_success' && e.srcIp === pr.srcIp && e.user === pr.user &&
                    e.at <= pr.at && pr.at - e.at <= p.lookbackMin * MIN);
                return finding(this, {
                    title: `Privilegios especiales para ${pr.user} en ${pr.host} (origen ${pr.srcIp})`,
                    justification:
                        `A las ${hhmm(pr.at)} se asignaron privilegios especiales (4672) a ${pr.user} en ${pr.host} ` +
                        `en una sesión originada en la IP externa ${pr.srcIp} (${pr.logId})` +
                        `${logon.length ? `, ${Math.round((pr.at - logon[logon.length - 1].at) / MIN)} min después de su inicio de sesión (${logon[logon.length - 1].logId})` : ''}. ` +
                        `Una cuenta con privilegios administrativos usada desde Internet amplía el impacto de un posible compromiso.`,
                    trigger: pr, context: logon,
                });
            });
        },
    },

    // ─────────────────────────── COMANDOS Y PROCESOS ────────────────────────
    // Se agrupan por (patrón, equipo, cuenta). Cada evento se asigna al patrón más grave.
    ...[
        { code: 'PX-002', severity: 5, name: 'Eliminación de copias de seguridad (shadow copies)', test: (e) => RX.shadowDelete.test(e.cmd),
          mitre: ['T1490'], tactic: 'Impact', why: 'eliminar las instantáneas de volumen impide la recuperación y es una acción típica previa al cifrado por ransomware' },
        { code: 'PX-003', severity: 5, name: 'Servidor web ejecutando un intérprete de comandos', test: (e) => /^IIS APPPOOL\\/i.test(e.user || '') && RX.shell.test(e.cmd),
          mitre: ['T1505.003'], tactic: 'Persistence', why: 'el proceso del sitio web (pool de IIS) no debería abrir consolas de comandos; es un rasgo característico de una web shell' },
        { code: 'PX-001', severity: 4, name: 'PowerShell con comando codificado', test: (e) => RX.encodedPs.test(e.cmd),
          mitre: ['T1059.001', 'T1027'], tactic: 'Execution', why: 'el parámetro -EncodedCommand oculta el contenido real del script' },
        { code: 'PX-006', severity: 4, name: 'Tarea programada que ejecuta script desde ruta escribible', test: (e) => e.type === 'scheduled_task_created' && (RX.scriptEngine.test(e.cmd) || RX.userWritable.test(e.cmd)),
          mitre: ['T1053.005'], tactic: 'Persistence', why: 'una tarea programada que lanza un script desde una ruta escribible por usuarios es un mecanismo común de persistencia' },
        { code: 'PX-007', severity: 4, name: 'Servicio instalado desde ruta escribible', test: (e) => e.type === 'service_installed' && RX.userWritable.test(e.cmd),
          mitre: ['T1543.003'], tactic: 'Persistence', why: 'los servicios legítimos rara vez se instalan desde ProgramData, Temp o Public' },
        { code: 'PX-004', severity: 3, name: 'Comandos de reconocimiento', test: (e) => RX.discovery.test(e.cmd) || RX.discovery.test(e.desc),
          mitre: ['T1087', 'T1135'], tactic: 'Discovery', why: 'enumeran cuentas, grupos o recursos compartidos de la red' },
        { code: 'PX-005', severity: 3, name: 'Compresión de archivos (posible preparación de datos)', test: (e) => RX.archive.test(e.cmd),
          mitre: ['T1560.001'], tactic: 'Collection', why: 'empaquetar archivos suele preceder a su extracción' },
        { code: 'PX-008', severity: 3, name: 'Ejecutable lanzado desde ruta escribible', test: (e) => RX.exeInWritable.test(e.cmd),
          mitre: [], tactic: 'Execution', why: 'los binarios legítimos se ejecutan normalmente desde Program Files o System32' },
    ].map((pat, idx, all) => ({
        code: pat.code, category: 'process_execution', severity: pat.severity, version: 1,
        name: pat.name,
        description: `Ejecución registrada que coincide con el patrón: ${pat.name.toLowerCase()}.`,
        eventTypes: ['process_creation', 'powershell_scriptblock', 'scheduled_task_created', 'service_installed'],
        params: { groupGapMin: 60 },
        mitre: pat.mitre, tactic: pat.tactic,
        detect(ev, p) {
            const candidates = ev.filter((e) => this.eventTypes.includes(e.type) && (e.cmd || e.desc));
            // Asigna cada evento solo al primer patrón (más grave) que lo cumpla
            const mine = candidates.filter((e) => pat.test(e) && !all.slice(0, idx).some((q) => q.test(e)));
            const out = [];
            for (const [, list] of groupBy(mine, (e) => `${e.host}|${e.user}`)) {
                for (const b of bursts(list, p.groupGapMin * MIN)) {
                    const e0 = b[0];
                    // Para bloques de PowerShell el contenido real está en la descripción
                    const shown = (e) => (e.type === 'powershell_scriptblock' ? e.desc : e.cmd) || e.desc;
                    const cmds = uniq(b.map(shown));
                    const verb = { scheduled_task_created: 'creó una tarea programada', service_installed: 'instaló un servicio',
                                   powershell_scriptblock: 'ejecutó el script de PowerShell' }[
                                   b.every((e) => e.type === e0.type) ? e0.type : ''] || 'ejecutó';
                    out.push(finding(this, {
                        title: `${pat.name} en ${e0.host} (${e0.user || 'cuenta desconocida'})`,
                        justification:
                            `${b.length === 1 ? `A las ${hhmm(e0.at)}` : `${b.length} veces entre ${hhmm(e0.at)} y ${hhmm(b[b.length - 1].at)}`}, ` +
                            `la cuenta ${e0.user || '(sin usuario)'} ${verb} en ${e0.host}: ${cmds.slice(0, 3).map((c) => `«${c}»`).join('; ')}` +
                            `${cmds.length > 3 ? ` y ${cmds.length - 3} más` : ''}. Se considera sospechoso porque ${pat.why}. ` +
                            `Evidencia: ${logIdRange(b)}.`,
                        trigger: e0, supporting: b.slice(1),
                    }));
                }
            }
            return out;
        },
    })),

    // ─────────────────────────── MOVIMIENTO LATERAL ─────────────────────────
    {
        code: 'LM-001', category: 'lateral_movement', severity: 5, version: 1,
        name: 'Inicio de sesión de red en otro equipo tras acceso externo',
        description: 'Una cuenta que inició sesión desde una IP externa realiza un inicio de sesión de red (LogonType=3) en un equipo distinto poco después.',
        eventTypes: ['logon_success', 'logon_failure', 'share_access', 'share_access_detailed'],
        params: { lookbackMin: 60, followMin: 30 },
        mitre: ['T1021.002'], tactic: 'Lateral Movement',
        detect(ev, p) {
            const out = [];
            const netLogons = ev.filter((e) => e.type === 'logon_success' && e.user && RX.logonType.exec(e.desc || '')?.[1] === '3');
            for (const n of netLogons) {
                const origin = ev.filter((e) => e.type === 'logon_success' && e.user === n.user && isExternalIp(e.srcIp) &&
                    e.host !== n.host && e.at < n.at && n.at - e.at <= p.lookbackMin * MIN);
                if (!origin.length) continue;
                const o = origin[origin.length - 1];
                const priorFails = ev.filter((e) => e.type === 'logon_failure' && e.user === n.user && e.host === n.host &&
                    e.at < n.at && n.at - e.at <= 10 * MIN);
                const follow = ev.filter((e) => ['share_access', 'share_access_detailed'].includes(e.type) && e.user === n.user &&
                    e.host === n.host && e.at >= n.at && e.at - n.at <= p.followMin * MIN);
                out.push(finding(this, {
                    title: `Movimiento lateral de ${n.user}: ${o.host} → ${n.host}`,
                    justification:
                        `${n.user} inició sesión en ${o.host} desde la IP externa ${o.srcIp} a las ${hhmm(o.at)} (${o.logId}) y ` +
                        `${Math.round((n.at - o.at) / MIN)} min después realizó un inicio de sesión de red (LogonType=3) en ${n.host} ` +
                        `desde ${n.srcIp} (${n.logId})` +
                        `${priorFails.length ? `, precedido de ${priorFails.length} intento(s) fallido(s) (${logIdRange(priorFails)})` : ''}` +
                        `${follow.length ? `. Después accedió a recursos compartidos de ${n.host}: ${uniq(follow.map((e) => e.desc)).join('; ')} (${logIdRange(follow)})` : ''}.`,
                    trigger: n, supporting: [...priorFails, ...follow], context: [o],
                }));
            }
            return out;
        },
    },

    // ───────────────────────────── OTRAS ANOMALÍAS ──────────────────────────
    {
        code: 'AN-001', category: 'anomaly', severity: 4, version: 1,
        name: 'Acceso masivo a archivos',
        description: 'Una cuenta accede a muchos objetos en el mismo equipo en poco tiempo.',
        eventTypes: ['object_access'],
        params: { maxGapMin: 2, minAccesses: 10 },
        mitre: ['T1039'], tactic: 'Collection',
        detect(ev, p) {
            const out = [];
            const acc = ev.filter((e) => e.type === 'object_access' && e.user);
            for (const [, list] of groupBy(acc, (e) => `${e.user}|${e.host}`)) {
                for (const b of bursts(list, p.maxGapMin * MIN)) {
                    if (b.length < p.minAccesses) continue;
                    const e0 = b[0];
                    out.push(finding(this, {
                        title: `Acceso masivo a archivos por ${e0.user} en ${e0.host}`,
                        justification:
                            `${e0.user} accedió a ${b.length} objetos en ${e0.host} entre ${hhmm(e0.at)} y ${hhmm(b[b.length - 1].at)}` +
                            `${uniq(b.map((e) => e.dest)).length === 1 && e0.dest ? ` (recurso ${e0.dest})` : ''}. ` +
                            `Supera el umbral de ${p.minAccesses} accesos con intervalos menores a ${p.maxGapMin} min. ` +
                            `Evidencia: ${logIdRange(b)}.`,
                        trigger: e0, supporting: b.slice(1),
                    }));
                }
            }
            return out;
        },
    },
    {
        code: 'AN-002', category: 'anomaly', severity: 4, version: 1,
        name: 'Alto volumen de datos enviado a destino externo',
        description: 'Muchas subidas (POST) o gran volumen de bytes salientes desde una cuenta hacia un mismo destino externo.',
        eventTypes: ['proxy_request'],
        params: { maxGapMin: 10, minUploads: 10, minMegabytes: 50 },
        mitre: ['T1048'], tactic: 'Exfiltration',
        detect(ev, p) {
            const out = [];
            const ups = ev.filter((e) => e.type === 'proxy_request' && isExternalIp(e.destIp));
            for (const [, list] of groupBy(ups, (e) => `${e.user}|${e.destIp}`)) {
                for (const b of bursts(list, p.maxGapMin * MIN)) {
                    const bytes = b.reduce((s, e) => s + Number(RX.bytesOut.exec(e.cmd || '')?.[1] || 0), 0);
                    const mb = bytes / (1024 * 1024);
                    if (b.length < p.minUploads && mb < p.minMegabytes) continue;
                    const e0 = b[0];
                    out.push(finding(this, {
                        title: `Envío de ${mb.toFixed(1)} MB a ${e0.destIp} desde ${e0.host}`,
                        justification:
                            `${b.length} solicitudes salientes de ${e0.user || '(sin usuario)'} desde ${e0.host} hacia ${e0.dest} ` +
                            `entre ${hhmm(e0.at)} y ${hhmm(b[b.length - 1].at)}, con ${bytes.toLocaleString('es-PA')} bytes enviados ` +
                            `(${mb.toFixed(1)} MB) según el campo bytes_out. Supera el umbral de ${p.minUploads} envíos o ` +
                            `${p.minMegabytes} MB. Evidencia: ${logIdRange(b)}.`,
                        trigger: e0, supporting: b.slice(1),
                    }));
                }
            }
            return out;
        },
    },
    {
        code: 'AN-003', category: 'anomaly', severity: 4, version: 1,
        name: 'Conexión saliente a IP externa iniciada por un intérprete de comandos',
        description: 'Conexión de red permitida hacia una IP pública cuyo proceso es PowerShell, cmd u otro intérprete.',
        eventTypes: ['network_connection_allowed'],
        params: {},
        mitre: ['T1071.001'], tactic: 'Command and Control',
        detect(ev) {
            return ev.filter((e) => e.type === 'network_connection_allowed' && isExternalIp(e.destIp) && RX.scriptEngine.test(e.cmd))
                .map((e) => finding(this, {
                    title: `Conexión saliente de ${e.cmd} a ${e.dest} desde ${e.host}`,
                    justification:
                        `A las ${hhmm(e.at)} se permitió en ${e.host} una conexión de ${e.user || '(sin usuario)'} hacia la IP externa ` +
                        `${e.dest} realizada por ${e.cmd} (${e.logId}). Los intérpretes de comandos no suelen comunicarse ` +
                        `directamente con Internet en un entorno corporativo.`,
                    trigger: e,
                }));
        },
    },
    {
        code: 'AN-004', category: 'anomaly', severity: 4, version: 1,
        name: 'Ráfaga de solicitudes web con errores o rutas de ataque',
        description: 'Muchas solicitudes HTTP desde una misma IP en poco tiempo con errores del servidor o URIs típicas de explotación.',
        eventTypes: ['http_request'],
        params: { maxGapMin: 5, minRequests: 10, minErrors: 5 },
        mitre: ['T1190'], tactic: 'Initial Access',
        detect(ev, p) {
            const out = [];
            const reqs = ev.filter((e) => e.type === 'http_request' && e.srcIp);
            for (const [ip, list] of groupBy(reqs, (e) => e.srcIp)) {
                for (const b of bursts(list, p.maxGapMin * MIN)) {
                    const errors = b.filter((e) => /^(5\d\d|404)$/.test(e.result || ''));
                    const attackUris = uniq(b.map((e) => e.cmd).filter((u) => RX.webAttackUri.test(u || '')));
                    if (b.length < p.minRequests || (errors.length < p.minErrors && !attackUris.length)) continue;
                    out.push(finding(this, {
                        title: `Ráfaga de ${b.length} solicitudes web desde ${ip} hacia ${uniq(b.map((e) => e.host)).join(', ')}`,
                        justification:
                            `${b.length} solicitudes HTTP desde ${ip} entre ${hhmm(b[0].at)} y ${hhmm(b[b.length - 1].at)}, ` +
                            `${errors.length} con respuesta de error (404/5xx). Rutas solicitadas: ${uniq(b.map((e) => e.cmd)).join(', ')}` +
                            `${attackUris.length ? `. Incluye rutas con patrones de explotación: ${attackUris.join(', ')}` : ''}. ` +
                            `Evidencia: ${logIdRange(b)}.`,
                        trigger: b[0], supporting: b.slice(1),
                    }));
                }
            }
            return out;
        },
    },
];

// ── Agrupación de alertas en incidentes ──────────────────────────────────────
// Dos alertas pertenecen al mismo incidente si comparten una cuenta o una IP externa.
// Cuentas compartidas por servicios web genéricos no se usan como vínculo.

const groupIntoIncidents = (findings) => {
    const parent = findings.map((_, i) => i);
    const find = (i) => (parent[i] === i ? i : (parent[i] = find(parent[i])));
    const owner = new Map();
    findings.forEach((f, i) => {
        const keys = [...f.entities.linkUsers.map((u) => `u:${u.toLowerCase()}`), ...f.entities.externalIps.map((ip) => `ip:${ip}`)];
        for (const k of keys) {
            if (owner.has(k)) parent[find(i)] = find(owner.get(k));
            else owner.set(k, i);
        }
    });
    const groups = new Map();
    findings.forEach((f, i) => {
        const r = find(i);
        if (!groups.has(r)) groups.set(r, []);
        groups.get(r).push(f);
    });
    return [...groups.values()].map((list) => {
        list.sort((a, b) => a.windowStart - b.windowStart);
        const top = [...list].sort((a, b) => b.severity - a.severity || a.windowStart - b.windowStart)[0];
        const users = uniq(list.flatMap((f) => f.entities.linkUsers));
        const targeted = uniq(list.flatMap((f) => f.entities.users)).filter((u) => !users.includes(u));
        const ips = uniq(list.flatMap((f) => f.entities.externalIps));
        const hosts = uniq(list.flatMap((f) => f.entities.hosts));
        const subject = [...ips, ...users].join(', ');
        return {
            title: `${top.title}${list.length === 2 ? ' (+1 alerta relacionada)' : list.length > 2 ? ` (+${list.length - 1} alertas relacionadas)` : ''}`.slice(0, 150),
            severity: Math.max(...list.map((f) => f.severity)),
            findings: list,
            rule: top.rule,
            affectedAssets: hosts,
            mitreTactics: uniq(list.map((f) => f.rule.tactic)),
            start: Math.min(...list.map((f) => f.windowStart)),
            end: Math.max(...list.map((f) => f.windowEnd)),
            metadata: { users, targeted_users: targeted, external_ips: ips, hosts, alert_count: list.length, subject },
        };
    }).sort((a, b) => b.severity - a.severity || a.start - b.start);
};

// ── Ejecución ────────────────────────────────────────────────────────────────

// events: [{ id, logId, type, code, sev, srcIp, destIp, destPort, host, user, dest,
//            logSource, desc, cmd, result, at(ms) }] ordenados por fecha
const runRules = (events) => {
    const ctx = { sprayEventIds: new Set(), bruteForceIps: new Set(), compromisedLogons: [] };
    const findings = [];
    for (const rule of RULES) {
        for (const f of rule.detect(events, rule.params, ctx)) findings.push(f);
    }
    findings.sort((a, b) => a.windowStart - b.windowStart || b.severity - a.severity);
    return { findings, incidents: groupIntoIncidents(findings) };
};

module.exports = { RULES, runRules, SEVERITY_LABEL, isExternalIp };
