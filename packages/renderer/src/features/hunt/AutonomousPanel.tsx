import React, { useEffect, useMemo, useRef, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Activity, AlertTriangle, CheckCircle2, ChevronDown, ChevronUp,
  Clock, Globe, Search, Shield, Square, Target, Terminal, TrendingUp, Zap,
} from "lucide-react";
import type {
  AutonomousActionRecord,
  AutonomousStrategy,
  ConsoleLogLine,
  ExploitPath,
  Finding,
  HuntSession,
} from "@hexguard/shared";

// ─── Strategy labels ──────────────────────────────────────────────────────────

const STRATEGY_LABELS: Record<AutonomousStrategy, string> = {
  recon:      "Reconnaissance",
  discover:   "Discovery",
  analyze:    "Analysis",
  exploit:    "Exploitation",
  validate:   "Validation",
  synthesize: "Synthesis",
};

// ─── Severity colours ─────────────────────────────────────────────────────────

const SEV_COLOR: Record<string, string> = {
  critical: "#ef4444",
  high:     "#f97316",
  medium:   "#f59e0b",
  low:      "#22c55e",
  info:     "#06b6d4",
};

// ─── Action type metadata ─────────────────────────────────────────────────────

function actionMeta(type: AutonomousActionRecord["actionType"]): { icon: React.ReactNode; color: string } {
  const s = 11;
  switch (type) {
    case "recon":       return { icon: <Globe size={s} />,         color: "#06b6d4" };
    case "enumerate":   return { icon: <Search size={s} />,        color: "#06b6d4" };
    case "fingerprint": return { icon: <Shield size={s} />,        color: "#a78bfa" };
    case "discover":    return { icon: <Search size={s} />,        color: "#38bdf8" };
    case "analyze":     return { icon: <Activity size={s} />,      color: "#f59e0b" };
    case "probe":       return { icon: <AlertTriangle size={s} />, color: "#f97316" };
    case "exploit":     return { icon: <Zap size={s} />,           color: "#ef4444" };
    case "escalate":    return { icon: <Zap size={s} />,           color: "#ef4444" };
    case "validate":    return { icon: <CheckCircle2 size={s} />,  color: "#22c55e" };
    case "synthesize":  return { icon: <Terminal size={s} />,      color: "#8b5cf6" };
    case "nuclei-scan": return { icon: <Shield size={s} />,        color: "#a78bfa" };
    case "nikto-scan":  return { icon: <Search size={s} />,        color: "#60a5fa" };
    case "waf-detect":  return { icon: <Shield size={s} />,        color: "#34d399" };
    case "deep-sqli":   return { icon: <AlertTriangle size={s} />, color: "#ef4444" };
    default:            return { icon: <Activity size={s} />,      color: "#6b7280" };
  }
}

// ─── MissionControlBar ───────────────────────────────────────────────────────

interface MCBarProps {
  hunt:     HuntSession;
  elapsed:  number;
  onStop:   () => void;
  onExport: (h: HuntSession) => void;
}

function MissionControlBar({ hunt, elapsed, onStop, onExport }: MCBarProps) {
  const ctx       = hunt.context;
  const findings  = ctx.findings ?? [];
  const critCount = findings.filter(f => f.severity === "critical").length;
  const highCount = findings.filter(f => f.severity === "high").length;
  const medCount  = findings.filter(f => f.severity === "medium").length;
  const isRunning = hunt.state === "executing" || hunt.state === "starting";
  const isEnded   = hunt.state === "ended";
  const strategy  = ctx.currentStrategy;
  const mm = String(Math.floor(elapsed / 60)).padStart(2, "0");
  const ss = String(elapsed % 60).padStart(2, "0");

  return (
    <div className="mc-bar">
      <div className="mc-bar-left">
        <span className="mc-apex-badge">APEX</span>
        <span className="mc-target" title={hunt.config.target}>{hunt.config.target}</span>
        <AnimatePresence mode="wait">
          {strategy && (
            <motion.span
              key={strategy}
              className="mc-strategy-badge"
              initial={{ opacity: 0, y: -4 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 4 }}
              transition={{ duration: 0.2 }}
            >
              {STRATEGY_LABELS[strategy] ?? strategy}
            </motion.span>
          )}
        </AnimatePresence>
      </div>

      <div className="mc-metrics">
        <span className="mc-metric">
          <Activity size={11} style={{ color: "#06b6d4" }} />
          <span className="mc-metric-val">{ctx.actionGraph?.length ?? 0}</span>
          <span className="mc-metric-lbl">actions</span>
        </span>
        <span className="mc-metric-sep" />
        <span className="mc-metric">
          <Globe size={11} style={{ color: "#a78bfa" }} />
          <span className="mc-metric-val">{ctx.visitedEndpoints.length}</span>
          <span className="mc-metric-lbl">endpoints</span>
        </span>
        {(critCount > 0 || highCount > 0 || medCount > 0) && <span className="mc-metric-sep" />}
        {critCount > 0 && (
          <span className="mc-metric">
            <span className="mc-sev-dot" style={{ background: "#ef4444" }} />
            <span className="mc-metric-val" style={{ color: "#ef4444" }}>{critCount}</span>
            <span className="mc-metric-lbl">crit</span>
          </span>
        )}
        {highCount > 0 && (
          <span className="mc-metric">
            <span className="mc-sev-dot" style={{ background: "#f97316" }} />
            <span className="mc-metric-val" style={{ color: "#f97316" }}>{highCount}</span>
            <span className="mc-metric-lbl">high</span>
          </span>
        )}
        {medCount > 0 && (
          <span className="mc-metric">
            <span className="mc-sev-dot" style={{ background: "#f59e0b" }} />
            <span className="mc-metric-val" style={{ color: "#f59e0b" }}>{medCount}</span>
            <span className="mc-metric-lbl">med</span>
          </span>
        )}
        {findings.length === 0 && isEnded && (
          <>
            <span className="mc-metric-sep" />
            <span className="mc-metric">
              <CheckCircle2 size={11} style={{ color: "#22c55e" }} />
              <span className="mc-metric-lbl" style={{ color: "#22c55e" }}>No findings</span>
            </span>
          </>
        )}
      </div>

      <div className="mc-bar-right">
        <span className="mc-elapsed"><Clock size={10} /> {mm}:{ss}</span>
        {isRunning && (
          <>
            <motion.span
              className="mc-pulse-dot"
              animate={{ opacity: [1, 0.2, 1] }}
              transition={{ duration: 1.2, repeat: Infinity }}
            />
            <motion.button className="mc-stop-btn" whileTap={{ scale: 0.93 }} onClick={onStop}>
              <Square size={11} /> Emergency Stop
            </motion.button>
          </>
        )}
        {isEnded && (
          <button className="mc-export-btn" onClick={() => onExport(hunt)}>
            <TrendingUp size={11} /> Export Report
          </button>
        )}
      </div>
    </div>
  );
}

// ─── ActionTimeline ───────────────────────────────────────────────────────────

function ActionTimeline({ actions, isRunning }: { actions: AutonomousActionRecord[]; isRunning: boolean }) {
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [actions.length]);

  return (
    <div className="mc-timeline">
      <div className="mc-col-header">
        <Activity size={11} /> Timeline
        {actions.length > 0 && <span className="mc-col-badge">{actions.length}</span>}
      </div>
      <div ref={scrollRef} className="mc-timeline-scroll">
        {actions.length === 0 && isRunning && (
          <div className="mc-tl-empty">
            <motion.span animate={{ opacity: [0.4, 1, 0.4] }} transition={{ duration: 1.5, repeat: Infinity }}>
              Initialising&hellip;
            </motion.span>
          </div>
        )}
        {actions.length === 0 && !isRunning && (
          <div className="mc-tl-empty">No actions yet</div>
        )}
        <div className="mc-tl-track">
          {actions.map((action, i) => {
            const meta   = actionMeta(action.actionType);
            const isLast = i === actions.length - 1;
            return (
              <motion.div
                key={action.id}
                className={`mc-tl-item${isLast && isRunning ? " mc-tl-active" : ""}`}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.18 }}
              >
                <div className="mc-tl-line-col">
                  <motion.div
                    className="mc-tl-dot"
                    style={{
                      background: meta.color,
                      boxShadow: isLast && isRunning ? `0 0 8px ${meta.color}88` : "none",
                    }}
                    animate={isLast && isRunning ? { opacity: [1, 0.4, 1] } : {}}
                    transition={{ duration: 1.1, repeat: Infinity }}
                  />
                  {i < actions.length - 1 && <div className="mc-tl-connector" />}
                </div>
                <div className="mc-tl-content">
                  <div className="mc-tl-row">
                    <span className="mc-tl-idx">#{i + 1}</span>
                    <span className="mc-tl-icon" style={{ color: meta.color }}>{meta.icon}</span>
                    <span className="mc-tl-type">{action.actionType}</span>
                  </div>
                  <div className="mc-tl-sub">
                    <span className="mc-tl-tool">{action.tool}</span>
                    {action.durationMs > 0 && (
                      <span className="mc-tl-dur">{(action.durationMs / 1000).toFixed(1)}s</span>
                    )}
                    {action.findingsCount > 0 && (
                      <span className="mc-tl-findings">{action.findingsCount}</span>
                    )}
                  </div>
                </div>
              </motion.div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// ─── AttackGraph ──────────────────────────────────────────────────────────────

interface GraphNode {
  id:        string;
  label:     string;
  type:      "target" | "endpoint" | "finding";
  url?:      string;
  severity?: string;
  x:         number;
  y:         number;
}

function buildGraph(
  target:    string,
  endpoints: string[],
  findings:  Finding[],
): { nodes: GraphNode[]; edges: [string, string][] } {
  const nodes: GraphNode[] = [];
  const edges: [string, string][] = [];
  const cx = 200, cy = 140;

  nodes.push({ id: "target", label: target.replace(/^https?:\/\//, ""), type: "target", x: cx, y: cy });

  const shown = endpoints.slice(0, 14);
  shown.forEach((ep, i) => {
    const angle = (i / Math.max(shown.length, 1)) * 2 * Math.PI - Math.PI / 2;
    const r  = shown.length <= 6 ? 100 : 88;
    const id = `ep-${i}`;
    nodes.push({ id, label: ep.replace(/^https?:\/\/[^/]+/, "") || "/", type: "endpoint", url: ep, x: cx + r * Math.cos(angle), y: cy + r * Math.sin(angle) });
    edges.push(["target", id]);

    const epFindings = findings.filter(f => f.endpoint && ep && (f.endpoint.startsWith(ep) || ep.startsWith(f.endpoint)));
    epFindings.slice(0, 2).forEach((finding, fi) => {
      const fid    = `f-${i}-${fi}`;
      const fAngle = angle + (fi === 0 ? -0.45 : 0.45);
      nodes.push({ id: fid, label: finding.severity, type: "finding", severity: finding.severity, x: cx + (r + 40) * Math.cos(fAngle), y: cy + (r + 40) * Math.sin(fAngle) });
      edges.push([id, fid]);
    });
  });

  return { nodes, edges };
}

function AttackGraph({ target, endpoints, findings, isRunning }: {
  target:    string;
  endpoints: string[];
  findings:  Finding[];
  isRunning: boolean;
}) {
  const { nodes, edges } = useMemo(
    () => buildGraph(target, endpoints, findings),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [target, endpoints.length, findings.length],
  );
  const nodeMap = useMemo(() => new Map(nodes.map(n => [n.id, n])), [nodes]);

  return (
    <div className="mc-graph-zone">
      <div className="mc-col-header mc-col-header-center">
        <Target size={11} /> Attack Surface
        {endpoints.length > 0 && <span className="mc-col-badge">{endpoints.length} endpoints</span>}
      </div>
      <div className="mc-graph-canvas">
        <svg viewBox="0 0 400 280" preserveAspectRatio="xMidYMid meet" style={{ width: "100%", height: "100%", display: "block" }}>
          <defs>
            <pattern id="mc-dotgrid" x="0" y="0" width="20" height="20" patternUnits="userSpaceOnUse">
              <circle cx="1" cy="1" r="0.7" fill="rgba(99,110,150,0.12)" />
            </pattern>
          </defs>
          <rect width="400" height="280" fill="url(#mc-dotgrid)" />

          {edges.map(([fromId, toId], i) => {
            const from = nodeMap.get(fromId);
            const to   = nodeMap.get(toId);
            if (!from || !to) return null;
            const isFinding = to.type === "finding";
            return (
              <line key={`e-${i}`} x1={from.x} y1={from.y} x2={to.x} y2={to.y}
                stroke={isFinding ? (SEV_COLOR[to.severity ?? "info"] ?? "#555") + "88" : "rgba(99,110,170,0.3)"}
                strokeWidth={isFinding ? 0.8 : 1}
                strokeDasharray={isFinding ? "3 3" : undefined}
              />
            );
          })}

          {nodes.map(node => {
            if (node.type === "target") {
              return (
                <g key={node.id}>
                  {isRunning && (
                    <motion.circle cx={node.x} cy={node.y} r={26}
                      fill="none" stroke="rgba(6,182,212,0.25)" strokeWidth={1.5}
                      animate={{ opacity: [0.6, 0, 0.6] }}
                      transition={{ duration: 2.2, repeat: Infinity }}
                    />
                  )}
                  <circle cx={node.x} cy={node.y} r={13} fill="rgba(6,182,212,0.1)" stroke="#06b6d4" strokeWidth={1.5} />
                  <circle cx={node.x} cy={node.y} r={5} fill="#06b6d4" />
                  <text x={node.x} y={node.y + 24} textAnchor="middle" fontSize={8} fill="rgba(6,182,212,0.85)" fontFamily="monospace">
                    {node.label.length > 20 ? node.label.slice(0, 18) + "\u2026" : node.label}
                  </text>
                </g>
              );
            }

            if (node.type === "endpoint") {
              const epFindings = findings.filter(f => node.url && f.endpoint && (f.endpoint.startsWith(node.url) || node.url.startsWith(f.endpoint)));
              const maxSev = epFindings.reduce((max, f) => {
                const order: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
                return (order[f.severity] ?? 0) > (order[max] ?? 0) ? f.severity : max;
              }, "none");
              const ringColor = maxSev !== "none" ? (SEV_COLOR[maxSev] ?? "rgba(99,110,170,0.5)") : "rgba(99,110,170,0.45)";
              return (
                <motion.g key={node.id} initial={{ opacity: 0, scale: 0.3 }} animate={{ opacity: 1, scale: 1 }} transition={{ type: "spring", stiffness: 280, damping: 22 }}>
                  <circle cx={node.x} cy={node.y} r={6.5} fill="rgba(10,14,26,0.8)" stroke={ringColor} strokeWidth={1.2} />
                  <circle cx={node.x} cy={node.y} r={2.5} fill="rgba(148,163,200,0.55)" />
                  <text x={node.x} y={node.y + 16} textAnchor="middle" fontSize={7} fill="rgba(148,163,200,0.6)" fontFamily="monospace">
                    {node.label.length > 12 ? node.label.slice(0, 10) + "\u2026" : node.label}
                  </text>
                </motion.g>
              );
            }

            if (node.type === "finding") {
              const color = SEV_COLOR[node.severity ?? "info"] ?? "#6b7280";
              return (
                <motion.g key={node.id} initial={{ opacity: 0, scale: 0 }} animate={{ opacity: 1, scale: 1 }} transition={{ type: "spring", stiffness: 320, damping: 18 }}>
                  <circle cx={node.x} cy={node.y} r={5} fill={color + "20"} stroke={color} strokeWidth={1.2} />
                  <text x={node.x} y={node.y + 3} textAnchor="middle" fontSize={6} fill={color} fontFamily="monospace" fontWeight={700}>
                    {(node.severity ?? "").slice(0, 4).toUpperCase()}
                  </text>
                </motion.g>
              );
            }

            return null;
          })}

          {nodes.length <= 1 && (
            <text x={200} y={258} textAnchor="middle" fontSize={10} fill="rgba(99,110,150,0.4)" fontFamily="monospace">
              {isRunning ? "Mapping attack surface\u2026" : "Start a hunt to visualise the attack surface"}
            </text>
          )}
        </svg>
      </div>
    </div>
  );
}

// ─── SeverityBreakdown ────────────────────────────────────────────────────────

function SeverityBreakdown({ findings }: { findings: Finding[] }) {
  const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  findings.forEach(f => { if (f.severity in counts) counts[f.severity]++; });
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  if (total === 0) return null;

  return (
    <div className="mc-sev-breakdown">
      <div className="mc-sev-bar">
        {(["critical", "high", "medium", "low"] as const).map(sev => {
          const pct = (counts[sev] / total) * 100;
          if (pct === 0) return null;
          return <div key={sev} className="mc-sev-segment" style={{ width: `${pct}%`, background: SEV_COLOR[sev] }} title={`${sev}: ${counts[sev]}`} />;
        })}
      </div>
      <div className="mc-sev-legend">
        {(["critical", "high", "medium", "low"] as const).map(sev =>
          counts[sev] > 0 ? (
            <span key={sev} className="mc-sev-legend-item">
              <span className="mc-sev-dot" style={{ background: SEV_COLOR[sev] }} />
              <span style={{ color: SEV_COLOR[sev], fontWeight: 700 }}>{counts[sev]}</span>
              <span className="mc-sev-lbl">{sev}</span>
            </span>
          ) : null
        )}
      </div>
    </div>
  );
}

// ─── ConfidenceArc ────────────────────────────────────────────────────────────

function ConfidenceArc({ score }: { score: number }) {
  const r = 38, cx = 54, cy = 54;
  const startAngle = 225, sweepAngle = 270;
  const pct   = Math.min(100, Math.max(0, score));
  const angle = startAngle + (sweepAngle * pct) / 100;

  function polar(deg: number): [number, number] {
    const rad = ((deg - 90) * Math.PI) / 180;
    return [cx + r * Math.cos(rad), cy + r * Math.sin(rad)];
  }

  function arcPath(from: number, to: number) {
    const [sx, sy] = polar(from);
    const [ex, ey] = polar(to);
    const large = to - from > 180 ? 1 : 0;
    return `M ${sx} ${sy} A ${r} ${r} 0 ${large} 1 ${ex} ${ey}`;
  }

  const color = pct >= 70 ? "#ef4444" : pct >= 40 ? "#f59e0b" : "#06b6d4";

  return (
    <div className="mc-arc-wrap">
      <svg width={108} height={108} style={{ display: "block", margin: "0 auto" }}>
        <path d={arcPath(startAngle, startAngle + sweepAngle)} fill="none" stroke="rgba(99,110,150,0.18)" strokeWidth={6} strokeLinecap="round" />
        {pct > 0 && (
          <>
            {pct >= 60 && <path d={arcPath(startAngle, angle)} fill="none" stroke={color} strokeWidth={10} strokeLinecap="round" opacity={0.18} />}
            <path d={arcPath(startAngle, angle)} fill="none" stroke={color} strokeWidth={6} strokeLinecap="round" />
          </>
        )}
        <text x={cx} y={cy - 3} textAnchor="middle" fontSize={20} fontWeight={800} fill={color} fontFamily="monospace">{pct}</text>
        <text x={cx} y={cy + 13} textAnchor="middle" fontSize={8} fill="rgba(99,110,150,0.65)" fontFamily="monospace" letterSpacing={1}>STOP SCORE</text>
      </svg>
    </div>
  );
}

// ─── IntelPanel ───────────────────────────────────────────────────────────────

function IntelPanel({ hunt }: { hunt: HuntSession }) {
  const ctx         = hunt.context;
  const findings    = ctx.findings ?? [];
  const exploitPaths: ExploitPath[] = ctx.exploitPaths ?? [];

  return (
    <div className="mc-intel-col">
      <div className="mc-col-header"><Shield size={11} /> Intel</div>

      <div className="mc-intel-section">
        <div className="mc-intel-label">STOP SCORE</div>
        <ConfidenceArc score={ctx.terminationScore ?? 0} />
      </div>

      {findings.length > 0 && (
        <div className="mc-intel-section">
          <div className="mc-intel-label">FINDINGS <span className="mc-col-badge">{findings.length}</span></div>
          <SeverityBreakdown findings={findings} />
        </div>
      )}

      {exploitPaths.length > 0 && (
        <div className="mc-intel-section">
          <div className="mc-intel-label">ATTACK PATHS</div>
          <div className="mc-ep-list">
            {exploitPaths.map(ep => (
              <div key={ep.id} className={`mc-ep-card mc-ep-${ep.status}`}>
                <div className="mc-ep-header">
                  <Zap size={10} style={{ color: "#f97316", flexShrink: 0 }} />
                  <span className="mc-ep-title">{ep.title}</span>
                  <span className="mc-ep-status">{ep.status}</span>
                </div>
                <div className="mc-ep-conf">{Math.round(ep.confidence * 100)}% confidence</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {findings.length > 0 && (
        <div className="mc-intel-section mc-intel-findings-section">
          <div className="mc-intel-label">TOP FINDINGS</div>
          <div className="mc-findings-list">
            {findings.slice(0, 10).map((f, i) => (
              <motion.div key={f.id} className="mc-finding-card"
                initial={{ opacity: 0, x: 10 }} animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.04, duration: 0.18 }}>
                <span className={`mc-finding-sev mc-sev-${f.severity}`}>{f.severity}</span>
                <span className="mc-finding-title" title={f.title}>{f.title}</span>
              </motion.div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── ConsoleDrawer ────────────────────────────────────────────────────────────

function ConsoleDrawer({ lines }: { lines: ConsoleLogLine[] }) {
  const [expanded, setExpanded] = useState(false);
  const scrollRef  = useRef<HTMLDivElement>(null);
  const prevLenRef = useRef(lines.length);
  const [flash, setFlash] = useState(false);

  useEffect(() => {
    if (lines.length > prevLenRef.current) {
      setFlash(true);
      const t = setTimeout(() => setFlash(false), 600);
      prevLenRef.current = lines.length;
      return () => clearTimeout(t);
    }
    prevLenRef.current = lines.length;
    return undefined;
  }, [lines.length]);

  useEffect(() => {
    if (expanded && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [lines.length, expanded]);

  return (
    <div className={`mc-console-drawer${expanded ? " mc-console-expanded" : ""}`}>
      <button className={`mc-console-strip${flash ? " mc-console-flash" : ""}`} onClick={() => setExpanded(p => !p)}>
        <Terminal size={11} />
        <span className="mc-console-label">CONSOLE</span>
        {lines.length > 0 && <span className="mc-col-badge">{lines.length} lines</span>}
        <span style={{ marginLeft: "auto", color: "rgba(99,110,150,0.55)", display: "flex", alignItems: "center" }}>
          {expanded ? <ChevronDown size={11} /> : <ChevronUp size={11} />}
        </span>
      </button>
      <AnimatePresence>
        {expanded && (
          <motion.div className="mc-console-body"
            initial={{ height: 0 }} animate={{ height: 200 }} exit={{ height: 0 }}
            transition={{ duration: 0.18, ease: "easeOut" }}
            style={{ overflow: "hidden" }}>
            <div ref={scrollRef} className="mc-console-output">
              {lines.length === 0 && <span className="mc-console-empty">Console output will appear here&hellip;</span>}
              {lines.map(l => (
                <div key={l.id} className={`mc-con-line mc-con-${l.tag}`}>
                  <span className="mc-con-ts">{new Date(l.timestamp).toLocaleTimeString()}</span>
                  <span className="mc-con-tag">[{l.tag}]</span>
                  <span className="mc-con-text">{l.text}</span>
                </div>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// ─── AutonomousPanel ──────────────────────────────────────────────────────────

interface Props {
  hunt:        HuntSession;
  consoleLogs: ConsoleLogLine[];
  onStop:      () => void;
  onExport:    (session: HuntSession) => void;
}

export default function AutonomousPanel({ hunt, consoleLogs, onStop, onExport }: Props) {
  const isRunning = hunt.state === "executing" || hunt.state === "starting";
  const [elapsed, setElapsed] = useState(0);
  const startRef = useRef<number | null>(null);

  useEffect(() => {
    if (isRunning) {
      if (startRef.current === null) startRef.current = Date.now() - elapsed * 1000;
      const id = setInterval(() => {
        setElapsed(Math.floor((Date.now() - (startRef.current ?? Date.now())) / 1000));
      }, 1000);
      return () => clearInterval(id);
    } else if (hunt.state !== "ended") {
      startRef.current = null;
      setElapsed(0);
    }
    return undefined;
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isRunning, hunt.state]);

  const actionGraph: AutonomousActionRecord[] = hunt.context.actionGraph ?? [];

  return (
    <div className="mc-panel">
      <MissionControlBar hunt={hunt} elapsed={elapsed} onStop={onStop} onExport={onExport} />
      <div className="mc-body">
        <ActionTimeline actions={actionGraph} isRunning={isRunning} />
        <AttackGraph
          target={hunt.config.target}
          endpoints={hunt.context.visitedEndpoints}
          findings={hunt.context.findings ?? []}
          isRunning={isRunning}
        />
        <IntelPanel hunt={hunt} />
      </div>
      <ConsoleDrawer lines={consoleLogs} />
    </div>
  );
}
