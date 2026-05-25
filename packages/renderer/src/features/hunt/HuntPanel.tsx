import React, { useEffect, useRef, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Play, Pause, Square, ChevronDown, ChevronRight,
  Shield, Zap, Search, AlertTriangle, BookOpen,
  CheckCircle2, Clock, Target, Activity, Terminal,
} from "lucide-react";
import type {
  ActionOption,
  AutoApproveRisk,
  ConsoleLogLine,
  DecisionProposal,
  HuntSession,
  HuntSessionConfig,
  RiskLevel,
  ScanPhase,
  ToolHealth,
} from "@hexguard/shared";
import AutonomousPanel from "./AutonomousPanel";
import { fadeUp } from "../../lib/motion";

// ─── Phase strip ─────────────────────────────────────────────────────────────

const PHASES: Array<{ id: ScanPhase; label: string; icon: React.ReactNode }> = [
  { id: "recon",            label: "Recon",      icon: <Search size={11} /> },
  { id: "fingerprint",      label: "Fingerprint", icon: <BookOpen size={11} /> },
  { id: "passive_audit",    label: "Passive",    icon: <Shield size={11} /> },
  { id: "discovery",        label: "Discovery",  icon: <Target size={11} /> },
  { id: "ai_analysis",      label: "AI",         icon: <Zap size={11} /> },
  { id: "active_probing",   label: "Active",     icon: <AlertTriangle size={11} /> },
  { id: "deep_scan",        label: "Deep",       icon: <Activity size={11} /> },
  { id: "vuln_assessment",  label: "Vuln",       icon: <AlertTriangle size={11} /> },
  { id: "exploitation",     label: "Exploit",    icon: <Zap size={11} /> },
  { id: "report_synthesis", label: "Report",     icon: <Terminal size={11} /> },
];

const PHASE_ORDER: ScanPhase[] = [
  "recon","fingerprint","passive_audit","discovery",
  "ai_analysis","active_probing","deep_scan",
  "vuln_assessment","exploitation","report_synthesis","ended",
];

function ScanPhaseStrip({ currentPhase }: { currentPhase: ScanPhase | undefined }) {
  if (!currentPhase) return null;
  const currentIdx = PHASE_ORDER.indexOf(currentPhase);

  return (
    <div className="phase-strip">
      {PHASES.map((p, i) => {
        const phaseIdx = PHASE_ORDER.indexOf(p.id);
        const done     = currentIdx > phaseIdx;
        const active   = currentIdx === phaseIdx;
        const cls      = done ? "phase-node done" : active ? "phase-node active" : "phase-node pending";
        return (
          <React.Fragment key={p.id}>
            {i > 0 && <div className={`phase-connector ${done ? "done" : ""}`} />}
            <div className={cls} title={p.label}>
              {done ? (
                <CheckCircle2 size={11} />
              ) : active ? (
                <motion.span
                  animate={{ rotate: 360 }}
                  transition={{ duration: 1.5, repeat: Infinity, ease: "linear" }}
                  style={{ display: "inline-flex" }}
                >
                  {p.icon}
                </motion.span>
              ) : (
                p.icon
              )}
              <span className="phase-node-label">{p.label}</span>
            </div>
          </React.Fragment>
        );
      })}
    </div>
  );
}



function toolIcon(tool: ActionOption["tool"]) {
  const s = 13;
  switch (tool) {
    case "ffuf":      return <Search size={s} />;
    case "sqlmap":    return <AlertTriangle size={s} />;
    case "zap":       return <Shield size={s} />;
    case "hexstrike": return <Zap size={s} />;
    default:          return <CheckCircle2 size={s} />;
  }
}

// ─── DecisionCard ─────────────────────────────────────────────────────────────

function DecisionCard({
  option,
  autoApproveId,
  isExecuting,
  onSelect,
}: {
  option: ActionOption;
  autoApproveId?: string;
  isExecuting: boolean;
  onSelect: (id: string, params?: Record<string, unknown>) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const [paramsJson, setParamsJson] = useState(
    Object.keys(option.toolParams).length > 0 ? JSON.stringify(option.toolParams, null, 2) : ""
  );
  const [paramsError, setParamsError] = useState("");
  const isAutoApprove = option.id === autoApproveId;
  const isTop = option.rank === 1;

  function handleConfirm() {
    let overrides: Record<string, unknown> | undefined;
    if (paramsJson.trim()) {
      try {
        overrides = JSON.parse(paramsJson) as Record<string, unknown>;
        setParamsError("");
      } catch {
        setParamsError("Invalid JSON — fix before confirming");
        return;
      }
    }
    onSelect(option.id, overrides);
  }

  const cardClass = [
    "decision-card",
    isAutoApprove ? "auto-approve" : "",
    isTop ? "rank-1" : "",
  ].filter(Boolean).join(" ");

  return (
    <motion.div className={cardClass} variants={fadeUp} initial="hidden" animate="visible">
      {/* Header row */}
      <div
        className="dc-header"
        onClick={() => !isExecuting && setExpanded(p => !p)}
        style={{ opacity: isExecuting ? 0.55 : 1 }}
      >
        <span className={`dc-rank ${isTop ? "rank-1" : ""}`}>{option.rank}</span>

        <span className={`dc-risk ${option.riskLevel}`}>{option.riskLevel}</span>

        <span className="dc-tool-icon">{toolIcon(option.tool)}</span>

        <span className="dc-title">{option.title}</span>

        <span className="dc-duration"><Clock size={10} /> {option.estimatedDurationSec}s</span>

        {isAutoApprove && <span className="dc-auto-badge">AUTO</span>}

        {!isExecuting && (
          <motion.button
            className="dc-select-btn"
            whileTap={{ scale: 0.92 }}
            onClick={e => { e.stopPropagation(); setExpanded(true); }}
          >
            Select
          </motion.button>
        )}

        <span className="dc-chevron">
          {expanded ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
        </span>
      </div>

      {/* Expanded body */}
      <AnimatePresence>
        {expanded && (
          <motion.div
            className="dc-body"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.16 }}
            style={{ overflow: "hidden" }}
          >
            <p className="dc-description">{option.description}</p>
            <p className="dc-rationale">
              <span>Rationale:</span> {option.rationale}
            </p>

            {option.tool !== "none" && (
              <div>
                <div className="dc-params-label">Tool parameters (editable)</div>
                <textarea
                  className={`dc-params-textarea ${paramsError ? "error" : ""}`}
                  value={paramsJson}
                  onChange={e => setParamsJson(e.target.value)}
                  rows={Math.max(3, Object.keys(option.toolParams).length + 2)}
                />
                {paramsError && <p className="dc-params-error">{paramsError}</p>}
              </div>
            )}

            <div className="dc-actions">
              <motion.button
                className="dc-confirm"
                whileTap={{ scale: 0.93 }}
                onClick={handleConfirm}
                disabled={isExecuting}
              >
                Confirm
              </motion.button>
              <motion.button
                className="dc-cancel"
                whileTap={{ scale: 0.93 }}
                onClick={() => setExpanded(false)}
              >
                Cancel
              </motion.button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

// ─── ProposalView ─────────────────────────────────────────────────────────────

function ProposalView({
  proposal,
  isExecuting,
  onSelect,
}: {
  proposal: DecisionProposal;
  isExecuting: boolean;
  onSelect: (id: string, params?: Record<string, unknown>) => void;
}) {
  return (
    <div>
      {/* Context summary */}
      <div className="hunt-context-box">
        <span className="hunt-context-label">HexStrike</span>
        {proposal.contextSummary}
      </div>

      {/* RAG sources */}
      {proposal.ragChunksUsed && proposal.ragChunksUsed.length > 0 && (
        <div className="hunt-rag-row">
          <BookOpen size={11} />
          <span>Sources consulted:</span>
          {proposal.ragChunksUsed.map(t => (
            <span key={t} className="hunt-rag-badge">{t}</span>
          ))}
        </div>
      )}

      {/* Decision cards */}
      {proposal.options.map(opt => (
        <DecisionCard
          key={opt.id}
          option={opt}
          autoApproveId={proposal.autoApproveOptionId}
          isExecuting={isExecuting}
          onSelect={onSelect}
        />
      ))}
    </div>
  );
}

// ─── ConsoleView ──────────────────────────────────────────────────────────────

function ConsoleView({ lines }: { lines: ConsoleLogLine[] }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [lines.length]);

  return (
    <div ref={ref} className="hunt-console">
      {lines.length === 0 && (
        <span style={{ color: "var(--text3)" }}>Console output will appear here during execution…</span>
      )}
      {lines.map(l => (
        <div key={l.id} className="console-line">
          <span className="console-ts">{new Date(l.timestamp).toLocaleTimeString()}</span>
          <span className={`console-tag ${l.tag}`}>[{l.tag}]</span>
          <span className="console-text">{l.text}</span>
        </div>
      ))}
    </div>
  );
}

// ─── HuntPanel ────────────────────────────────────────────────────────────────

interface Props {
  hunt: HuntSession | null;
  toolHealth: ToolHealth[];
  projectLinked: boolean;
  onStart: (config: HuntSessionConfig) => void;
  onSubmitDecision: (optionId: string, overrideParams?: Record<string, unknown>) => void;
  onPause: () => void;
  onResume: () => void;
  onEnd: () => void;
  onExport: (session: HuntSession) => void;
  onStopAutonomous: () => void;
}

export default function HuntPanel({
  hunt,
  toolHealth,
  projectLinked,
  onStart,
  onSubmitDecision,
  onPause,
  onResume,
  onEnd,
  onExport,
  onStopAutonomous,
}: Props) {
  const [target, setTarget]         = useState("");
  const [scope, setScope]           = useState("");
  const [profile, setProfile]       = useState<HuntSessionConfig["profile"]>("active");
  const [maxRPM, setMaxRPM]         = useState(30);
  const [bearerToken, setBearerToken] = useState("");
  const [autoApprove, setAutoApprove] = useState<AutoApproveRisk>("none");
  const [maxActions, setMaxActions]           = useState(40);
  const [terminationThreshold, setTerminationThreshold] = useState(70);
  const [consoleLogs, setConsoleLogs] = useState<ConsoleLogLine[]>([]);
  const [activeTab, setActiveTab]   = useState<"decisions" | "console">("decisions");
  const api = typeof window !== "undefined" ? window.hexguard : undefined;

  useEffect(() => {
    if (!api?.onHuntConsole) return;
    const unsub = api.onHuntConsole((line) => {
      setConsoleLogs(prev => [...prev.slice(-500), line]);
    });
    return unsub;
  }, [api]);

  const isActive    = hunt && hunt.state !== "idle" && hunt.state !== "ended";
  const isExecuting = hunt?.state === "executing" || hunt?.state === "starting";
  const isPaused    = hunt?.state === "paused";

  function handleStart() {
    if (!target.trim()) return;
    setConsoleLogs([]);
    onStart({
      target: target.trim(),
      scope: scope.trim() || target.trim(),
      profile,
      maxRequestsPerMinute: maxRPM,
      autoApproveRisk: autoApprove,
      bearerToken: bearerToken.trim() || undefined,
      ...(profile === "autonomous" ? { maxActions, terminationThreshold } : {}),
    });
  }

  // Determine status row state
  const statusState =
    hunt?.state === "starting"           ? "starting"  :
    hunt?.state === "executing"          ? "executing" :
    hunt?.state === "paused"             ? "paused"    :
    hunt?.state === "ended"              ? "ended"     : null;

  const statusLabel =
    statusState === "starting"  ? "HexStrike is analysing target and searching knowledge base…" :
    statusState === "executing" ? `Executing: ${hunt?.context.lastAction?.chosenOptionTitle ?? "tool"}…` :
    statusState === "paused"    ? "Session paused — resume when ready to continue." :
    statusState === "ended"     ? `Hunt complete — ${hunt?.context.findings.length ?? 0} finding(s), ${hunt?.history.length ?? 0} action(s).` :
    null;

  return (
    <div className="hunt-layout">
      {/* ── Left config panel ─────────────────────────────────────────── */}
      <div className="hunt-config">
        <div style={{ fontSize: 11, fontWeight: 700, color: "var(--accent)", textTransform: "uppercase", letterSpacing: "0.1em" }}>
          Hunt Session
        </div>

        {/* Tool health */}
        <div className="hunt-health-list">
          {toolHealth.map(t => (
            <div key={t.id} className="hunt-health-item">
              <span className={`hunt-health-dot ${t.status}`} />
              {t.label}
            </div>
          ))}
        </div>

        {/* RAG pill */}
        <div className={`hunt-rag-pill ${projectLinked ? "" : "inactive"}`}>
          <BookOpen size={11} />
          {projectLinked ? "RAG active" : "No project linked — RAG inactive"}
        </div>

        <div style={{ borderTop: "1px solid var(--border)" }} />

        {/* Form */}
        <div className="form-group">
          <label className="form-label">Target URL</label>
          <input
            className="form-input"
            value={target}
            onChange={e => setTarget(e.target.value)}
            disabled={!!isActive}
            placeholder="https://target.example.com"
          />
        </div>

        <div className="form-group">
          <label className="form-label">Scope (regex / path prefix)</label>
          <input
            className="form-input"
            value={scope}
            onChange={e => setScope(e.target.value)}
            disabled={!!isActive}
            placeholder="/api/*"
          />
        </div>

        <div className="form-group">
          <label className="form-label">Profile</label>
          <select
            className="form-select"
            value={profile}
            onChange={e => setProfile(e.target.value as HuntSessionConfig["profile"])}
            disabled={!!isActive}
          >
            <option value="active">Active</option>
            <option value="passive">Passive</option>
            <option value="simulation">Simulation</option>
            <option value="autonomous">Apex (Autonomous)</option>
          </select>
        </div>

        {profile === "autonomous" && (
          <div className="apex-warning">
            <AlertTriangle size={13} />
            <span><strong>Apex mode</strong> gives the AI full unsupervised control. No human approvals will be required.</span>
          </div>
        )}

        {profile === "autonomous" && (
          <div className="form-group">
            <label className="form-label">Max Actions <span className="form-hint">{maxActions}</span></label>
            <input className="form-input" type="range" min={10} max={100} value={maxActions}
              onChange={e => setMaxActions(Number(e.target.value))} disabled={!!isActive} />
          </div>
        )}

        {profile === "autonomous" && (
          <div className="form-group">
            <label className="form-label">Stop Threshold <span className="form-hint">{terminationThreshold}%</span></label>
            <input className="form-input" type="range" min={50} max={90} value={terminationThreshold}
              onChange={e => setTerminationThreshold(Number(e.target.value))} disabled={!!isActive} />
          </div>
        )}

        {profile !== "autonomous" && (
          <div className="form-group">
            <label className="form-label">Max Requests / min</label>
            <input
              className="form-input"
              type="number"
              value={maxRPM}
              onChange={e => setMaxRPM(Math.min(120, Math.max(1, Number(e.target.value))))}
              disabled={!!isActive}
              min={1} max={120}
            />
          </div>
        )}

        <div className="form-group">
          <label className="form-label">Bearer Token (optional)</label>
          <input
            className="form-input"
            type="password"
            value={bearerToken}
            onChange={e => setBearerToken(e.target.value)}
            disabled={!!isActive}
            placeholder="eyJhbGci…"
          />
        </div>

        {profile !== "autonomous" && (
          <div className="form-group">
            <label className="form-label">Auto-approve risk threshold</label>
            <select
              className="form-select"
              value={autoApprove}
              onChange={e => setAutoApprove(e.target.value as AutoApproveRisk)}
              disabled={!!isActive}
            >
              <option value="none">None — always ask</option>
              <option value="low">Low risk — auto-execute</option>
              <option value="low+medium">Low + Medium — auto-execute</option>
            </select>
          </div>
        )}

        <div style={{ borderTop: "1px solid var(--border)" }} />

        {/* Controls */}
        {!isActive && (
          <motion.button
            className="run-btn primary"
            whileTap={{ scale: 0.96 }}
            onClick={handleStart}
            disabled={!target.trim()}
          >
            <Play size={14} /> Start Hunt
          </motion.button>
        )}

        {isActive && !isPaused && (
          <div className="hunt-ctrl-row">
            <motion.button className="hunt-btn" whileTap={{ scale: 0.93 }} onClick={onPause}>
              <Pause size={13} /> Pause
            </motion.button>
            <motion.button className="hunt-btn danger" whileTap={{ scale: 0.93 }} onClick={onEnd}>
              <Square size={12} /> End
            </motion.button>
          </div>
        )}

        {isPaused && (
          <div className="hunt-ctrl-row">
            <motion.button className="hunt-btn success" whileTap={{ scale: 0.93 }} onClick={onResume}>
              <Play size={13} /> Resume
            </motion.button>
            <motion.button className="hunt-btn danger" whileTap={{ scale: 0.93 }} onClick={onEnd}>
              <Square size={12} /> End
            </motion.button>
          </div>
        )}

        {hunt?.state === "ended" && (
          <motion.button className="hunt-btn accent" whileTap={{ scale: 0.93 }} onClick={() => onExport(hunt)}>
            Export Report
          </motion.button>
        )}

        {/* State badge */}
        {hunt && hunt.state !== "idle" && (
          <div className={`run-state-badge ${hunt.state === "awaiting_decision" ? "validating" : hunt.state}`}
            style={{ fontSize: 11 }}>
            <span className="hunt-status-dot" />
            {hunt.state.replace(/_/g, " ")}
          </div>
        )}
      </div>

      {/* ── Right main panel ──────────────────────────────────────────── */}
      <div className="hunt-main">
        {/* Autonomous mode panel (replaces everything below) */}
        {hunt?.config?.profile === "autonomous" ? (
          <AutonomousPanel hunt={hunt} consoleLogs={consoleLogs} onStop={onStopAutonomous} onExport={onExport} />
        ) : (
          <>
        {/* Metrics strip */}
        {hunt && hunt.metrics.length > 0 && (
          <div className="hunt-metrics">
            {hunt.metrics.map(m => (
              <div key={m.label} className="hunt-metric-item">
                <span className="hunt-metric-label">{m.label}</span>
                <span className="hunt-metric-value">{m.value}</span>
              </div>
            ))}
          </div>
        )}

        {/* Phase progress strip */}
        {hunt && (
          <ScanPhaseStrip currentPhase={hunt.context.scanPhase} />
        )}

        {/* Tab bar */}
        <div className="hunt-tabs">
          <button
            className={`hunt-tab ${activeTab === "decisions" ? "active" : ""}`}
            onClick={() => setActiveTab("decisions")}
          >
            <Target size={12} /> Decisions
          </button>
          <button
            className={`hunt-tab ${activeTab === "console" ? "active" : ""}`}
            onClick={() => setActiveTab("console")}
          >
            <Terminal size={12} /> Console
            {consoleLogs.length > 0 && (
              <span className="hunt-tab-badge">{consoleLogs.length}</span>
            )}
          </button>
        </div>

        {/* Content */}
        {activeTab === "decisions" ? (
          <div className="hunt-scroll">
            {/* Status rows */}
            {statusState && statusLabel && (
              <div className={`hunt-status-row ${statusState}`}>
                {statusState !== "ended" ? (
                  <motion.span
                    animate={{ rotate: statusState === "starting" || statusState === "executing" ? 360 : 0 }}
                    transition={{ duration: 1.2, repeat: Infinity, ease: "linear" }}
                  >
                    <Activity size={14} />
                  </motion.span>
                ) : (
                  <CheckCircle2 size={14} />
                )}
                {statusLabel}
              </div>
            )}

            {/* Proposal cards */}
            {hunt?.proposal && (
              <ProposalView
                proposal={hunt.proposal}
                isExecuting={!!isExecuting}
                onSelect={onSubmitDecision}
              />
            )}

            {/* Empty state */}
            {!hunt && (
              <div className="hunt-empty">
                <Target size={32} style={{ color: "var(--border2)", marginBottom: 4 }} />
                <div className="hunt-empty-title">Configure a target and start a hunt session.</div>
                <div className="hunt-empty-sub">
                  HexStrike will propose ranked actions informed by your project knowledge base.
                  You choose what to run — always in control.
                </div>
              </div>
            )}
          </div>
        ) : (
          <ConsoleView lines={consoleLogs} />
        )}
          </>
        )}
      </div>
    </div>
  );
}
