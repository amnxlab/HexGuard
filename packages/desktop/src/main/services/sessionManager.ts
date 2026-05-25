/**
 * sessionManager.ts — Autonomous pipeline-based hunt session state machine.
 *
 * State transitions:
 *   idle → starting → executing (loop through pipeline phases) →
 *   awaiting_decision (for high-risk phase confirmations) → executing → … → ended
 *
 * Low-risk phases run automatically.  High-risk phases (active_probing, deep_scan)
 * pause and emit a confirmation proposal before executing.
 */

import { BrowserWindow } from "electron";
import type {
  ConsoleLogLine,
  DecisionProposal,
  HuntAction,
  HuntSession,
  HuntSessionConfig,
  HuntState,
  RagSearchChunk,
  RunEvent,
  RunMetric,
  ScanPhase,
} from "@hexguard/shared";
import { validateRunConfig } from "./policyEngine";
import {
  nextPhase,
  phaseLabel,
  phaseNeedsConfirmation,
  runReconPhase,
  runFingerprintPhase,
  runPassiveAuditPhase,
  runDiscoveryPhase,
  runAiAnalysisPhase,
  runActiveProbingPhase,
  runDeepScanPhase,
  runVulnAssessmentPhase,
  runExploitationPhase,
  runReportSynthesisPhase,
  type PhaseResult,
} from "../engine/pipelineEngine";

// ─── Module state ─────────────────────────────────────────────────────────────

let currentSession: HuntSession | null = null;
let mainWin: BrowserWindow | null = null;
let autoApproveTimer: ReturnType<typeof setTimeout> | null = null;

// Injected by main/index.ts so the session manager can search project knowledge
type KnowledgeSearchFn = (projectId: string, query: string, limit?: number, sessionId?: string) => Promise<RagSearchChunk[]>;
let searchKnowledge: KnowledgeSearchFn = async () => [];

export function initSessionManager(win: BrowserWindow, searchFn: KnowledgeSearchFn): void {
  mainWin = win;
  searchKnowledge = searchFn;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function nowIso(): string {
  return new Date().toISOString();
}

function makeId(prefix: string): string {
  return `${prefix}-${Date.now()}-${Math.floor(Math.random() * 9999)}`;
}

function pushEvent(level: "info" | "warning" | "error", title: string, detail: string): void {
  if (!currentSession) return;
  const ev: RunEvent = { id: makeId("evt"), timestamp: nowIso(), level, title, detail };
  currentSession.context.events.unshift(ev);
}

function consoleLine(tag: ConsoleLogLine["tag"], text: string): void {
  if (!mainWin || mainWin.isDestroyed()) return;
  const line: ConsoleLogLine = {
    id: makeId("con"),
    timestamp: nowIso(),
    tag,
    text,
    runId: currentSession?.id ?? "none",
  };
  mainWin.webContents.send("hunt:console", line);
}

function emitUpdate(): void {
  if (!mainWin || mainWin.isDestroyed() || !currentSession) return;
  syncMetrics();
  mainWin.webContents.send("hunt:update", currentSession);
}

function setState(s: HuntState): void {
  if (!currentSession) return;
  currentSession.state = s;
}

function syncMetrics(): void {
  if (!currentSession) return;
  const ctx = currentSession.context;
  currentSession.metrics = [
    { label: "Findings",             value: String(ctx.findings.length) },
    { label: "Endpoints",            value: String(ctx.visitedEndpoints.length) },
    { label: "Actions Taken",        value: String(currentSession.history.length) },
    { label: "High/Critical",        value: String(ctx.findings.filter(f => f.severity === "high" || f.severity === "critical").length) },
  ];
}

// ─── Pipeline engine ──────────────────────────────────────────────────────────

/**
 * Advance the pipeline to the next phase.
 * Low-risk phases run immediately; high-risk phases emit a confirmation card.
 *
 * @param confirmed Pass `true` when called immediately after the user confirmed
 *                  a high-risk phase gate — skips the re-check for that phase so
 *                  the phase actually executes instead of looping back to a new
 *                  confirmation card.
 */
async function advancePipeline(confirmed = false): Promise<void> {
  if (!currentSession) return;

  const phase = (currentSession.context.scanPhase ?? "recon") as ScanPhase;

  if (phase === "ended") {
    if (currentSession.state !== "ended") await endHunt();
    return;
  }

  // Pause for confirmation on high-risk phases (unless user just confirmed this phase)
  if (!confirmed && phaseNeedsConfirmation(phase)) {
    currentSession.proposal = makeConfirmationProposal(phase);
    setState("awaiting_decision");
    consoleLine("info", `${phaseLabel(phase)} requires your confirmation before proceeding`);
    emitUpdate();
    return;
  }

  setState("executing");
  emitUpdate();
  consoleLine("info", `[pipeline] ▶ ${phaseLabel(phase)}`);
  const phaseStartMs = Date.now();

  try {
    let result: PhaseResult;
    const ctx = currentSession.context;
    if (!ctx.capturedResponses) ctx.capturedResponses = [];
    const captures = ctx.capturedResponses;

    switch (phase) {
      case "recon":
        result = await runReconPhase(currentSession, consoleLine);
        break;
      case "fingerprint":
        result = await runFingerprintPhase(currentSession, captures, consoleLine);
        break;
      case "passive_audit":
        result = await runPassiveAuditPhase(currentSession, captures, consoleLine);
        break;
      case "discovery":
        result = await runDiscoveryPhase(currentSession, ctx.techFingerprint, consoleLine);
        break;
      case "ai_analysis":
        result = await runAiAnalysisPhase(currentSession, captures, ctx.findings, consoleLine);
        break;
      case "active_probing":
        result = await runActiveProbingPhase(currentSession, ctx.visitedEndpoints, consoleLine);
        break;
      case "deep_scan":
        result = await runDeepScanPhase(currentSession, consoleLine);
        break;
      case "vuln_assessment":
        result = await runVulnAssessmentPhase(currentSession, captures, consoleLine);
        break;
      case "exploitation":
        result = await runExploitationPhase(currentSession, consoleLine);
        break;
      case "report_synthesis":
        result = await runReportSynthesisPhase(currentSession, consoleLine);
        break;
      default:
        result = { findings: [], captures: [], visitedEndpoints: [] };
    }

    // Merge results into session context
    ctx.findings.push(...result.findings);
    ctx.capturedResponses.push(...result.captures);
    const epsBefore = ctx.visitedEndpoints.length;
    const existingEps = new Set(ctx.visitedEndpoints);
    // Primary source: explicit visitedEndpoints from the phase
    for (const ep of result.visitedEndpoints) {
      if (!existingEps.has(ep)) { ctx.visitedEndpoints.push(ep); existingEps.add(ep); }
    }
    // Secondary source: any fetched capture URL that had a non-error response.
    // This ensures active-probing, vuln-assessment etc. contribute to the endpoint list
    // even when they return visitedEndpoints: [].
    for (const cap of result.captures) {
      if (cap.statusCode < 500 && !existingEps.has(cap.url)) {
        ctx.visitedEndpoints.push(cap.url);
        existingEps.add(cap.url);
      }
    }
    if (result.techFingerprint) ctx.techFingerprint = result.techFingerprint;
    if (result.securityAudit)   ctx.securityAudit   = result.securityAudit;

    // Record in history
    const action: HuntAction = {
      id:                 makeId("action"),
      timestamp:          nowIso(),
      chosenOptionId:     `phase-${phase}`,
      chosenOptionTitle:  phaseLabel(phase),
      toolParams:         {
        phase,
        newEndpoints: ctx.visitedEndpoints.length - epsBefore,
        requests:     result.captures.length,
        totalFindings: ctx.findings.length,
        totalEndpoints: ctx.visitedEndpoints.length,
      },
      state:              "completed",
      result:             null,
      durationMs:         Date.now() - phaseStartMs,
      findings:           result.findings,
    };
    currentSession.history.push(action);
    ctx.lastAction = action;

    if (result.findings.length > 0) {
      pushEvent("info", `${phaseLabel(phase)} — ${result.findings.length} finding(s)`, "Phase complete");
    }

    // Advance to next phase and recurse
    ctx.scanPhase = nextPhase(phase);
    emitUpdate();
    setImmediate(() => { void advancePipeline(); });

  } catch (err) {
    consoleLine("err", `Phase ${phase} error: ${String(err)}`);
    pushEvent("error", `${phaseLabel(phase)} failed`, String(err));
    // Skip to next phase on error rather than halting the whole scan
    currentSession.context.scanPhase = nextPhase(phase);
    emitUpdate();
    setImmediate(() => { void advancePipeline(); });
  }
}

function makeConfirmationProposal(phase: ScanPhase): DecisionProposal {
  const findingCount = currentSession?.context.findings.length ?? 0;
  const descriptions: Partial<Record<ScanPhase, string>> = {
    active_probing:  "Tests for XSS reflection, open redirects, and path traversal using crafted HTTP requests.",
    deep_scan:       "Runs sqlmap on discovered endpoints (including form-based) and OWASP ZAP active scan if available.",
    vuln_assessment: "Extracts HTML forms, then fuzzes all inputs with XSS, SQLi, SSRF, traversal, and auth-bypass payloads. Submits real HTTP requests to the target.",
    exploitation:    "Generates proof-of-concept exploits for confirmed high/critical findings via AI, tests for IDOR on numeric-ID endpoints, and checks for session fixation.",
  };
  const durations: Partial<Record<ScanPhase, number>> = {
    active_probing:  120,
    deep_scan:       300,
    vuln_assessment: 240,
    exploitation:    180,
  };
  return {
    id:             `confirm-${phase}-${Date.now()}`,
    timestamp:      nowIso(),
    contextSummary: `Ready to proceed to ${phaseLabel(phase)}. This phase actively probes the target for vulnerabilities.`,
    options: [
      {
        id:                   `proceed-${phase}`,
        rank:                 1,
        title:                `Proceed: ${phaseLabel(phase)}`,
        description:          descriptions[phase] ?? "Runs the next pipeline phase.",
        rationale:            `${findingCount} finding(s) discovered so far. Active testing may reveal additional vulnerabilities.`,
        tool:                 "none" as const,
        toolParams:           { _pipelineAdvance: phase },
        riskLevel:            "high" as const,
        estimatedDurationSec: durations[phase] ?? 180,
      },
      {
        id:                   `skip-${phase}`,
        rank:                 2,
        title:                "Skip — end session",
        description:          "Generate a report from findings discovered so far.",
        rationale:            "You can end the session at any time.",
        tool:                 "none" as const,
        toolParams:           { _skipToEnd: true },
        riskLevel:            "low" as const,
        estimatedDurationSec: 5,
      },
    ],
  };
}



// ─── Public API ───────────────────────────────────────────────────────────────

export async function startHunt(config: HuntSessionConfig): Promise<HuntSession> {
  // Validate target scope
  const policy = validateRunConfig({
    target: config.target,
    scope: config.scope,
    profile: config.profile,
    maxRequestsPerMinute: config.maxRequestsPerMinute,
  });
  if (!policy.allowed) throw new Error(`Policy blocked: ${policy.reason}`);

  if (autoApproveTimer) { clearTimeout(autoApproveTimer); autoApproveTimer = null; }

  const sessionId = makeId("hunt");
  currentSession = {
    id: sessionId,
    state: "starting",
    config,
    context: {
      sessionId,
      target:           config.target,
      findings:         [],
      visitedEndpoints: config.seedPaths ?? [],
      toolResults:      [],
      events:           [],
      phaseHints:       config.seedPaths && config.seedPaths.length > 0 ? ["seed_paths_available"] : [],
      // Pipeline state
      scanPhase:         "recon",
      capturedResponses: [],
    },
    history:  [],
    proposal: null,
    metrics:  [],
  };

  pushEvent("info", "Hunt session started", `Target: ${config.target} | Profile: ${config.profile}`);
  consoleLine("info", `Hunt started — target: ${config.target}`);
  consoleLine("info", "Pipeline: recon → fingerprint → passive_audit → discovery → ai_analysis → (confirm) active_probing → deep_scan");
  emitUpdate();

  // Kick off autonomous pipeline
  setImmediate(() => { void advancePipeline(); });
  return currentSession!;
}

export async function submitDecision(
  optionId: string,
  _overrideParams?: Record<string, unknown>,
): Promise<HuntSession> {
  if (!currentSession) throw new Error("No active hunt session");
  if (currentSession.state !== "awaiting_decision") {
    throw new Error(`Cannot submit decision in state: ${currentSession.state}`);
  }

  if (autoApproveTimer) { clearTimeout(autoApproveTimer); autoApproveTimer = null; }

  const proposal = currentSession.proposal;
  if (!proposal) throw new Error("No active proposal");

  const option = proposal.options.find(o => o.id === optionId);
  if (!option) throw new Error(`Option ${optionId} not found in current proposal`);

  // Skip / end session
  if (
    (option.toolParams as Record<string, unknown>)._skipToEnd ||
    (option.tool === "none" && option.title.toLowerCase().includes("end"))
  ) {
    return endHunt();
  }

  // Pipeline phase confirmation — advance to the confirmed phase
  if ((option.toolParams as Record<string, unknown>)._pipelineAdvance) {
    currentSession.proposal = null;
    setState("executing");
    emitUpdate();
    // Pass confirmed=true so advancePipeline skips the gate for this phase and actually runs it
    await advancePipeline(true);
    return currentSession!;
  }

  // Fallback: unexpected option type — end session gracefully
  consoleLine("warn", `Unexpected option type for submitDecision: ${option.id}`);
  return endHunt();
}

export async function pauseHunt(): Promise<HuntSession> {
  if (!currentSession) throw new Error("No active hunt session");
  if (autoApproveTimer) { clearTimeout(autoApproveTimer); autoApproveTimer = null; }
  setState("paused");
  pushEvent("info", "Session paused", "Resume when ready");
  consoleLine("info", "Hunt paused");
  emitUpdate();
  return currentSession;
}

export async function resumeHunt(): Promise<HuntSession> {
  if (!currentSession) throw new Error("No active hunt session");
  if (currentSession.state !== "paused") throw new Error("Session is not paused");
  consoleLine("info", "Hunt resumed");
  pushEvent("info", "Session resumed", "");
  setImmediate(() => { void advancePipeline(); });
  return currentSession!;
}

export async function endHunt(): Promise<HuntSession> {
  if (!currentSession) throw new Error("No active hunt session");
  if (autoApproveTimer) { clearTimeout(autoApproveTimer); autoApproveTimer = null; }
  setState("ended");
  currentSession.proposal = null;
  pushEvent("info", "Hunt session ended", `${currentSession.context.findings.length} finding(s) · ${currentSession.history.length} action(s) taken`);
  consoleLine("info", "Hunt ended");
  emitUpdate();
  return currentSession;
}

export function getCurrentHunt(): HuntSession | null {
  return currentSession;
}

// ─── Autonomous hunt (Apex profile) ──────────────────────────────────────────

export async function startAutonomousHunt(config: HuntSessionConfig): Promise<HuntSession> {
  if (config.profile !== "autonomous") throw new Error("startAutonomousHunt requires profile === 'autonomous'");

  const policy = validateRunConfig({
    target: config.target,
    scope: config.scope,
    profile: config.profile,
    maxRequestsPerMinute: config.maxRequestsPerMinute,
  });
  if (!policy.allowed) throw new Error(`Policy blocked: ${policy.reason}`);

  if (autoApproveTimer) { clearTimeout(autoApproveTimer); autoApproveTimer = null; }

  const sessionId = makeId("apex");
  currentSession = {
    id: sessionId,
    state: "executing", // No "starting" state — immediately executing
    config,
    context: {
      sessionId,
      target:           config.target,
      findings:         [],
      visitedEndpoints: config.seedPaths ?? [],
      toolResults:      [],
      events:           [],
      phaseHints:       config.seedPaths && config.seedPaths.length > 0 ? ["seed_paths_available"] : [],
      capturedResponses: [],
    },
    history:  [],
    proposal: null,
    metrics:  [],
  };

  pushEvent("info", "Apex autonomous hunt started", `Target: ${config.target}`);
  consoleLine("info", `[apex] Autonomous hunt initialized — target: ${config.target}`);
  emitUpdate();

  // Import here to avoid circular dependency at module load time
  const { startAutonomousHunt: runLoop, stopAutonomousHunt: killLoop } =
    await import("../engine/autonomousEngine.js");

  // Store the kill reference for stopAutonomousHunt()
  _apexKillFn = killLoop;

  // Launch the autonomous loop (non-blocking)
  void runLoop(
    currentSession,
    config,
    consoleLine,
    (updated: HuntSession) => {
      if (currentSession && currentSession.id === updated.id) {
        syncMetrics();
        emitUpdate();
      }
    },
    (ended: HuntSession) => {
      if (currentSession && currentSession.id === ended.id) {
        setState("ended");
        currentSession.proposal = null;
        syncMetrics();
        pushEvent("info", "Apex hunt complete", `${ended.context.findings.length} finding(s) · ${ended.context.actionGraph?.length ?? 0} actions`);
        consoleLine("info", "[apex] Hunt ended");
        emitUpdate();
      }
    },
  );

  return currentSession!;
}

let _apexKillFn: (() => void) | null = null;

export async function stopAutonomousHunt(): Promise<HuntSession> {
  if (!currentSession) throw new Error("No active hunt session");
  if (_apexKillFn) { _apexKillFn(); _apexKillFn = null; }
  setState("ended");
  currentSession.proposal = null;
  pushEvent("info", "Apex hunt stopped (Emergency Stop)", "Partial report may be available");
  consoleLine("warn", "[apex] Emergency stop — hunt terminated by user");
  emitUpdate();
  return currentSession;
}
