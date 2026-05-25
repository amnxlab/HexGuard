/**
 * autonomousEngine.ts — the closed-loop AI execution engine for "Apex" mode.
 *
 * Flow:
 *   startAutonomousHunt(session, config, cbs)
 *     → autonomousLoop()
 *       → selectNextAction()  // AI or local fallback
 *       → executeAction()     // delegates to existing phase runners
 *       → merge results → emit update → schedule next iteration
 *     → terminates when:
 *         • selectNextAction returns null
 *         • terminationScore >= threshold
 *         • actionCount >= maxActions
 *         • stopAutonomousHunt() is called (kill flag)
 *
 * No HITL gates.  Emergency Stop is the only human control.
 */

import type {
  AutonomousActionRecord,
  AutonomousStrategy,
  ConsoleLogLine,
  ExploitPath,
  Finding,
  HuntSession,
  HuntSessionConfig,
} from "@hexguard/shared";
import {
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
} from "./pipelineEngine";
import { runNucleiPhase } from "../adapters/nuclei";
import { runNiktoPhase } from "../adapters/nikto";
import { runH2cSmugglerPhase } from "../adapters/h2csmuggler";
import { runSurfPhase } from "../adapters/surf";
import { wapitiAdapter } from "../adapters/wapiti";
import { wafw00fAdapter } from "../adapters/wafw00f";
import { zapAdapter } from "../adapters/zap";
import { RedundancyGuard } from "./redundancyGuard";
import { selectNextAction, deriveStrategy } from "./actionSelector";
import { hexstrikeEvaluateTermination } from "../services/mcpClient";

// ─── Module state (one hunt at a time) ───────────────────────────────────────

let killFlag = false;

export function stopAutonomousHunt(): void {
  killFlag = true;
}

// ─── Tool-name → phase-runner mapping ────────────────────────────────────────

type ConsoleFn = (tag: ConsoleLogLine["tag"], text: string) => void;

async function executeAction(
  tool: string,
  params: Record<string, unknown>,
  session: HuntSession,
  consoleFn: ConsoleFn,
): Promise<PhaseResult> {
  const ctx = session.context;
  if (!ctx.capturedResponses) ctx.capturedResponses = [];
  const captures = ctx.capturedResponses;

  switch (tool) {
    case "http-recon":
      return runReconPhase(session, consoleFn);

    case "tech-fingerprint":
      return runFingerprintPhase(session, captures, consoleFn);

    case "passive-audit":
      return runPassiveAuditPhase(session, captures, consoleFn);

    case "ffuf":
    case "ffuf-deep":
      return runDiscoveryPhase(session, ctx.techFingerprint, consoleFn);

    case "passive-analyze":
    case "ai-analysis":
      return runAiAnalysisPhase(session, captures, ctx.findings, consoleFn);

    case "active-probe":
      return runActiveProbingPhase(session, ctx.visitedEndpoints, consoleFn);

    case "sqlmap":
    case "deep-scan":
      return runDeepScanPhase(session, consoleFn);

    case "nuclei":
    case "nuclei-scan":
      return runNucleiPhase(session, consoleFn);

    case "nikto":
    case "nikto-scan":
      return runNiktoPhase(session, consoleFn);

    case "h2csmuggler":
    case "h2c-scan":
      return runH2cSmugglerPhase(session, consoleFn);

    case "surf":
    case "ssrf-probe":
      return runSurfPhase(session, consoleFn);

    case "wapiti":
    case "wapiti-scan": {
      const outDir = `/tmp/hexguard-wapiti-${Date.now()}`;
      await (await import("node:fs/promises")).mkdir(outDir, { recursive: true });
      const res = await wapitiAdapter.invoke({ target: session.config.target, outputDir: outDir, onConsole: consoleFn });
      await (await import("node:fs/promises")).rm(outDir, { recursive: true, force: true }).catch(() => {});
      const findings: Finding[] = res.findings.map(f => ({
        id:        makeId("finding-wapiti"),
        timestamp: nowIso(),
        title:     `[${f.module}] ${f.info.slice(0, 100)}`,
        severity:  f.severity,
        endpoint:  f.url || session.config.target,
        evidence:  f.info + (f.parameter ? `\nParameter: ${f.parameter}` : "") + (f.wstg ? `\nWSTG: ${f.wstg}` : ""),
        tool:      "wapiti",
      }));
      return { findings, captures: [], visitedEndpoints: [] };
    }

    case "wafw00f":
    case "waf-detect": {
      const outDir = `/tmp/hexguard-waf-${Date.now()}`;
      await (await import("node:fs/promises")).mkdir(outDir, { recursive: true });
      const res = await wafw00fAdapter.invoke({ target: session.config.target, outputDir: outDir, onConsole: consoleFn });
      await (await import("node:fs/promises")).rm(outDir, { recursive: true, force: true }).catch(() => {});
      const findings: Finding[] = res.detected ? [{
        id:        makeId("finding-waf"),
        timestamp: nowIso(),
        title:     `WAF detected: ${res.firewalls.join(", ")}`,
        severity:  "low",
        endpoint:  session.config.target,
        evidence:  `Web Application Firewall (${res.firewalls.join(", ")}) detected. Payloads may be filtered.`,
        tool:      "wafw00f",
      }] : [];
      return { findings, captures: [], visitedEndpoints: [] };
    }

    case "deep-sqli":
      // Run deep scan phase with elevated level/risk injected via session config override
      return runDeepScanPhase(session, consoleFn);

    case "vuln-assessment":
      return runVulnAssessmentPhase(session, captures, consoleFn);

    case "hexstrike-poc":
    case "exploitation":
      return runExploitationPhase(session, consoleFn);

    case "zap": {
      const res = await zapAdapter.invoke({
        target: session.config.target,
        outputDir: `/tmp/hexguard-zap-${Date.now()}`,
        onConsole: consoleFn,
      });
      const riskToSev = (r: string): Finding["severity"] =>
        r === "High" ? "high" : r === "Medium" ? "medium" : "low";
      const findings: Finding[] = res.alerts.map(a => ({
        id:        makeId("finding-zap"),
        timestamp: nowIso(),
        title:     a.name,
        severity:  riskToSev(a.risk),
        endpoint:  a.url || session.config.target,
        evidence:  a.description + (a.solution ? `\nRemediation: ${a.solution}` : ""),
        tool:      "zap",
      }));
      return { findings, captures: [], visitedEndpoints: [] };
    }

    case "report-synthesis":
    default:
      // Unknown or report tool → run vuln assessment as a safe fallback,
      // unless it's explicitly a report synthesize action
      if (tool === "report-synthesis") {
        return runReportSynthesisPhase(session, consoleFn);
      }
      return runVulnAssessmentPhase(session, captures, consoleFn);
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeId(prefix: string): string {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
}

function nowIso(): string {
  return new Date().toISOString();
}

function updateExploitPaths(session: HuntSession, newFindings: Finding[]): void {
  if (!session.context.exploitPaths) session.context.exploitPaths = [];
  const high = newFindings.filter(f => f.severity === "high" || f.severity === "critical");
  for (const f of high) {
    const existing = session.context.exploitPaths.find(p => p.title.includes(f.endpoint));
    if (existing) {
      if (existing.status === "planned") existing.status = "in-progress";
    } else {
      const path: ExploitPath = {
        id:         makeId("path"),
        title:      `${f.severity.toUpperCase()}: ${f.title} @ ${f.endpoint}`,
        steps:      ["Discovered", "Validating", "Exploit PoC"],
        confidence: f.severity === "critical" ? 0.9 : 0.7,
        status:     "in-progress",
      };
      session.context.exploitPaths.push(path);
    }
  }
}

// ─── Main autonomous loop ─────────────────────────────────────────────────────

export async function startAutonomousHunt(
  session: HuntSession,
  config: HuntSessionConfig,
  consoleFn: ConsoleFn,
  emitUpdate: (s: HuntSession) => void,
  onEnded: (s: HuntSession) => void,
): Promise<void> {
  killFlag = false;
  const guard = new RedundancyGuard();
  const maxActions = config.maxActions ?? 40;
  const threshold  = config.terminationThreshold ?? 70;
  let actionCount  = 0;

  // Initialise autonomous-specific context
  session.context.actionGraph      = [];
  session.context.terminationScore = 0;
  session.context.currentStrategy  = "recon";
  session.context.exploitPaths     = [];
  if (!session.context.capturedResponses) session.context.capturedResponses = [];

  consoleFn("info", `[apex] Autonomous hunt started — target: ${config.target}`);
  consoleFn("info", `[apex] Max actions: ${maxActions}, termination threshold: ${threshold}`);
  emitUpdate(session);

  async function autonomousLoop(): Promise<void> {
    // ── Kill-flag check ──────────────────────────────────────────────────────
    if (killFlag) {
      consoleFn("warn", "[apex] Emergency stop received — halting loop");
      await finalise("emergency-stop");
      return;
    }

    // ── Hard limits ──────────────────────────────────────────────────────────
    if (actionCount >= maxActions) {
      consoleFn("info", `[apex] Reached max actions (${maxActions}) — synthesising report`);
      await finalise("max-actions");
      return;
    }
    if ((session.context.terminationScore ?? 0) >= threshold) {
      consoleFn("info", `[apex] Termination score ${session.context.terminationScore} ≥ ${threshold} — complete`);
      await finalise("termination-score");
      return;
    }

    // ── Select next action ───────────────────────────────────────────────────
    const proposal = await selectNextAction(session, guard, config);

    if (!proposal) {
      consoleFn("info", "[apex] AI returned null proposal — assessment complete");
      await finalise("ai-complete");
      return;
    }

    // ── Termination signal via synthesize ────────────────────────────────────
    if (
      proposal.actionType === "synthesize" ||
      (proposal.terminationScore ?? 0) >= threshold
    ) {
      consoleFn("info", `[apex] Strategy: synthesize — ${proposal.rationale}`);
      await finalise("synthesize");
      return;
    }

    // ── Redundancy check ─────────────────────────────────────────────────────
    if (guard.hasTried(proposal.tool, proposal.toolParams)) {
      const stalls = guard.incrementStall();
      consoleFn("warn", `[apex] Tool "${proposal.tool}" already tried (stall #${stalls})`);
      if (stalls >= 3) {
        consoleFn("warn", "[apex] 3 consecutive stalls — forcing synthesis");
        await finalise("stall-limit");
        return;
      }
      // Try again next tick
      setImmediate(() => { void autonomousLoop(); });
      return;
    }

    guard.resetStall();

    // ── Execute action ───────────────────────────────────────────────────────
    const actionId   = makeId("apex");
    const startMs    = Date.now();
    const strategy   = deriveStrategy(session);
    session.context.currentStrategy = strategy as AutonomousStrategy;

    consoleFn("info", `[apex] #${actionCount + 1} → ${proposal.actionType}:${proposal.tool} — ${proposal.rationale}`);

    let result: PhaseResult;
    try {
      result = await executeAction(proposal.tool, proposal.toolParams, session, consoleFn);
    } catch (err) {
      consoleFn("err", `[apex] Action ${proposal.tool} failed: ${String(err)}`);
      result = { findings: [], captures: [], visitedEndpoints: [] };
    }

    // ── Mark tried ───────────────────────────────────────────────────────────
    guard.markTried(proposal.tool, proposal.toolParams);
    actionCount++;

    // ── Merge results ────────────────────────────────────────────────────────
    const ctx = session.context;
    ctx.findings.push(...result.findings);
    ctx.capturedResponses!.push(...result.captures);
    const existingEps = new Set(ctx.visitedEndpoints);
    for (const ep of result.visitedEndpoints) {
      if (!existingEps.has(ep)) { ctx.visitedEndpoints.push(ep); existingEps.add(ep); }
    }
    for (const cap of result.captures) {
      if (cap.statusCode < 500 && !existingEps.has(cap.url)) {
        ctx.visitedEndpoints.push(cap.url);
        existingEps.add(cap.url);
      }
    }
    if (result.techFingerprint) ctx.techFingerprint = result.techFingerprint;
    if (result.securityAudit)   ctx.securityAudit   = result.securityAudit;

    // ── Record in action graph ───────────────────────────────────────────────
    const record: AutonomousActionRecord = {
      id:             actionId,
      actionType:     proposal.actionType,
      tool:           proposal.tool,
      params:         proposal.toolParams,
      rationale:      proposal.rationale,
      aiConfidence:   proposal.aiConfidence,
      findingsCount:  result.findings.length,
      durationMs:     Date.now() - startMs,
      timestamp:      nowIso(),
      parentActionId: proposal.parentActionId,
    };
    if (!ctx.actionGraph) ctx.actionGraph = [];
    ctx.actionGraph.push(record);

    // ── Update exploit paths ─────────────────────────────────────────────────
    updateExploitPaths(session, result.findings);

    // ── Update termination score (async, non-blocking) ───────────────────────
    void (async () => {
      try {
        const score = await hexstrikeEvaluateTermination(session, ctx.actionGraph ?? []);
        ctx.terminationScore = score;
      } catch {
        // Offline — estimate locally from coverage
        const endpointCoverage = Math.min(ctx.visitedEndpoints.length / 20, 1);
        const actionCoverage   = Math.min(actionCount / maxActions, 1);
        ctx.terminationScore   = Math.round((endpointCoverage * 0.6 + actionCoverage * 0.4) * 100);
      }
    })();

    emitUpdate(session);

    // ── Schedule next iteration ──────────────────────────────────────────────
    setImmediate(() => { void autonomousLoop(); });
  }

  // ── Finalise: run report synthesis then signal ended ─────────────────────

  async function finalise(reason: string): Promise<void> {
    consoleFn("info", `[apex] Finalising — reason: ${reason} | actions: ${actionCount} | findings: ${session.context.findings.length}`);
    try {
      const reportResult = await runReportSynthesisPhase(session, consoleFn);
      session.context.findings.push(...reportResult.findings);
    } catch (err) {
      consoleFn("err", `[apex] Report synthesis failed: ${String(err)}`);
    }
    session.context.terminationScore = 100;
    onEnded(session);
  }

  // Kick off the loop
  setImmediate(() => { void autonomousLoop(); });
}
