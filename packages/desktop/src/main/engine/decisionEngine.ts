/**
 * decisionEngine.ts — RAG-first HITL decision engine.
 *
 * Before every proposal cycle the engine:
 *   1. Searches the project RAG for relevant prior knowledge
 *   2. Forwards context + RAG chunks to HexStrike /api/decision/propose
 *   3. Falls back to local rule-based proposals if HexStrike is unavailable
 *   4. Marks autoApproveOptionId when the top-ranked option is within the
 *      session's autoApproveRisk threshold
 */

import type {
  ActionOption,
  AutoApproveRisk,
  DecisionProposal,
  HuntSessionConfig,
  RagSearchChunk,
  RiskLevel,
  SessionContext,
} from "@hexguard/shared";
import { hexstrikeProposeDecisions } from "../services/mcpClient";

// ─── Risk ordering ────────────────────────────────────────────────────────────

const RISK_ORDER: RiskLevel[] = ["low", "medium", "high", "critical"];

function riskIndex(r: RiskLevel): number {
  return RISK_ORDER.indexOf(r);
}

function isWithinAutoApprove(risk: RiskLevel, threshold: AutoApproveRisk): boolean {
  if (threshold === "none") return false;
  if (threshold === "low")   return riskIndex(risk) <= riskIndex("low");
  if (threshold === "low+medium") return riskIndex(risk) <= riskIndex("medium");
  return false;
}

// ─── Local fallback proposals ────────────────────────────────────────────────

function makeFallbackProposals(context: SessionContext): ActionOption[] {
  const options: ActionOption[] = [];
  const hints = context.phaseHints;
  const hexstrikeRunCount = hints.filter(h => h === "hexstrike_run").length;
  const MAX_HEXSTRIKE_RUNS = 2;

  if (!hints.includes("discovery_done")) {
    options.push({
      id: `opt-ffuf-${Date.now()}`,
      rank: 1,
      title: "Discover endpoints with ffuf",
      description: `Run directory and path fuzzing against ${context.target} to enumerate API surface.`,
      rationale: "No discovery has been performed yet. Endpoint enumeration is always the first step.",
      tool: "ffuf",
      toolParams: { target: context.target },
      riskLevel: "low",
      estimatedDurationSec: 60,
    });
  } else if (!hints.includes("sqlmap_run") && context.visitedEndpoints.length > 0) {
    const endpoint = context.visitedEndpoints[0];
    options.push({
      id: `opt-sqlmap-${Date.now()}`,
      rank: 1,
      title: "Test for SQL injection",
      description: `Run sqlmap against discovered endpoints starting with ${endpoint}.`,
      rationale: `Endpoints discovered (${context.visitedEndpoints.length} found). SQL injection testing is the next logical escalation.`,
      tool: "sqlmap",
      toolParams: { target: endpoint },
      riskLevel: "medium",
      estimatedDurationSec: 120,
    });
  } else if (!hints.includes("zap_run") && context.findings.length > 0) {
    options.push({
      id: `opt-zap-${Date.now()}`,
      rank: 1,
      title: "Validate findings with ZAP",
      description: `Run OWASP ZAP active scan to confirm ${context.findings.length} finding(s).`,
      rationale: "Confirmed findings exist. ZAP validation will reduce false positives and surface additional issues.",
      tool: "zap",
      toolParams: { target: context.target },
      riskLevel: "medium",
      estimatedDurationSec: 180,
    });
  }

  // Only offer HexStrike analysis if it hasn't been run too many times already
  if (hexstrikeRunCount < MAX_HEXSTRIKE_RUNS) {
    options.push({
      id: `opt-hexstrike-${Date.now()}`,
      rank: options.length + 1,
      title: "Ask HexStrike for deeper analysis",
      description: "Run HexStrike intelligence analysis to identify attack vectors and prioritise next steps.",
      rationale: "HexStrike can apply AI reasoning to the current context to surface non-obvious attack paths.",
      tool: "hexstrike",
      toolParams: { target: context.target, mode: "analyze" },
      riskLevel: "low",
      estimatedDurationSec: 30,
    });
  }

  // When hexstrike is saturated (or no other tools remain), make End session rank 1
  const allPhasesComplete =
    hints.includes("discovery_done") &&
    hints.includes("sqlmap_run") &&
    hints.includes("zap_run");
  const hexstrikeSaturated = hexstrikeRunCount >= MAX_HEXSTRIKE_RUNS;

  if (hexstrikeSaturated || allPhasesComplete) {
    // Bump rank to front
    options.push({
      id: `opt-end-${Date.now()}`,
      rank: 1,
      title: "End session and generate report",
      description: "Conclude this hunt session. A comprehensive report will be written to the project knowledge base.",
      rationale: hexstrikeSaturated
        ? `Maximum HexStrike analysis cycles (${MAX_HEXSTRIKE_RUNS}) completed. Review findings and export the report.`
        : "All major scanning phases complete. Review findings and export the report.",
      tool: "none",
      toolParams: {},
      riskLevel: "low",
      estimatedDurationSec: 5,
    });
    // Re-rank remaining options
    for (const o of options) {
      if (o.id !== options[options.length - 1].id) o.rank += 1;
    }
  } else {
    // Normal end option appended at the bottom
    options.push({
      id: `opt-end-${Date.now()}`,
      rank: options.length + 1,
      title: "End session and generate report",
      description: "Conclude this hunt session. A comprehensive report will be written to the project knowledge base.",
      rationale: "You can end the session at any time to review findings.",
      tool: "none",
      toolParams: {},
      riskLevel: "low",
      estimatedDurationSec: 5,
    });
  }

  return options;
}

// ─── Main entry point ─────────────────────────────────────────────────────────

export async function proposeNextActions(
  context: SessionContext,
  config: HuntSessionConfig,
  priorKnowledge: RagSearchChunk[] = [],
): Promise<DecisionProposal> {
  const proposalId = `proposal-${Date.now()}`;
  const timestamp = new Date().toISOString();

  let options: ActionOption[] = [];
  let contextSummary = "";
  let ragChunksUsed: string[] = [];

  if (priorKnowledge.length > 0) {
    ragChunksUsed = [...new Set(priorKnowledge.map(c => c.title))];
  }

  // ── Try HexStrike first ────────────────────────────────────────────────────
  try {
    const hexResult = await hexstrikeProposeDecisions(context, priorKnowledge);
    if (hexResult && hexResult.options && hexResult.options.length > 0) {
      options = hexResult.options;
      contextSummary = hexResult.contextSummary ?? "";
      if (hexResult.ragChunksUsed) ragChunksUsed = hexResult.ragChunksUsed;
    }
  } catch {
    // Fall through to local fallback
  }

  // ── Local fallback ────────────────────────────────────────────────────────
  if (options.length === 0) {
    options = makeFallbackProposals(context);
    const endpointCount = context.visitedEndpoints.length;
    const findingCount = context.findings.length;
    contextSummary = [
      `Target: ${context.target}`,
      endpointCount > 0 ? `${endpointCount} endpoint(s) discovered` : "No endpoints discovered yet",
      findingCount > 0  ? `${findingCount} finding(s) confirmed`     : "No confirmed findings",
      context.phaseHints.length > 0 ? `Phase: ${context.phaseHints.join(", ")}` : "",
      ragChunksUsed.length > 0 ? `\nRelevant prior knowledge consulted: ${ragChunksUsed.join(", ")}` : "",
    ].filter(Boolean).join(" · ");
  }

  // Sort by rank
  options.sort((a, b) => a.rank - b.rank);

  // ── Auto-approve resolution ───────────────────────────────────────────────
  let autoApproveOptionId: string | undefined;
  const top = options[0];
  if (top && isWithinAutoApprove(top.riskLevel, config.autoApproveRisk ?? "none")) {
    autoApproveOptionId = top.id;
  }

  return {
    id: proposalId,
    timestamp,
    contextSummary,
    options,
    autoApproveOptionId,
    ragChunksUsed: ragChunksUsed.length > 0 ? ragChunksUsed : undefined,
  };
}
