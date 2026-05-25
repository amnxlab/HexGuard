/**
 * actionSelector.ts — selects the single best next action for the autonomous
 * hunt loop.
 *
 * Primary path: calls HexStrike AI → /api/autonomous/select-action
 * Fallback:     local rule-based priority table (no AI required)
 *
 * Returns null to signal that the loop should terminate.
 */

import type {
  AutonomousActionType,
  AutonomousStrategy,
  HexstrikeActionProposal,
  HuntSession,
  HuntSessionConfig,
} from "@hexguard/shared";
import { hexstrikeSelectNextAction } from "../services/mcpClient";
import { RedundancyGuard } from "./redundancyGuard";

// ─── Local fallback rule table ────────────────────────────────────────────────

interface RulePriority {
  actionType: AutonomousActionType;
  tool: string;
  buildParams: (session: HuntSession) => Record<string, unknown>;
  condition: (session: HuntSession) => boolean;
  rationale: string;
}

const RULE_TABLE: RulePriority[] = [
  // 1. Always start with recon if no captures yet
  {
    actionType: "recon",
    tool:       "http-recon",
    condition:  s => !s.context.capturedResponses || s.context.capturedResponses.length === 0,
    buildParams: s => ({ target: s.config.target }),
    rationale:  "No HTTP data collected yet — starting with basic recon",
  },
  // 2. Fingerprint if no tech fingerprint
  {
    actionType: "fingerprint",
    tool:       "tech-fingerprint",
    condition:  s => !s.context.techFingerprint && (s.context.capturedResponses?.length ?? 0) > 0,
    buildParams: s => ({ target: s.config.target, captures: s.context.capturedResponses?.slice(0, 5) }),
    rationale:  "HTTP responses available but no tech fingerprint — fingerprinting now",
  },
  // 3. Enumerate / discover if fewer than 5 endpoints
  {
    actionType: "discover",
    tool:       "ffuf",
    condition:  s => s.context.visitedEndpoints.length < 5 && (s.context.capturedResponses?.length ?? 0) > 0,
    buildParams: s => ({ target: s.config.target }),
    rationale:  "Few endpoints found — running directory discovery",
  },
  // 4. Passive analysis once we have captures
  {
    actionType: "analyze",
    tool:       "passive-audit",
    condition:  s => (s.context.capturedResponses?.length ?? 0) >= 2 && !s.context.securityAudit,
    buildParams: s => ({ captures: s.context.capturedResponses?.slice(0, 20) }),
    rationale:  "Running passive security audit on captured responses",
  },
  // 5. Active probing if enough endpoints and no high/critical findings yet
  {
    actionType: "probe",
    tool:       "active-probe",
    condition:  s => s.context.visitedEndpoints.length >= 5 &&
      s.context.findings.filter(f => f.severity === "high" || f.severity === "critical").length === 0,
    buildParams: s => ({ endpoints: s.context.visitedEndpoints.slice(0, 10) }),
    rationale:  "Actively probing endpoints for XSS, SSRF, and traversal",
  },
  // 6. Enumerate more deeply if moderate endpoint count
  {
    actionType: "enumerate",
    tool:       "ffuf-deep",
    condition:  s => s.context.visitedEndpoints.length >= 5 && s.context.visitedEndpoints.length < 20,
    buildParams: s => ({ target: s.config.target, wordlist: "medium" }),
    rationale:  "Expanding endpoint enumeration with a larger wordlist",
  },
  // 7. WAF detection early — after fingerprint, before deep scanning
  {
    actionType: "waf-detect",
    tool:       "wafw00f",
    condition:  s => !!s.context.techFingerprint && !s.context.actionGraph?.some(a => a.tool === "wafw00f"),
    buildParams: s => ({ target: s.config.target }),
    rationale:  "Fingerprint available — detecting WAF before deep scanning",
  },
  // 8. Nuclei scan after fingerprint if we have endpoints
  {
    actionType: "nuclei-scan",
    tool:       "nuclei",
    condition:  s => s.context.visitedEndpoints.length >= 2 && !s.context.actionGraph?.some(a => a.tool === "nuclei"),
    buildParams: s => ({ target: s.config.target }),
    rationale:  "Running Nuclei exposure/misconfiguration templates",
  },
  // 9. Deep scan (sqlmap + ZAP + nikto + nuclei) if high/critical findings exist
  {
    actionType: "exploit",
    tool:       "sqlmap",
    condition:  s => s.context.findings.some(f => f.severity === "high" || f.severity === "critical"),
    buildParams: s => {
      const vuln = s.context.findings.find(f => f.severity === "high" || f.severity === "critical");
      return { target: vuln?.endpoint ?? s.config.target };
    },
    rationale:  "Critical/high finding — running targeted SQLi test",
  },
  // 10. Nikto scan in deep phase (parallel with deep-scan above)
  {
    actionType: "nikto-scan",
    tool:       "nikto",
    condition:  s => s.context.visitedEndpoints.length >= 3 && !s.context.actionGraph?.some(a => a.tool === "nikto"),
    buildParams: s => ({ target: s.config.target }),
    rationale:  "Running Nikto web server vulnerability scan",
  },
  // Vuln assessment if we have forms from captures
  {
    actionType: "probe",
    tool:       "vuln-assessment",
    condition:  s => (s.context.capturedResponses?.length ?? 0) >= 3,
    buildParams: s => ({ captures: s.context.capturedResponses?.slice(0, 20) }),
    rationale:  "Running form-based vulnerability assessment",
  },
  // Deep SQLi if an existing SQLi finding needs escalation
  {
    actionType: "deep-sqli",
    tool:       "deep-sqli",
    condition:  s =>
      s.context.findings.some(f => /sql|inject/i.test(f.title)) &&
      !s.context.findings.some(f => f.tool === "sqlmap" && /level=3/i.test(f.evidence ?? "")),
    buildParams: s => {
      const sqli = s.context.findings.find(f => /sql|inject/i.test(f.title));
      return { target: sqli?.endpoint ?? s.config.target, level: 3, risk: 2 };
    },
    rationale:  "SQLi hint found — escalating to deep time-based blind SQLi scan",
  },
  // 9. Escalate — attempt PoC generation if high/critical confirmed
  {
    actionType: "escalate",
    tool:       "hexstrike-poc",
    condition:  s => s.context.findings.filter(f => f.severity === "high" || f.severity === "critical").length >= 2,
    buildParams: s => ({
      findings: s.context.findings.filter(f => f.severity === "high" || f.severity === "critical").slice(0, 3),
    }),
    rationale:  "Multiple high-severity findings — generating PoC exploits",
  },
  // 10. Validate: run ZAP if not yet run
  {
    actionType: "validate",
    tool:       "zap",
    condition:  s => s.context.visitedEndpoints.length >= 5,
    buildParams: s => ({ target: s.config.target }),
    rationale:  "Validating with OWASP ZAP active scan",
  },
];

// ─── Determine current strategy ───────────────────────────────────────────────

export function deriveStrategy(session: HuntSession): AutonomousStrategy {
  const ctx = session.context;
  const highCount = ctx.findings.filter(f => f.severity === "high" || f.severity === "critical").length;
  if (!ctx.capturedResponses || ctx.capturedResponses.length === 0) return "recon";
  if (highCount >= 2) return "exploit";
  if (ctx.visitedEndpoints.length >= 10) return "analyze";
  if (ctx.visitedEndpoints.length >= 5) return "discover";
  return "recon";
}

// ─── Main selector ────────────────────────────────────────────────────────────

export async function selectNextAction(
  session: HuntSession,
  guard: RedundancyGuard,
  config: HuntSessionConfig,
): Promise<HexstrikeActionProposal | null> {
  const ctx = session.context;
  const threshold = config.terminationThreshold ?? 70;

  // Check termination score before doing anything
  if ((ctx.terminationScore ?? 0) >= threshold) {
    return null; // Signal termination
  }

  // Try the AI first
  try {
    const proposal = await hexstrikeSelectNextAction(
      session,
      guard.getExclusions(),
      ctx.actionGraph ?? [],
    );
    if (proposal) {
      // If AI signals termination via terminationScore
      if ((proposal.terminationScore ?? 0) >= threshold) {
        return null;
      }
      // If AI proposes something already tried, check skipIfTried flag
      if (proposal.skipIfTried && guard.hasTried(proposal.tool, proposal.toolParams)) {
        // Fall through to local fallback
      } else {
        return proposal;
      }
    }
  } catch {
    // HexStrike offline — use local fallback
  }

  // Local rule-based fallback
  for (const rule of RULE_TABLE) {
    if (rule.condition(session)) {
      const params = rule.buildParams(session);
      if (!guard.hasTried(rule.tool, params)) {
        return {
          actionType:   rule.actionType,
          tool:         rule.tool,
          toolParams:   params,
          rationale:    rule.rationale,
          aiConfidence: 0.6,
        };
      }
    }
  }

  // All local rules exhausted or tried — synthesize report
  return {
    actionType:        "synthesize",
    tool:              "report-synthesis",
    toolParams:        { reason: "all-rules-exhausted" },
    rationale:         "All reachable test paths have been explored — synthesizing report",
    aiConfidence:      1.0,
    terminationScore:  100,
  };
}
