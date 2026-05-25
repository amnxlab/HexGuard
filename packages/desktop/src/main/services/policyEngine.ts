import type { HuntSessionConfig, PolicyDecision } from "@hexguard/shared";

const blockedPatterns = [/localhost/i, /127\.0\.0\.1/, /192\.168\./, /10\.\d+\.\d+\.\d+/, /intranet/i];

export function validateRunConfig(config: HuntSessionConfig): PolicyDecision {
  if (!config.target.trim()) return { allowed: false, reason: "Target is required." };
  if (blockedPatterns.some(p => p.test(config.target))) {
    return { allowed: false, reason: "Target appears to be a private or local address. Only use explicitly scoped public bug bounty targets." };
  }
  if (config.maxRequestsPerMinute > 120) {
    return { allowed: false, reason: "Request rate exceeds safety cap of 120 req/min." };
  }
  return { allowed: true };
}
