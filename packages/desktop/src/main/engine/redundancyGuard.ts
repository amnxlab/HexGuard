/**
 * redundancyGuard.ts — prevents the autonomous engine from re-executing the
 * same (tool × target × key-params) combination in a single hunt session.
 *
 * A stable fingerprint is built from the tool name and the sorted set of
 * "significant" params (everything except internal flags).  The guard is
 * created once per autonomous hunt and discarded when the session ends.
 */

const IGNORED_PARAM_KEYS = new Set(["_internal", "_parentActionId", "rationale"]);

function buildFingerprint(tool: string, params: Record<string, unknown>): string {
  const significant: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(params)) {
    if (!IGNORED_PARAM_KEYS.has(k)) significant[k] = v;
  }
  // Sort keys for stable output
  const sortedKeys = Object.keys(significant).sort();
  const canonical = sortedKeys.map(k => `${k}=${JSON.stringify(significant[k])}`).join(";");
  return `${tool}:${canonical}`;
}

export class RedundancyGuard {
  private readonly tried = new Set<string>();
  private stallCount = 0;

  hasTried(tool: string, params: Record<string, unknown>): boolean {
    return this.tried.has(buildFingerprint(tool, params));
  }

  markTried(tool: string, params: Record<string, unknown>): void {
    this.tried.add(buildFingerprint(tool, params));
  }

  /** Called when the AI proposes a tool that was already tried. */
  incrementStall(): number {
    return ++this.stallCount;
  }

  resetStall(): void {
    this.stallCount = 0;
  }

  get stalls(): number {
    return this.stallCount;
  }

  /** Returns an array of fingerprint strings for the AI prompt context. */
  getExclusions(): string[] {
    return [...this.tried];
  }

  size(): number {
    return this.tried.size;
  }
}
