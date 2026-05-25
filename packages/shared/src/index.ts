export type AppMode = "ask" | "hunt";

// ─── Tool Health ──────────────────────────────────────────────────────────────

export interface ToolHealth {
  id: "mcp-local" | "mcp-remote" | "local-tools";
  label: string;
  status: "online" | "offline" | "degraded";
  detail: string;
}

// ─── Chat ─────────────────────────────────────────────────────────────────────

export interface ChatMessage {
  id: string;
  role: "user" | "assistant" | "system";
  content: string;
  timestamp: string;
  state?: "streaming" | "complete";
  /** Who generated this message.
   *  "hexstrike" = actual Gemini LLM response
   *  "hexguard"  = local/hybrid/hardcoded (errors, fallbacks, tool outputs) */
  source?: "hexguard" | "hexstrike";
  /** Which Gemini model produced this reply (only set when source === "hexstrike") */
  model?: string;
  /** Special rendering hint.
   *  "quota"  = Gemini quota/rate-limit — rendered as a prominent amber warning card
   *  "error"  = general server/config error — rendered with a red left border
   *  "normal" = regular message (default, no special treatment) */
  kind?: "quota" | "error" | "normal";
}

export interface ChatSession {
  id: string;
  title: string;
  projectId?: string | null;
  createdAt: string;
  updatedAt: string;
  messages: ChatMessage[];
}

// ─── Projects ─────────────────────────────────────────────────────────────────

export interface Project {
  id: string;
  name: string;
  description?: string;
  createdAt: string;
  updatedAt: string;
}

export interface CreateProjectRequest {
  name: string;
  description?: string;
}

export interface CreateSessionRequest {
  projectId?: string | null;
}

export interface SessionProjectAssignment {
  sessionId: string;
  projectId: string | null;
}

// ─── Knowledge / RAG ──────────────────────────────────────────────────────────

export type KnowledgeSourceType = "manual-text" | "manual-file" | "hunt-report";

export interface IngestProjectKnowledgeRequest {
  projectId: string;
  sessionId?: string;
  title: string;
  text: string;
  sourceType?: KnowledgeSourceType;
  fileType?: string;
}

export interface ProjectKnowledgeItem {
  id: string;
  projectId: string;
  sessionId?: string;
  title: string;
  rawTextPath: string;
  ragJsonPath: string;
  charCount: number;
  createdAt: string;
  updatedAt: string;
  sourceType?: KnowledgeSourceType;
  fileType?: string;
}

export interface RagSearchChunk {
  knowledgeId: string;
  chunkId: string;
  title: string;
  text: string;
  score: number;
}

export interface RagSearchRequest {
  projectId: string;
  sessionId?: string;
  query: string;
  limit?: number;
}

// ─── Ask ──────────────────────────────────────────────────────────────────────

export interface AskRequest {
  sessionId: string;
  prompt: string;
  projectId?: string | null;
  knowledgeContext?: string;
}

export interface AskResponse {
  message: ChatMessage;
  latencyMs: number;
  transport: "local" | "remote";
}

// ─── HexStrike Diagnostics ────────────────────────────────────────────────────

export interface HexStrikeDiagnostics {
  status: "starting" | "running" | "stopped";
  pid: number | null;
  python: string;
  script: string;
  cwd: string;
  lastExitCode: number | null;
  lastSignal: string | null;
  lastError: string | null;
  recentStdout: string[];
  recentStderr: string[];
  launchedAt: string | null;
}

// ─── Events & Logging ─────────────────────────────────────────────────────────

export interface RunEvent {
  id: string;
  timestamp: string;
  level: "info" | "warning" | "error";
  title: string;
  detail: string;
}

export interface RunMetric {
  label: string;
  value: string;
}

export interface ConsoleLogLine {
  id: string;
  timestamp: string;
  tag: "cmd" | "req" | "res" | "out" | "err" | "warn" | "info";
  text: string;
  runId: string;
}

// ─── Policy ───────────────────────────────────────────────────────────────────

export interface PolicyDecision {
  allowed: boolean;
  reason?: string;
}

// ─── Pipeline scan types ──────────────────────────────────────────────────────

export type ScanPhase =
  | "recon"
  | "fingerprint"
  | "passive_audit"
  | "discovery"
  | "ai_analysis"
  | "active_probing"
  | "deep_scan"
  | "vuln_assessment"
  | "exploitation"
  | "report_synthesis"
  | "ended";

export interface ExtractedFormField {
  name: string;
  type: string;
  value: string;
}

export interface ExtractedForm {
  action: string;
  method: "GET" | "POST";
  fields: ExtractedFormField[];
}

export interface ExploitResult {
  findingId: string;
  pocCurl: string;
  pocDescription: string;
  remediationSteps: string[];
  cvssScore: number;
  cvssVector: string;
}

export interface HttpCapture {
  url: string;
  method: string;
  statusCode: number;
  headers: Record<string, string>;
  bodyPreview: string;
  contentType: string;
  timingMs: number;
}

export interface TechFingerprint {
  server?: string;
  language?: string;
  framework?: string;
  cms?: string;
  database?: string;
  waf?: string;
  suggestedWordlist?: string;
  evidence: string[];
  confidence: number;
}

export interface HeaderAuditItem {
  header: string;
  present: boolean;
  value?: string;
  severity: RiskLevel;
  recommendation: string;
}

export interface CorsAuditResult {
  allowsArbitraryOrigins: boolean;
  reflectsOrigin: boolean;
  allowCredentials: boolean;
  severity: RiskLevel;
}

export interface CookieAuditItem {
  name: string;
  missingSecure: boolean;
  missingHttpOnly: boolean;
  sameSite?: string;
  severity: RiskLevel;
}

export interface InfoDisclosureItem {
  header: string;
  value: string;
  severity: RiskLevel;
}

export interface SecurityAuditResult {
  target: string;
  headers: HeaderAuditItem[];
  cors: CorsAuditResult | null;
  cookies: CookieAuditItem[];
  infoDisclosure: InfoDisclosureItem[];
  sensitiveFiles: Array<{ url: string; statusCode: number; severity: RiskLevel }>;
}

// ─── Hunt Session — HITL Decision Engine ──────────────────────────────────────

export type HuntState =
  | "idle"
  | "starting"
  | "awaiting_decision"
  | "executing"
  | "paused"
  | "ended";

export type RiskLevel = "low" | "medium" | "high" | "critical";
export type AutoApproveRisk = "none" | "low" | "low+medium";

// ─── Autonomous Mode Types ────────────────────────────────────────────────────

export type AutonomousActionType =
  | "recon"
  | "enumerate"
  | "fingerprint"
  | "discover"
  | "analyze"
  | "probe"
  | "exploit"
  | "escalate"
  | "validate"
  | "synthesize"
  | "nuclei-scan"
  | "nikto-scan"
  | "h2c-scan"
  | "ssrf-probe"
  | "waf-detect"
  | "deep-sqli";

export type AutonomousStrategy = "recon" | "discover" | "analyze" | "exploit" | "validate" | "synthesize";

export interface AutonomousActionRecord {
  id: string;
  actionType: AutonomousActionType;
  tool: string;
  params: Record<string, unknown>;
  rationale: string;
  aiConfidence: number;   // 0–1
  findingsCount: number;
  durationMs: number;
  timestamp: string;
  parentActionId?: string;
}

export interface ExploitPath {
  id: string;
  title: string;
  steps: string[];
  confidence: number;
  status: "planned" | "in-progress" | "completed" | "abandoned";
}

export interface HexstrikeActionProposal {
  actionType: AutonomousActionType;
  tool: string;
  toolParams: Record<string, unknown>;
  rationale: string;
  aiConfidence: number;   // 0–1
  terminationScore?: number;  // 0–100; ≥threshold means stop
  parentActionId?: string;
  skipIfTried?: boolean;
}

export interface HuntSessionConfig {
  target: string;
  scope: string;
  profile: "active" | "passive" | "simulation" | "autonomous";
  maxRequestsPerMinute: number;
  autoApproveRisk?: AutoApproveRisk;
  projectId?: string | null;
  seedPaths?: string[];
  bearerToken?: string;
  // Autonomous mode options
  maxActions?: number;          // default 40
  terminationThreshold?: number; // 0–100, default 70
}

export interface ActionOption {
  id: string;
  rank: number;
  title: string;
  description: string;
  rationale: string;
  tool: "ffuf" | "sqlmap" | "zap" | "hexstrike" | "none";
  toolParams: Record<string, unknown>;
  riskLevel: RiskLevel;
  estimatedDurationSec: number;
}

export interface DecisionProposal {
  id: string;
  timestamp: string;
  contextSummary: string;
  options: ActionOption[];
  autoApproveOptionId?: string;
  ragChunksUsed?: string[];
}

export interface Finding {
  id: string;
  timestamp: string;
  title: string;
  severity: RiskLevel;
  endpoint: string;
  evidence: string;
  tool: string;
}

export interface PhaseResult {
  findings:         Finding[];
  captures:         HttpCapture[];
  visitedEndpoints: string[];
  techFingerprint?: TechFingerprint;
  securityAudit?:   SecurityAuditResult;
}

export interface HuntAction {
  id: string;
  timestamp: string;
  chosenOptionId: string;
  chosenOptionTitle: string;
  toolParams: Record<string, unknown>;
  state: "pending" | "running" | "completed" | "failed";
  result: ToolAdapterResult | null;
  durationMs?: number;
  findings: Finding[];
}

export interface SessionContext {
  sessionId: string;
  target: string;
  findings: Finding[];
  visitedEndpoints: string[];
  toolResults: Array<{ actionId: string; tool: string; summary: string }>;
  events: RunEvent[];
  phaseHints: string[];
  lastProposal?: DecisionProposal;
  lastAction?: HuntAction;
  // ── Pipeline engine fields ───────────────────────────────────────────────
  scanPhase?: ScanPhase;
  capturedResponses?: HttpCapture[];
  techFingerprint?: TechFingerprint;
  securityAudit?: SecurityAuditResult;
  // ── Autonomous mode fields ───────────────────────────────────────────────
  actionGraph?: AutonomousActionRecord[];
  terminationScore?: number;
  currentStrategy?: AutonomousStrategy;
  exploitPaths?: ExploitPath[];
}

export interface HuntSession {
  id: string;
  state: HuntState;
  config: HuntSessionConfig;
  context: SessionContext;
  history: HuntAction[];
  proposal: DecisionProposal | null;
  metrics: RunMetric[];
}

// ─── Tool Adapter Types ───────────────────────────────────────────────────────

export interface ToolAdapterResult {
  tool: "ffuf" | "sqlmap" | "zap";
  success: boolean;
  exitCode: number;
  error?: string;
  durationMs: number;
}

export interface FfufEndpoint {
  url: string;
  method: string;
  statusCode: number;
  contentLength: number;
  words: number;
  lines: number;
  redirectLocation: string;
}

export interface FfufResult extends ToolAdapterResult {
  tool: "ffuf";
  endpoints: FfufEndpoint[];
  totalRequests: number;
}

export interface SqlmapFinding {
  parameter: string;
  injectionType: string;
  title: string;
  dbms: string;
  confidence: "high" | "medium" | "low";
}

export interface SqlmapResult extends ToolAdapterResult {
  tool: "sqlmap";
  findings: SqlmapFinding[];
  isVulnerable: boolean;
}

export interface ZapAlert {
  alertRef: string;
  name: string;
  risk: "High" | "Medium" | "Low" | "Informational";
  confidence: "High" | "Medium" | "Low" | "False Positive";
  url: string;
  description: string;
  solution: string;
}

export interface ZapScanResult extends ToolAdapterResult {
  tool: "zap";
  alerts: ZapAlert[];
  scanStatus: "running" | "succeeded" | "failed";
}

export interface ToolInvokeRequest {
  tool: "ffuf" | "sqlmap" | "zap";
  target: string;
  wordlistPath?: string;
  extraArgs?: string[];
}

// ─── Gemini AI Config ─────────────────────────────────────────────────────────

export type GeminiModel =
  | "gemini-2.5-flash"
  | "gemini-2.5-flash-lite"
  | "gemini-2.0-flash"
  | "gemini-2.0-flash-lite"
  | "gemini-1.5-flash"
  | "gemini-1.5-flash-8b"
  | "gemini-1.5-pro";

export interface GeminiModelInfo {
  id: GeminiModel;
  label: string;
  description: string;
  rpmLimit: number;
}

export const GEMINI_MODELS: GeminiModelInfo[] = [
  { id: "gemini-2.5-flash",      label: "Gemini 2.5 Flash",       description: "Latest model, best reasoning (recommended)",   rpmLimit: 10 },
  { id: "gemini-2.5-flash-lite", label: "Gemini 2.5 Flash Lite",  description: "Lightweight 2.5-series, high throughput",      rpmLimit: 30 },
  { id: "gemini-2.0-flash",      label: "Gemini 2.0 Flash",       description: "Fast and capable, proven free-tier model",     rpmLimit: 15 },
  { id: "gemini-2.0-flash-lite", label: "Gemini 2.0 Flash Lite",  description: "Ultra-fast, lightest footprint",               rpmLimit: 30 },
  { id: "gemini-1.5-flash",      label: "Gemini 1.5 Flash",       description: "Stable, well-rounded performance",             rpmLimit: 15 },
  { id: "gemini-1.5-flash-8b",   label: "Gemini 1.5 Flash 8B",    description: "Small model, highest token throughput",        rpmLimit: 15 },
  { id: "gemini-1.5-pro",        label: "Gemini 1.5 Pro",         description: "Most capable, 2 RPM free-tier limit",          rpmLimit: 2  },
];

export interface GeminiConfig {
  apiKey: string;
  model: GeminiModel;
}

// ─── Report Types ─────────────────────────────────────────────────────────────

export interface ReportSummary {
  totalEndpoints: number;
  escalated: number;
  confirmed: number;
  chains: number;
  totalRequests: number;
}

export interface ReportBundle {
  runId: string;
  generatedAt: string;
  target: string;
  summary: ReportSummary;
  jsonPath: string;
  htmlPath: string;
}

// ─── Startup / Pre-flight ─────────────────────────────────────────────────────

export type PreflightCheckId = "python" | "hexstrike" | "gemini-cfg" | "ffuf" | "sqlmap" | "zap" | "wafw00f" | "nikto" | "nuclei" | "wapiti" | "h2csmuggler" | "surf";
export type PreflightStatus  = "pending" | "checking" | "pass" | "fail" | "warn";

export interface PreflightCheck {
  id: PreflightCheckId;
  label: string;
  critical: boolean;
  status: PreflightStatus;
  detail: string;
}

export interface PreflightReport {
  checks: PreflightCheck[];
  allCriticalPass: boolean;
}

// ─── Session / Project CRUD ───────────────────────────────────────────────────

export interface RenameSessionRequest {
  sessionId: string;
  title: string;
}

export interface DeleteSessionRequest {
  sessionId: string;
}

export interface RenameProjectRequest {
  projectId: string;
  name: string;
  description?: string;
}

export interface DeleteProjectRequest {
  projectId: string;
}

// ─── API Surface ──────────────────────────────────────────────────────────────

export interface HexguardApi {
  getToolHealth: () => Promise<ToolHealth[]>;
  listProjects: () => Promise<Project[]>;
  createProject: (request: CreateProjectRequest) => Promise<Project>;
  renameProject: (request: RenameProjectRequest) => Promise<Project>;
  deleteProject: (request: DeleteProjectRequest) => Promise<void>;
  listSessions: () => Promise<ChatSession[]>;
  createSession: (request?: CreateSessionRequest) => Promise<ChatSession>;
  assignSessionProject: (request: SessionProjectAssignment) => Promise<ChatSession>;
  renameSession: (request: RenameSessionRequest) => Promise<ChatSession>;
  deleteSession: (request: DeleteSessionRequest) => Promise<void>;
  listProjectKnowledge: (projectId: string, sessionId?: string) => Promise<ProjectKnowledgeItem[]>;
  readRawKnowledge?: (projectId: string, itemId: string) => Promise<string>;
  deleteProjectKnowledge?: (projectId: string, itemId: string) => Promise<void>;
  searchProjectKnowledge?: (request: RagSearchRequest) => Promise<RagSearchChunk[]>;
  ingestProjectKnowledge: (request: IngestProjectKnowledgeRequest) => Promise<ProjectKnowledgeItem>;
  ingestFile?: (projectId: string, filePath: string, title?: string, sessionId?: string) => Promise<ProjectKnowledgeItem>;
  ask: (request: AskRequest) => Promise<AskResponse>;
  // ── Hunt ────────────────────────────────────────────────────────────────────
  startHunt: (config: HuntSessionConfig) => Promise<HuntSession>;
  submitDecision: (optionId: string, overrideParams?: Record<string, unknown>) => Promise<HuntSession>;
  pauseHunt: () => Promise<HuntSession>;
  resumeHunt: () => Promise<HuntSession>;
  endHunt: () => Promise<HuntSession>;
  getCurrentHunt: () => Promise<HuntSession | null>;
  onHuntUpdate: (listener: (session: HuntSession) => void) => () => void;
  onHuntConsole: (listener: (line: ConsoleLogLine) => void) => () => void;
  invokeTool: (request: ToolInvokeRequest) => Promise<ToolAdapterResult>;
  exportReport: (session: HuntSession, chatSessionId?: string) => Promise<ReportBundle>;
  openReportsFolder?: () => Promise<void>;
  /** Transcribe audio locally via the hexstrike Whisper backend.
   *  audioBase64 — base64-encoded audio bytes; mimeType — e.g. "audio/webm"
   *  Returns the transcribed text, or throws if the server is unavailable. */
  transcribeAudio?: (audioBase64: string, mimeType: string) => Promise<string>;
  getGeminiConfig: () => Promise<GeminiConfig | null>;
  setGeminiConfig: (config: GeminiConfig) => Promise<void>;
  runPreflight: () => Promise<PreflightReport>;
  retryHexStrike: () => Promise<void>;
  getHexStrikeDiagnostics?: () => Promise<HexStrikeDiagnostics>;
  onStartupUpdate: (listener: (check: PreflightCheck) => void) => () => void;
  // ── Autonomous hunt ─────────────────────────────────────────────────────────
  startAutonomousHunt: (config: HuntSessionConfig) => Promise<HuntSession>;
  stopAutonomousHunt: () => Promise<HuntSession>;
  // ── HexStrike extended API ──────────────────────────────────────────────────
  hexstrikeSmartScan?: (target: string, objective?: string) => Promise<unknown>;
  hexstrikeAnalyzeTarget?: (target: string) => Promise<unknown>;
  hexstrikeRunTool?: (toolName: string, params: Record<string, unknown>) => Promise<unknown>;
  hexstrikeBugBountyRecon?: (domain: string, scope?: string[]) => Promise<unknown>;
  hexstrikeBugBountyComprehensive?: (domain: string, scope?: string[]) => Promise<unknown>;
  hexstrikeListProcesses?: () => Promise<unknown>;
  hexstrikeTerminateProcess?: (pid: number) => Promise<unknown>;
  hexstrikeTelemetry?: () => Promise<unknown>;
  // ── Window chrome ───────────────────────────────────────────────────────────
  windowMinimize?: () => Promise<void>;
  windowMaximize?: () => Promise<void>;
  windowClose?:    () => Promise<void>;
}
