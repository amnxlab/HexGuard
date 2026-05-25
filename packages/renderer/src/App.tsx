import React, { useEffect, useRef, useState } from "react";
import { Toaster, toast } from "sonner";
import { TooltipProvider } from "./components/Tooltip";
import CommandPalette from "./components/CommandPalette";
import type {
  AppMode,
  ChatSession,
  GeminiConfig,
  HuntSession,
  HuntSessionConfig,
  PreflightCheck,
  PreflightReport,
  Project,
  ProjectKnowledgeItem,
  ToolHealth
} from "@hexguard/shared";
import Sidebar from "./components/Sidebar";
import Topbar from "./components/Topbar";
import RightRail from "./components/RightRail";
import KnowledgePreview from "./components/KnowledgePreview";
import AskPanel from "./features/ask/AskPanel";
import HuntPanel from "./features/hunt/HuntPanel";
import StartupScreen from "./components/StartupScreen";
import { fallbackProjects, fallbackSessions } from "./lib/sampleData";
import { applyTheme, loadStoredTheme } from "./lib/themes";

const DEFAULT_TOOLS: ToolHealth[] = [
  { id: "mcp-local",   label: "HexStrike Local",   status: "offline",  detail: "Connect hexstrike_server.py to enable" },
  { id: "mcp-remote",  label: "HexStrike Remote",  status: "offline",  detail: "Remote MCP not configured" },
  { id: "local-tools", label: "Local Toolchain",   status: "degraded", detail: "Preview mode — adapters scaffolded" }
];

export default function App() {
  const [mode, setMode]               = useState<AppMode>("ask");
  const [sidebarTab, setSidebarTab]   = useState<"ask" | "auto" | "settings">("ask");
  const [projects, setProjects]       = useState<Project[]>([]);
  const [sessions, setSessions]       = useState<ChatSession[]>([]);
  const [knowledgeItems, setKnowledgeItems] = useState<ProjectKnowledgeItem[]>([]);
  const [showAllKnowledge, setShowAllKnowledge] = useState(false);
  const [previewDoc, setPreviewDoc] = useState<{ title: string; content: string } | null>(null);
  const [activeId, setActiveId]       = useState<string | null>(null);
  const [tools, setTools]             = useState<ToolHealth[]>(DEFAULT_TOOLS);
  const [hunt, setHunt]               = useState<HuntSession | null>(null);
  const [askLoading, setAskLoading]   = useState(false);
  const [theme, setTheme]             = useState<string>(loadStoredTheme);
  const [geminiConfig, setGeminiConfig] = useState<GeminiConfig | null>(null);
  const [cmdOpen, setCmdOpen]         = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const cleanupRef                    = useRef<(() => void) | null>(null);

  // ── Startup preflight ────────────────────────────────────────────────────
  const [appReady, setAppReady]       = useState(false);
  const [preflightReport, setPreflightReport] = useState<PreflightReport>({
    checks: [], allCriticalPass: false,
  });
  const startupCleanupRef = useRef<(() => void) | null>(null);

  useEffect(() => { applyTheme(theme); }, [theme]);

  // Ctrl+K / Cmd+K → command palette
  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if ((e.ctrlKey || e.metaKey) && e.key === "k") {
        e.preventDefault();
        setCmdOpen(prev => !prev);
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  const api = typeof window !== "undefined" ? window.hexguard : undefined;

  // Derived: projectId of the active session — used as an effect dep so that
  // assigning a project to the current session immediately triggers a reload.
  const activeProjectId = sessions.find(s => s.id === activeId)?.projectId ?? null;

  // ── Run preflight on mount ───────────────────────────────────────────────
  useEffect(() => {
    if (!api) {
      // Browser/preview mode — skip preflight, go straight in
      setAppReady(true);
      return;
    }
    // Subscribe to live check updates before invoking runPreflight
    startupCleanupRef.current = api.onStartupUpdate((check: PreflightCheck) => {
      setPreflightReport(prev => {
        const updated = prev.checks.map(c => c.id === check.id ? check : c);
        // If the incoming check id is new, append it
        const exists = prev.checks.some(c => c.id === check.id);
        const checks = exists ? updated : [...prev.checks, check];
        const allCriticalPass = checks.filter(c => c.critical).every(c => c.status === "pass");
        return { checks, allCriticalPass };
      });
    });
    void api.runPreflight().then(async report => {
      setPreflightReport(report);
      // Refresh tool health now that the server has had time to start
      try {
        const t = await api.getToolHealth();
        setTools(t);
      } catch { /* non-fatal */ }
    });
    return () => { startupCleanupRef.current?.(); };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    async function init() {
      if (!api) {
        setProjects(fallbackProjects);
        setSessions(fallbackSessions);
        setActiveId(fallbackSessions[0]?.id ?? null);
        return;
      }
      try {
        const [s, p] = await Promise.all([api.listSessions(), api.listProjects()]);
        setProjects(p);
        setSessions(s);
        setActiveId(s[0]?.id ?? null);
        const currentHunt = api.getCurrentHunt ? await api.getCurrentHunt() : null;
        if (currentHunt) setHunt(currentHunt);

        const gcfg = await api.getGeminiConfig();
        setGeminiConfig(gcfg);
      } catch {
        setProjects(fallbackProjects);
        setSessions(fallbackSessions);
        setActiveId(fallbackSessions[0]?.id ?? null);
      }
      // Tool health is fetched independently so other IPC failures don't mask it
      try {
        const t = await api.getToolHealth();
        setTools(t);
      } catch { /* non-fatal */ }
    }
    void init();
    if (api) { cleanupRef.current = api.onHuntUpdate(updated => setHunt(updated)); }
    // Refresh tool health every 30 s
    let healthTimer: ReturnType<typeof setInterval> | undefined;
    if (api) {
      healthTimer = setInterval(() => {
        void api.getToolHealth().then(t => setTools(t)).catch(() => {});
      }, 30_000);
    }
    return () => { cleanupRef.current?.(); clearInterval(healthTimer); };
  }, []);

  // Reset "show all" mode whenever the active session changes
  useEffect(() => {
    setShowAllKnowledge(false);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeId]);

  // Reload knowledge when session changes, project is (re)assigned, or showAll toggles.
  // activeProjectId in deps ensures this re-runs when handleAssignSessionProject fires.
  useEffect(() => {
    if (!api || !activeId || !activeProjectId) { setKnowledgeItems([]); return; }
    const sessionFilter = showAllKnowledge ? undefined : activeId;
    void api.listProjectKnowledge(activeProjectId, sessionFilter).then(items => {
      setKnowledgeItems(items);
    }).catch(() => setKnowledgeItems([]));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeId, showAllKnowledge, activeProjectId]);

  async function handleRetryHexStrike() {
    if (!api) return;
    await api.retryHexStrike();
    const report = await api.runPreflight();
    setPreflightReport(report);
  }

  // Sync sidebar tab with mode
  function handleModeChange(m: AppMode) {
    setMode(m);
    setSidebarTab(m === "ask" ? "ask" : "auto");
  }

  async function handleNewSession(projectId?: string | null) {
    if (!api) {
      const s: ChatSession = {
        id: `session-preview-${Date.now()}`,
        title: "New Session",
        projectId: projectId ?? null,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        messages: []
      };
      setSessions(prev => [...prev, s]);
      setActiveId(s.id);
      return;
    }
    const s = await api.createSession({ projectId: projectId ?? null });
    setSessions(prev => [...prev, s]);
    setActiveId(s.id);
  }

  async function handleCreateProject(name: string) {
    if (!name?.trim()) return;
    if (!api) {
      const now = new Date().toISOString();
      const p: Project = {
        id: `project-preview-${Date.now()}`,
        name: name.trim(),
        createdAt: now,
        updatedAt: now
      };
      setProjects(prev => [p, ...prev]);
      return;
    }
    const p = await api.createProject({ name: name.trim() });
    setProjects(prev => [p, ...prev]);
  }

  async function handleRenameProject(projectId: string, name: string) {
    if (!api) {
      setSessions(prev => prev); // no-op in preview
      setProjects(prev => prev.map(p => p.id === projectId ? { ...p, name, updatedAt: new Date().toISOString() } : p));
      return;
    }
    const updated = await api.renameProject({ projectId, name });
    setProjects(prev => prev.map(p => p.id === projectId ? updated : p));
  }

  async function handleDeleteProject(projectId: string) {
    if (!api) {
      setProjects(prev => prev.filter(p => p.id !== projectId));
      setSessions(prev => prev.map(s => s.projectId === projectId ? { ...s, projectId: null } : s));
      return;
    }
    await api.deleteProject({ projectId });
    setProjects(prev => prev.filter(p => p.id !== projectId));
    setSessions(prev => prev.map(s => s.projectId === projectId ? { ...s, projectId: null } : s));
  }

  async function handleRenameSession(sessionId: string, title: string) {
    if (!api) {
      setSessions(prev => prev.map(s => s.id === sessionId ? { ...s, title, updatedAt: new Date().toISOString() } : s));
      return;
    }
    const updated = await api.renameSession({ sessionId, title });
    setSessions(prev => prev.map(s => s.id === sessionId ? updated : s));
  }

  async function handleDeleteSession(sessionId: string) {
    setSessions(prev => {
      const remaining = prev.filter(s => s.id !== sessionId);
      if (activeId === sessionId) setActiveId(remaining[0]?.id ?? null);
      return remaining;
    });
    if (api) {
      await api.deleteSession({ sessionId });
    }
  }

  async function handleAssignSessionProject(sessionId: string, projectId: string | null) {
    if (!api) {
      setSessions(prev => prev.map(s => (s.id === sessionId ? { ...s, projectId, updatedAt: new Date().toISOString() } : s)));
      return;
    }
    const updated = await api.assignSessionProject({ sessionId, projectId });
    setSessions(prev => prev.map(s => (s.id === sessionId ? updated : s)));
  }

  async function handleAddKnowledge() {
    const session = sessions.find(s => s.id === activeId);
    const projectId = session?.projectId ?? null;
    if (!projectId || !activeId) return;
    // Open a native file picker scoped to .md files
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".md,text/markdown";
    input.multiple = true;
    input.onchange = async () => {
      const files = Array.from(input.files ?? []);
      if (!files.length) return;
      for (const file of files) {
        const text = await file.text();
        const title = file.name.replace(/\.md$/i, "");
        if (!text.trim()) continue;
        if (!api) {
          setKnowledgeItems(prev => [
            { id: `preview-${Date.now()}`, projectId, sessionId: activeId, title, rawTextPath: "", ragJsonPath: "", charCount: text.length, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() } as ProjectKnowledgeItem,
            ...prev,
          ]);
          continue;
        }
        const item: ProjectKnowledgeItem = await api.ingestProjectKnowledge({
          projectId,
          sessionId: activeId,
          title,
          text: text.trim(),
        });
        setKnowledgeItems(prev => [item, ...prev]);
      }
    };
    input.click();
  }

  async function handleDeleteKnowledge(itemId: string) {
    const session = sessions.find(s => s.id === activeId);
    const projectId = session?.projectId ?? null;
    if (!projectId || !api?.deleteProjectKnowledge) return;
    await api.deleteProjectKnowledge(projectId, itemId);
    setKnowledgeItems(prev => prev.filter(i => i.id !== itemId));
  }

  async function handlePreviewKnowledge(itemId: string, title: string) {
    const session = sessions.find(s => s.id === activeId);
    const projectId = session?.projectId ?? null;
    if (!projectId || !api?.readRawKnowledge) return;
    const content = await api.readRawKnowledge(projectId, itemId);
    setPreviewDoc({ title, content });
  }

  async function handleSend(prompt: string) {
    if (!activeId) return;
    setAskLoading(true);
    try {
      // Auto-update session title from first user message
      setSessions(prev => prev.map(s => {
        if (s.id !== activeId) return s;
        const isFirstUserMsg = !s.messages.some(m => m.role === "user");
        if (!isFirstUserMsg) return s;
        const title = prompt.slice(0, 48) + (prompt.length > 48 ? "…" : "");
        return { ...s, title };
      }));
      if (!api) {
        const userMsg = { id: `user-${Date.now()}`, role: "user" as const, content: prompt, timestamp: new Date().toISOString(), state: "complete" as const };
        const asstMsg = { id: `ast-${Date.now()}`, role: "assistant" as const, content: `Preview mode — no live API.\n\nYou asked: "${prompt}"\n\nLaunch via Electron for real HexStrike responses.`, timestamp: new Date().toISOString(), state: "complete" as const };
        setSessions(prev => prev.map(s => s.id === activeId ? { ...s, messages: [...s.messages, userMsg, asstMsg], updatedAt: new Date().toISOString() } : s));
        return;
      }
      const res = await api.ask({ sessionId: activeId, prompt });
      setSessions(prev => prev.map(s => {
        if (s.id !== activeId) return s;
        const userMsg = { id: `user-${Date.now()}`, role: "user" as const, content: prompt, timestamp: new Date().toISOString(), state: "complete" as const };
        return { ...s, messages: [...s.messages, userMsg, res.message], updatedAt: new Date().toISOString() };
      }));
    } finally {
      setAskLoading(false);
    }
  }

  async function handleStartHunt(cfg: HuntSessionConfig) {
    const configWithProject: HuntSessionConfig = {
      ...cfg,
      projectId: activeSession?.projectId ?? undefined,
    };
    if (!api) {
      toast.error("Hunt mode requires Electron.");
      return;
    }
    if (cfg.profile === "autonomous") {
      const initial = await api.startAutonomousHunt(configWithProject);
      setHunt(initial);
    } else {
      const initial = await api.startHunt(configWithProject);
      setHunt(initial);
    }
  }

  async function handleStopAutonomousHunt() {
    if (!api) return;
    const updated = await api.stopAutonomousHunt();
    setHunt(updated);
  }

  async function handleSubmitDecision(optionId: string, overrideParams?: Record<string, unknown>) {
    if (!api) return;
    const updated = await api.submitDecision(optionId, overrideParams);
    setHunt(updated);
  }

  async function handlePauseHunt() {
    if (!api) return;
    const updated = await api.pauseHunt();
    setHunt(updated);
  }

  async function handleResumeHunt() {
    if (!api) return;
    const updated = await api.resumeHunt();
    setHunt(updated);
  }

  async function handleEndHunt() {
    if (!api) return;
    const updated = await api.endHunt();
    setHunt(updated);
  }

  async function handleGeminiSave(cfg: GeminiConfig) {
    setGeminiConfig(cfg);
    if (api) {
      await api.setGeminiConfig(cfg);
      // Refresh tool health so "Gemini AI" pill goes green
      const t = await api.getToolHealth().catch(() => null);
      if (t) setTools(t);
    }
  }

  async function handleExportReport(session: HuntSession) {
    if (!api) {
      toast.error("Export requires Electron.");
      return;
    }
    try {
      const bundle = await api.exportReport(session, activeId ?? undefined);
      const shortPath = bundle.htmlPath.replace(/.*[\/\\]reports[\/\\]/, "reports/");
      toast.success(`Report opened in browser · ${shortPath}`);
    } catch (e) {
      toast.error(`Export failed: ${String(e)}`);
    }
  }

  async function handleOpenReports() {
    if (!api) {
      toast.error("Open reports folder requires Electron.");
      return;
    }
    try {
      await api.openReportsFolder?.();
    } catch (e) {
      toast.error(`Could not open reports folder: ${String(e)}`);
    }
  }

  const activeSession = sessions.find(s => s.id === activeId) ?? null;
  const activeProject = projects.find(p => p.id === activeSession?.projectId) ?? null;

  if (!appReady) {
    return (
      <StartupScreen
        checks={preflightReport.checks}
        allCriticalPass={preflightReport.allCriticalPass}
        onEnter={() => setAppReady(true)}
        onRetry={handleRetryHexStrike}
      />
    );
 }

  return (
    <TooltipProvider>
    <div className={`app-shell${sidebarCollapsed ? " sidebar-collapsed" : ""}`}>
      <Toaster position="top-right" richColors closeButton />
      <CommandPalette
        open={cmdOpen}
        onClose={() => setCmdOpen(false)}
        sessions={sessions}
        projects={projects}
        onSelectSession={(id) => { setActiveId(id); setCmdOpen(false); }}
        onNewSession={() => { void handleNewSession(); setCmdOpen(false); }}
        onThemeChange={(id) => { setTheme(id); }}
        onExport={hunt?.state === "ended" ? () => { void handleExportReport(hunt); } : undefined}
      />
      <Sidebar
        sidebarTab={sidebarTab}
        onSidebarTab={setSidebarTab}
        mode={mode}
        projects={projects}
        sessions={sessions}
        activeSessionId={activeId}
        tools={tools}
        activeTheme={theme}
        geminiConfig={geminiConfig}
        onModeChange={handleModeChange}
        onSelectSession={(id) => { setActiveId(id); }}
        onCreateSession={handleNewSession}
        onCreateProject={handleCreateProject}
        onRenameSession={handleRenameSession}
        onDeleteSession={handleDeleteSession}
        onRenameProject={handleRenameProject}
        onDeleteProject={handleDeleteProject}
        onMoveSession={handleAssignSessionProject}
        onThemeChange={setTheme}
        onGeminiSave={handleGeminiSave}
      />
      <Topbar
        mode={mode}
        hunt={hunt}
        activeSession={activeSession}
        sidebarCollapsed={sidebarCollapsed}
        onToggleSidebar={() => setSidebarCollapsed(c => !c)}
        onOpenCommandPalette={() => setCmdOpen(true)}
        onOpenReports={handleOpenReports}
      />
      <main className="main-panel">
        {/* Both panels are always mounted — CSS visibility prevents state loss on mode switch */}
        <div style={{ display: mode === "ask" ? "contents" : "none" }}>
          <AskPanel session={activeSession} onSend={handleSend} loading={askLoading} onNewSession={handleNewSession} />
        </div>
        <div style={{ display: mode !== "ask" ? "contents" : "none" }}>
          <HuntPanel
            hunt={hunt}
            toolHealth={tools}
            projectLinked={Boolean(activeSession?.projectId)}
            onStart={handleStartHunt}
            onSubmitDecision={handleSubmitDecision}
            onPause={handlePauseHunt}
            onResume={handleResumeHunt}
            onEnd={handleEndHunt}
            onExport={handleExportReport}
            onStopAutonomous={handleStopAutonomousHunt}
          />
        </div>
      </main>
      <RightRail
        activeSession={activeSession}
        activeProject={activeProject}
        knowledgeItems={knowledgeItems}
        showAllKnowledge={showAllKnowledge}
        onCreateProject={() => { /* triggered from sidebar tree instead */ }}
        onAddKnowledge={handleAddKnowledge}
        onToggleShowAll={() => setShowAllKnowledge(p => !p)}
        onDeleteKnowledge={handleDeleteKnowledge}
        onPreviewKnowledge={handlePreviewKnowledge}
      />
      {previewDoc && (
        <KnowledgePreview
          title={previewDoc.title}
          content={previewDoc.content}
          onClose={() => setPreviewDoc(null)}
        />
      )}
    </div>
    </TooltipProvider>
  );
}
