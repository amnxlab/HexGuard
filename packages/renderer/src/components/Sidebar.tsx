import React, { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  MessageCircle, Zap, Settings, Key, Cpu,
  CheckCircle2, XCircle, AlertTriangle,
} from "lucide-react";
import type { AppMode, ChatSession, GeminiConfig, GeminiModel, Project, ToolHealth } from "@hexguard/shared";
import { GEMINI_MODELS } from "@hexguard/shared";
import { THEMES } from "../lib/themes";
import ProjectTree from "./ProjectTree";
import { Tooltip } from "./Tooltip";
import { panelCrossfade } from "../lib/motion";

interface Props {
  sidebarTab: "ask" | "auto" | "settings";
  onSidebarTab: (t: "ask" | "auto" | "settings") => void;
  mode: AppMode;
  projects: Project[];
  sessions: ChatSession[];
  activeSessionId: string | null;
  tools: ToolHealth[];
  activeTheme: string;
  geminiConfig: GeminiConfig | null;
  onModeChange: (m: AppMode) => void;
  onSelectSession: (id: string) => void;
  onCreateSession: (projectId?: string | null) => void;
  onCreateProject: (name: string) => void;
  onRenameSession: (sessionId: string, title: string) => void;
  onDeleteSession: (sessionId: string) => void;
  onRenameProject: (projectId: string, name: string) => void;
  onDeleteProject: (projectId: string) => void;
  onMoveSession: (sessionId: string, projectId: string | null) => void;
  onThemeChange: (id: string) => void;
  onGeminiSave: (cfg: GeminiConfig) => void;
}

export default function Sidebar({ sidebarTab, onSidebarTab, mode, projects, sessions, activeSessionId, tools, activeTheme, geminiConfig, onModeChange, onSelectSession, onCreateSession, onCreateProject, onRenameSession, onDeleteSession, onRenameProject, onDeleteProject, onMoveSession, onThemeChange, onGeminiSave }: Props) {
  const [apiKey, setApiKey] = useState(geminiConfig?.apiKey ?? "");
  const [selectedModel, setSelectedModel] = useState<GeminiModel>(geminiConfig?.model ?? "gemini-2.0-flash");
  const [saveStatus, setSaveStatus] = useState<"idle" | "saved" | "error">("idle");

  // Keep local state in sync whenever the saved config changes externally
  useEffect(() => {
    if (geminiConfig) {
      setApiKey(geminiConfig.apiKey);
      setSelectedModel(geminiConfig.model);
    }
  }, [geminiConfig]);

  const hasUnsavedModel = selectedModel !== (geminiConfig?.model ?? "gemini-2.0-flash");
  const maskedKey = geminiConfig?.apiKey
    ? `••••••${geminiConfig.apiKey.slice(-6)}`
    : null;

  function handleTabClick(tab: "ask" | "auto" | "settings") {
    onSidebarTab(tab);
    if (tab === "ask") onModeChange("ask");
    if (tab === "auto") onModeChange("hunt");
  }

  function handleGeminiSave() {
    const trimmed = apiKey.trim();
    if (!trimmed) { setSaveStatus("error"); return; }
    onGeminiSave({ apiKey: trimmed, model: selectedModel });
    setSaveStatus("saved");
    setTimeout(() => setSaveStatus("idle"), 2500);
  }

  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <img src="/icons/Logo-Emblem.png" alt="HexGuard" className="brand-icon" />
        <div className="brand-text">
          <span className="brand-name">HexGuard Hunt</span>
          <span className="brand-tagline">AI Security Workspace</span>
        </div>
      </div>

      {/* Mode tab bar */}
      <div className="mode-tabs">
        {(["ask", "auto", "settings"] as const).map(tab => {
          const isActive = sidebarTab === tab;
          return (
            <Tooltip
              key={tab}
              content={tab === "ask" ? "Ask Mode" : tab === "auto" ? "Autonomous Mode" : "Settings"}
              side="bottom"
              delay={800}
            >
              <button
                className={`mode-tab${tab === "auto" ? " auto" : ""}${tab === "settings" ? " settings" : ""}${isActive ? " active" : ""}`}
                onClick={() => tab === "settings" ? onSidebarTab("settings") : handleTabClick(tab as "ask" | "auto")}
              >
                {tab === "ask"      && <MessageCircle size={15} strokeWidth={1.7} />}
                {tab === "auto"     && <Zap size={15} strokeWidth={1.7} />}
                {tab === "settings" && <Settings size={15} strokeWidth={1.7} />}
                {tab === "ask" ? "ASK" : tab === "auto" ? "Auto" : "Settings"}
                {isActive && (
                  <motion.div
                    layoutId="tab-pill"
                    className="mode-tab-pill"
                    transition={{ type: "spring", stiffness: 400, damping: 30 }}
                  />
                )}
              </button>
            </Tooltip>
          );
        })}
      </div>

      {/* Project + Session tree */}
      <AnimatePresence mode="wait">
      {sidebarTab !== "settings" && (
        <motion.div key="tree" variants={panelCrossfade} initial="hidden" animate="visible" exit="exit" style={{ display: "contents" }}>
        <ProjectTree
          projects={projects}
          sessions={sessions}
          activeSessionId={activeSessionId}
          onSelectSession={onSelectSession}
          onCreateSession={onCreateSession}
          onCreateProject={onCreateProject}
          onRenameSession={onRenameSession}
          onDeleteSession={onDeleteSession}
          onRenameProject={onRenameProject}
          onDeleteProject={onDeleteProject}
          onMoveSession={onMoveSession}
        />
        </motion.div>
      )}

      {sidebarTab === "settings" && (
        <motion.div key="settings" variants={panelCrossfade} initial="hidden" animate="visible" exit="exit" style={{ display: "contents" }}>
        <div className="sidebar-settings">
          <div className="theme-picker-section">
            <div className="theme-picker-label">Theme</div>
            <div className="theme-swatch-grid">
              {THEMES.map(t => (
                <Tooltip key={t.id} content={t.name} side="top" delay={400}>
                  <motion.button
                    className={`theme-swatch${activeTheme === t.id ? " active" : ""}`}
                    style={{ background: t.swatch, borderColor: activeTheme === t.id ? t.accent : "transparent" }}
                    onClick={() => onThemeChange(t.id)}
                    whileHover={{ scale: 1.06, y: -2 }}
                    whileTap={{ scale: 0.95 }}
                    transition={{ type: "spring", stiffness: 400, damping: 20 }}
                  >
                    <span className="theme-swatch-accent" style={{ background: t.accent }} />
                    {activeTheme === t.id && (
                      <span className="theme-swatch-check">
                        <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3.5" strokeLinecap="round" strokeLinejoin="round">
                          <polyline points="20 6 9 17 4 12" />
                        </svg>
                      </span>
                    )}
                  </motion.button>
                </Tooltip>
              ))}
            </div>
          </div>

          {/* HexStrike AI config */}
          <div className="tool-health-section" style={{ borderTop: "1px solid var(--border)", paddingTop: "1rem", marginTop: "0.25rem" }}>
            <div className="tool-health-label" style={{ marginBottom: "0.75rem" }}>
              HexStrike AI
              {geminiConfig && (
                <span style={{ marginLeft: 6, fontSize: "0.68rem", color: "var(--success, #68d391)", fontWeight: 400 }}>● connected</span>
              )}
            </div>

            {/* Active model indicator */}
            {geminiConfig?.model && (
              <div style={{ display: "flex", alignItems: "center", gap: 5, marginBottom: "0.6rem", fontSize: "0.68rem", color: "var(--text3)" }}>
                <Cpu size={10} />
                <span>Active: <strong style={{ color: "var(--text2)" }}>{geminiConfig.model}</strong></span>
              </div>
            )}

            <div style={{ marginBottom: "0.6rem" }}>
              <label style={{ display: "flex", alignItems: "center", justifyContent: "space-between", fontSize: "0.72rem", color: "var(--text3)", marginBottom: "0.3rem" }}>
                API Key
                {maskedKey && <span style={{ fontFamily: "monospace", color: "var(--text2)", letterSpacing: 1 }}>{maskedKey}</span>}
              </label>
              <input
                type="password"
                autoComplete="off"
                value={apiKey}
                onChange={e => { setApiKey(e.target.value); setSaveStatus("idle"); }}
                placeholder={maskedKey ? "Replace key…" : "AIza…"}
                style={{
                  width: "100%", background: "var(--bg2)", border: "1px solid var(--border)",
                  borderRadius: 6, padding: "5px 8px", color: "var(--text)",
                  fontSize: "0.78rem", fontFamily: "var(--font)", outline: "none",
                }}
              />
            </div>

            <div style={{ marginBottom: "0.75rem" }}>
              <label style={{ display: "flex", alignItems: "center", justifyContent: "space-between", fontSize: "0.72rem", color: "var(--text3)", marginBottom: "0.3rem" }}>
                Model
                {hasUnsavedModel && (
                  <span style={{ display: "inline-flex", alignItems: "center", gap: 3, color: "#f6ad55", fontSize: "0.68rem" }}>
                    <span style={{ width: 6, height: 6, borderRadius: "50%", background: "#f6ad55", display: "inline-block" }} />
                    unsaved
                  </span>
                )}
              </label>
              <select
                value={selectedModel}
                onChange={e => { setSelectedModel(e.target.value as GeminiModel); setSaveStatus("idle"); }}
                style={{
                  width: "100%", background: "var(--bg2)", border: "1px solid var(--border)",
                  borderRadius: 6, padding: "5px 8px", color: "var(--text)",
                  fontSize: "0.78rem", fontFamily: "var(--font)", outline: "none", cursor: "pointer",
                }}
              >
                {GEMINI_MODELS.map(m => (
                  <option key={m.id} value={m.id}>
                    {m.label} ({m.rpmLimit} RPM free)
                  </option>
                ))}
              </select>
              <div style={{ fontSize: "0.68rem", color: "var(--text3)", marginTop: "0.25rem" }}>
                {GEMINI_MODELS.find(m => m.id === selectedModel)?.description}
              </div>
            </div>

            <motion.button
              onClick={handleGeminiSave}
              whileTap={{ scale: 0.97 }}
              style={{
                width: "100%", padding: "6px 0", borderRadius: 7,
                background: saveStatus === "saved" ? "var(--green)" : saveStatus === "error" ? "var(--red)" : "var(--accent2)",
                color: "#fff", border: "none", cursor: "pointer",
                fontSize: "0.78rem", fontWeight: 600, transition: "background .2s",
                display: "flex", alignItems: "center", justifyContent: "center", gap: 6,
              }}
            >
              {saveStatus === "saved" ? <><CheckCircle2 size={13} /> Saved</> : saveStatus === "error" ? <><XCircle size={13} /> API key required</> : <><Key size={13} /> Save &amp; Connect</>}
            </motion.button>
            <div style={{ fontSize: "0.65rem", color: "var(--text3)", marginTop: "0.4rem", textAlign: "center" }}>
              Key stored in local app data only
            </div>
          </div>

          <div className="tool-health-section" style={{ borderTop: "1px solid var(--border)", paddingTop: "1rem", marginTop: "0.25rem" }}>
            <div className="tool-health-label">Tool Status</div>
            {tools.map(t => (
              <Tooltip key={t.id} content={t.detail ?? t.status} side="right">
                <div className="tool-row-full">
                  <div className={`tool-dot ${t.status}`} />
                  <span className="tool-label">{t.label}</span>
                  <span className={`tool-status-pill ${t.status}`}>
                    {t.status === "online" && <CheckCircle2 size={10} />}
                    {t.status === "degraded" && <AlertTriangle size={10} />}
                    {t.status === "offline" && <Cpu size={10} />}
                    {" "}{t.status}
                  </span>
                </div>
              </Tooltip>
            ))}
          </div>
        </div>
        </motion.div>
      )}
      </AnimatePresence>
    </aside>
  );
}
