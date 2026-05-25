import React from "react";
import { motion, AnimatePresence } from "framer-motion";
import { BookOpen, Upload, FileText, Trash2, Link2Off, Layers } from "lucide-react";
import type { ChatSession, Project, ProjectKnowledgeItem } from "@hexguard/shared";
import { fadeUp } from "../lib/motion";

interface Props {
  activeSession: ChatSession | null;
  activeProject: Project | null;
  knowledgeItems: ProjectKnowledgeItem[];
  showAllKnowledge: boolean;
  onCreateProject: () => void;
  onAddKnowledge: () => void;
  onToggleShowAll: () => void;
  onDeleteKnowledge?: (itemId: string) => void;
  onPreviewKnowledge?: (itemId: string, title: string) => void;
}

export default function RightRail({
  activeSession,
  activeProject,
  knowledgeItems,
  showAllKnowledge,
  onCreateProject,
  onAddKnowledge,
  onToggleShowAll,
  onDeleteKnowledge,
  onPreviewKnowledge,
}: Props) {
  const hasProject = Boolean(activeSession?.projectId && activeProject);
  const sessionLabel = activeSession?.title ?? "No session";

  return (
    <aside className="right-rail">
      <div className="rail-title-bar">
        <span style={{ display: "flex", alignItems: "center", gap: 7 }}>
          <BookOpen size={14} strokeWidth={1.7} /> Knowledge
        </span>
      </div>
      <div className="rail-body">
        <div className="rail-section-title" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <span>{showAllKnowledge ? "All Project RAG Docs" : "Session RAG Docs"}</span>
          <motion.button
            className="rail-mini-btn"
            title={showAllKnowledge ? "Show current session only" : "Show all project docs"}
            onClick={onToggleShowAll}
            whileTap={{ scale: 0.92 }}
            style={{ display: "flex", alignItems: "center", gap: 4, opacity: showAllKnowledge ? 1 : 0.6 }}
          >
            <Layers size={10} /> {showAllKnowledge ? "All" : "Session"}
          </motion.button>
        </div>
        {!activeSession && (
          <motion.div className="rail-empty" style={{ padding: "12px 10px" }} variants={fadeUp} initial="hidden" animate="visible">
            No active session.
          </motion.div>
        )}

        {activeSession && !hasProject && (
          <motion.div className="rail-empty" style={{ padding: "12px 10px", display: "flex", flexDirection: "column", gap: 6 }} variants={fadeUp} initial="hidden" animate="visible">
            <span style={{ display: "flex", alignItems: "center", gap: 5, opacity: 0.6 }}>
              <Link2Off size={12} /> Not linked to a project
            </span>
            <span style={{ fontSize: 11, opacity: 0.5 }}>Assign this session to a project in the sidebar to enable RAG docs.</span>
          </motion.div>
        )}

        {activeSession && hasProject && (
          <div className="rail-project-card">
            <div className="rail-project-head">
              <div className="rail-project-body">
                <div className="rail-project-name" title={sessionLabel} style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {sessionLabel}
                </div>
                <div className="rail-project-meta">
                  {activeProject!.name} · {knowledgeItems.length} doc{knowledgeItems.length !== 1 ? "s" : ""}{showAllKnowledge ? " (all)" : " (session)"}
                </div>
              </div>
            </div>

            <AnimatePresence>
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: "auto", opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: 0.2 }}
                style={{ overflow: "hidden" }}
              >
                {knowledgeItems.length > 0 && (
                  <div className="rail-knowledge-list">
                    {knowledgeItems.map(item => (
                      <div key={item.id} className="rail-knowledge-item">
                        <button
                          className="rail-knowledge-open"
                          onClick={() => onPreviewKnowledge?.(item.id, item.title)}
                          title={`Preview: ${item.title}`}
                        >
                          <FileText size={11} style={{ flexShrink: 0, opacity: 0.7 }} />
                          <span className="rail-knowledge-title">{item.title}</span>
                        </button>
                        <button
                          className="rail-knowledge-delete"
                          onClick={() => onDeleteKnowledge?.(item.id)}
                          title="Delete"
                        >
                          <Trash2 size={11} />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
                <div className="rail-project-actions">
                  <motion.button
                    className="rail-mini-btn"
                    onClick={onAddKnowledge}
                    whileTap={{ scale: 0.92 }}
                    style={{ display: "flex", alignItems: "center", gap: 4 }}
                  >
                    <Upload size={11} /> Import .md
                  </motion.button>
                </div>
              </motion.div>
            </AnimatePresence>
          </div>
        )}
      </div>
    </aside>
  );
}

