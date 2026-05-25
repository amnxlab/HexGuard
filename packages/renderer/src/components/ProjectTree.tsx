import React, { useMemo, useState, useRef, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import {
  Search, X, ChevronRight, ChevronDown, Folder, Plus,
  Pencil, Trash2, MoveRight, FolderPlus, MoreHorizontal,
} from "lucide-react";
import type { ChatSession, Project } from "@hexguard/shared";
import { fadeUp, staggerFast } from "../lib/motion";

interface Props {
  projects: Project[];
  sessions: ChatSession[];
  activeSessionId: string | null;
  onSelectSession: (id: string) => void;
  onCreateSession: (projectId?: string | null) => void;
  onCreateProject: (name: string) => void;
  onRenameSession: (sessionId: string, title: string) => void;
  onDeleteSession: (sessionId: string) => void;
  onRenameProject: (projectId: string, name: string) => void;
  onDeleteProject: (projectId: string) => void;
  onMoveSession: (sessionId: string, projectId: string | null) => void;
}

function relativeTime(iso: string): string {
  try {
    const diff = Date.now() - new Date(iso).getTime();
    const m = Math.floor(diff / 60000);
    if (m < 1) return "now";
    if (m < 60) return `${m}m`;
    const h = Math.floor(m / 60);
    if (h < 24) return `${h}h`;
    return `${Math.floor(h / 24)}d`;
  } catch { return ""; }
}

function initial(title: string): string {
  return title.charAt(0).toUpperCase();
}

export default function ProjectTree({
  projects,
  sessions,
  activeSessionId,
  onSelectSession,
  onCreateSession,
  onCreateProject,
  onRenameSession,
  onDeleteSession,
  onRenameProject,
  onDeleteProject,
  onMoveSession,
}: Props) {
  const [search, setSearch] = useState("");
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});

  // Inline rename state
  const [renamingId, setRenamingId] = useState<string | null>(null);
  const [renameVal, setRenameVal] = useState("");
  const renameInputRef = useRef<HTMLInputElement>(null);

  // Delete confirmation state
  const [confirmId, setConfirmId] = useState<string | null>(null);
  const [confirmType, setConfirmType] = useState<"session" | "project">("session");

  // New project inline input
  const [addingProject, setAddingProject] = useState(false);
  const [newProjectName, setNewProjectName] = useState("");
  const newProjectRef = useRef<HTMLInputElement>(null);

  // Move session dropdown
  const [moveSessionId, setMoveSessionId] = useState<string | null>(null);

  useEffect(() => {
    if (renamingId && renameInputRef.current) renameInputRef.current.focus();
  }, [renamingId]);

  useEffect(() => {
    if (addingProject && newProjectRef.current) newProjectRef.current.focus();
  }, [addingProject]);

  const q = search.toLowerCase();

  const { byProject, uncategorized } = useMemo(() => {
    const map = new Map<string, ChatSession[]>();
    for (const p of projects) map.set(p.id, []);
    const unc: ChatSession[] = [];

    for (const s of sessions) {
      const matchesSearch = !q || s.title.toLowerCase().includes(q);
      if (!matchesSearch) continue;
      if (s.projectId && map.has(s.projectId)) {
        map.get(s.projectId)!.push(s);
      } else {
        unc.push(s);
      }
    }

    const sort = (arr: ChatSession[]) =>
      [...arr].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));

    for (const [id, list] of map) map.set(id, sort(list));
    return { byProject: map, uncategorized: sort(unc) };
  }, [projects, sessions, q]);

  // When searching, only show projects that match name or have matching sessions
  const visibleProjects = q
    ? projects.filter(
        p => p.name.toLowerCase().includes(q) || (byProject.get(p.id)?.length ?? 0) > 0
      )
    : projects;

  function toggleCollapse(id: string) {
    setCollapsed(prev => ({ ...prev, [id]: !prev[id] }));
  }

  function startRename(id: string, current: string) {
    setConfirmId(null);
    setMoveSessionId(null);
    setRenamingId(id);
    setRenameVal(current);
  }

  function commitRename(type: "session" | "project") {
    if (!renamingId) return;
    const trimmed = renameVal.trim();
    if (trimmed) {
      if (type === "session") onRenameSession(renamingId, trimmed);
      else onRenameProject(renamingId, trimmed);
    }
    setRenamingId(null);
  }

  function requestDelete(id: string, type: "session" | "project") {
    setRenamingId(null);
    setMoveSessionId(null);
    setConfirmId(id);
    setConfirmType(type);
  }

  function commitDelete() {
    if (!confirmId) return;
    if (confirmType === "session") onDeleteSession(confirmId);
    else onDeleteProject(confirmId);
    setConfirmId(null);
  }

  function commitNewProject() {
    const name = newProjectName.trim();
    if (name) onCreateProject(name);
    setAddingProject(false);
    setNewProjectName("");
  }

  function renderSession(s: ChatSession, currentProjectId: string | null) {
    const isActive = s.id === activeSessionId;

    // Delete confirm
    if (confirmId === s.id) {
      return (
        <motion.div key={s.id} className="ptree-session-row confirm" variants={fadeUp} layout>
          <span className="ptree-confirm-text">Delete "{s.title.slice(0, 22)}"?</span>
          <button className="ptree-confirm-yes" onClick={commitDelete}>Yes</button>
          <button className="ptree-confirm-no" onClick={() => setConfirmId(null)}>No</button>
        </motion.div>
      );
    }

    // Move dropdown
    if (moveSessionId === s.id) {
      const targets = [
        { id: null as string | null, name: "Uncategorized" },
        ...projects.map(p => ({ id: p.id, name: p.name })),
      ].filter(t => t.id !== currentProjectId);

      return (
        <motion.div key={s.id} className="ptree-session-row move-open" variants={fadeUp} layout>
          <span className="ptree-move-label">Move "{s.title.slice(0, 18)}" to:</span>
          <div className="ptree-move-list">
            {targets.map(t => (
              <button
                key={t.id ?? "__unc__"}
                className="ptree-move-item"
                onClick={() => { onMoveSession(s.id, t.id); setMoveSessionId(null); }}
              >
                {t.name}
              </button>
            ))}
            <button className="ptree-move-cancel" onClick={() => setMoveSessionId(null)}>Cancel</button>
          </div>
        </motion.div>
      );
    }

    return (
      <DropdownMenu.Root key={s.id}>
        <motion.div
          className={`ptree-session-row${isActive ? " active" : ""}`}
          variants={fadeUp}
          layout
        >
          {renamingId === s.id ? (
            <input
              ref={renameInputRef}
              className="ptree-rename-input"
              value={renameVal}
              onChange={e => setRenameVal(e.target.value)}
              onKeyDown={e => {
                if (e.key === "Enter") commitRename("session");
                if (e.key === "Escape") setRenamingId(null);
              }}
              onBlur={() => commitRename("session")}
            />
          ) : (
            <>
              <button className="ptree-session-btn" onClick={() => onSelectSession(s.id)}>
                <span className={`ptree-avatar${isActive ? " active" : ""}`}>{initial(s.title)}</span>
                <span
                  className="ptree-session-title"
                  onDoubleClick={() => startRename(s.id, s.title)}
                  title="Double-click to rename"
                >
                  {s.title}
                </span>
                <span className="ptree-time">{relativeTime(s.updatedAt)}</span>
              </button>
              <div className="ptree-row-actions">
                <DropdownMenu.Trigger asChild>
                  <button className="ptree-icon-btn" title="More options">
                    <MoreHorizontal size={11} />
                  </button>
                </DropdownMenu.Trigger>
              </div>
            </>
          )}
        </motion.div>

        <DropdownMenu.Portal>
          <DropdownMenu.Content className="dropdown-content" sideOffset={4}>
            <DropdownMenu.Item
              className="dropdown-item"
              onSelect={() => startRename(s.id, s.title)}
            >
              <Pencil size={13} /> Rename
            </DropdownMenu.Item>
            {projects.length > 0 && (
              <DropdownMenu.Item
                className="dropdown-item"
                onSelect={() => setMoveSessionId(s.id)}
              >
                <MoveRight size={13} /> Move to Project
              </DropdownMenu.Item>
            )}
            <DropdownMenu.Separator className="dropdown-separator" />
            <DropdownMenu.Item
              className="dropdown-item danger"
              onSelect={() => requestDelete(s.id, "session")}
            >
              <Trash2 size={13} /> Delete
            </DropdownMenu.Item>
          </DropdownMenu.Content>
        </DropdownMenu.Portal>
      </DropdownMenu.Root>
    );
  }

  return (
    <div className="ptree">
      {/* Search */}
      <div className="ptree-search">
        <Search size={12} className="ptree-search-icon" />
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Search sessions…"
          className="ptree-search-input"
        />
        <AnimatePresence>
          {search && (
            <motion.button
              className="ptree-search-clear"
              onClick={() => setSearch("")}
              initial={{ opacity: 0, scale: 0.7 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.7 }}
              transition={{ duration: 0.12 }}
            >
              <X size={12} />
            </motion.button>
          )}
        </AnimatePresence>
      </div>

      <div className="ptree-scroll">
        {/* Uncategorized group */}
        <div className="ptree-group">
          <div className="ptree-group-head">
            <button className="ptree-chevron" onClick={() => toggleCollapse("__unc__")}>
              {collapsed["__unc__"]
                ? <ChevronRight size={10} />
                : <ChevronDown size={10} />}
            </button>
            <span className="ptree-group-name no-action">Uncategorized</span>
            <button
              className="ptree-add-session-btn"
              title="New session"
              onClick={() => onCreateSession(null)}
            >
              <Plus size={12} />
            </button>
          </div>
          <AnimatePresence>
          {!collapsed["__unc__"] && (
            <motion.div
              className="ptree-sessions"
              variants={staggerFast}
              initial="hidden"
              animate="visible"
            >
              {uncategorized.map(s => renderSession(s, null))}
              {uncategorized.length === 0 && (
                <div className="ptree-empty">No sessions</div>
              )}
            </motion.div>
          )}
          </AnimatePresence>
        </div>

        {/* Project groups */}
        {visibleProjects.map(project => {
          const list = byProject.get(project.id) ?? [];
          const isOpen = !collapsed[project.id];

          // Delete confirm for project
          if (confirmId === project.id) {
            return (
              <div key={project.id} className="ptree-group">
                <div className="ptree-group-head confirm">
                  <span className="ptree-confirm-text">Delete project "{project.name.slice(0, 18)}"?</span>
                  <button className="ptree-confirm-yes" onClick={commitDelete}>Yes</button>
                  <button className="ptree-confirm-no" onClick={() => setConfirmId(null)}>No</button>
                </div>
              </div>
            );
          }

          return (
            <div key={project.id} className="ptree-group">
              <div className="ptree-group-head">
                <button className="ptree-chevron" onClick={() => toggleCollapse(project.id)}>
                  {isOpen ? <ChevronDown size={10} /> : <ChevronRight size={10} />}
                </button>
                {renamingId === project.id ? (
                  <input
                    ref={renameInputRef}
                    className="ptree-rename-input"
                    value={renameVal}
                    onChange={e => setRenameVal(e.target.value)}
                    onKeyDown={e => {
                      if (e.key === "Enter") commitRename("project");
                      if (e.key === "Escape") setRenamingId(null);
                    }}
                    onBlur={() => commitRename("project")}
                  />
                ) : (
                  <>
                    <Folder size={11} className="ptree-project-icon" />
                    <span
                      className="ptree-group-name"
                      onDoubleClick={() => startRename(project.id, project.name)}
                      title="Double-click to rename"
                    >
                      {project.name}
                    </span>
                    <div className="ptree-row-actions">
                      <button
                        className="ptree-add-session-btn"
                        title="New session in project"
                        onClick={() => onCreateSession(project.id)}
                      >
                        <Plus size={12} />
                      </button>
                      <button
                        className="ptree-icon-btn"
                        title="Rename project"
                        onClick={() => startRename(project.id, project.name)}
                      >
                        <Pencil size={10} />
                      </button>
                      <button
                        className="ptree-icon-btn danger"
                        title="Delete project"
                        onClick={() => requestDelete(project.id, "project")}
                      >
                        <Trash2 size={10} />
                      </button>
                    </div>
                  </>
                )}
              </div>
              <AnimatePresence>
              {isOpen && (
                <motion.div
                  className="ptree-sessions"
                  variants={staggerFast}
                  initial="hidden"
                  animate="visible"
                >
                  {list.map(s => renderSession(s, project.id))}
                  {list.length === 0 && (
                    <div className="ptree-empty">No sessions in this project</div>
                  )}
                </motion.div>
              )}
              </AnimatePresence>
            </div>
          );
        })}

        {/* Add project */}
        {addingProject ? (
          <div className="ptree-new-project-row">
            <input
              ref={newProjectRef}
              className="ptree-rename-input"
              placeholder="Project name…"
              value={newProjectName}
              onChange={e => setNewProjectName(e.target.value)}
              onKeyDown={e => {
                if (e.key === "Enter") commitNewProject();
                if (e.key === "Escape") { setAddingProject(false); setNewProjectName(""); }
              }}
              onBlur={commitNewProject}
            />
          </div>
        ) : (
          <button className="ptree-new-project-btn" onClick={() => setAddingProject(true)}>
            <FolderPlus size={12} style={{ display: "inline", verticalAlign: "middle", marginRight: 5 }} />
            New Project
          </button>
        )}
      </div>
    </div>
  );
}

