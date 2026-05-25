import React, { useEffect, useMemo, useRef, useState } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { motion, AnimatePresence } from "framer-motion";
import {
  Search, MessageCircle, Zap, Plus, Palette,
  Download, Settings, X,
} from "lucide-react";
import type { ChatSession, Project } from "@hexguard/shared";
import { commandPaletteVariants } from "../lib/motion";
import { THEMES } from "../lib/themes";

interface Action {
  id: string;
  group: "sessions" | "projects" | "actions";
  icon: React.ReactNode;
  title: string;
  subtitle?: string;
  shortcut?: string;
  onSelect: () => void;
}

interface Props {
  open: boolean;
  onClose: () => void;
  sessions: ChatSession[];
  projects: Project[];
  onSelectSession: (id: string) => void;
  onNewSession: () => void;
  onThemeChange: (id: string) => void;
  onExport?: () => void;
}

export default function CommandPalette({
  open,
  onClose,
  sessions,
  projects,
  onSelectSession,
  onNewSession,
  onThemeChange,
  onExport,
}: Props) {
  const [query, setQuery] = useState("");
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (open) {
      setQuery("");
      setSelectedIndex(0);
      setTimeout(() => inputRef.current?.focus(), 40);
    }
  }, [open]);

  const actions = useMemo<Action[]>(() => {
    const base: Action[] = [
      {
        id: "new-session",
        group: "actions",
        icon: <Plus size={14} />,
        title: "New Session",
        subtitle: "Start a fresh chat",
        shortcut: "⌘ N",
        onSelect: () => { onNewSession(); onClose(); },
      },
      ...THEMES.slice(0, 5).map(t => ({
        id: `theme-${t.id}`,
        group: "actions" as const,
        icon: <Palette size={14} />,
        title: `Theme: ${t.name}`,
        subtitle: "Change color theme",
        onSelect: () => { onThemeChange(t.id); onClose(); },
      })),
    ];

    if (onExport) {
      base.push({
        id: "export",
        group: "actions",
        icon: <Download size={14} />,
        title: "Export Report",
        subtitle: "Save run report to disk",
        shortcut: "⌘ E",
        onSelect: () => { onExport(); onClose(); },
      });
    }

    const sessionActions: Action[] = sessions.slice(0, 20).map(s => ({
      id: `session-${s.id}`,
      group: "sessions",
      icon: <MessageCircle size={14} />,
      title: s.title,
      subtitle: projects.find(p => p.id === s.projectId)?.name ?? "Uncategorized",
      onSelect: () => { onSelectSession(s.id); onClose(); },
    }));

    return [...base, ...sessionActions];
  }, [sessions, projects, onNewSession, onThemeChange, onExport, onClose, onSelectSession]);

  const filtered = useMemo(() => {
    if (!query.trim()) return actions;
    const q = query.toLowerCase();
    return actions.filter(
      a => a.title.toLowerCase().includes(q) || (a.subtitle ?? "").toLowerCase().includes(q)
    );
  }, [actions, query]);

  // Reset selection when filtered list changes
  useEffect(() => { setSelectedIndex(0); }, [filtered.length]);

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setSelectedIndex(i => Math.min(i + 1, filtered.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSelectedIndex(i => Math.max(i - 1, 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      filtered[selectedIndex]?.onSelect();
    } else if (e.key === "Escape") {
      onClose();
    }
  }

  const groups = [
    { key: "sessions" as const, label: "Sessions" },
    { key: "actions" as const, label: "Actions" },
  ];

  return (
    <Dialog.Root open={open} onOpenChange={v => !v && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay asChild>
          <motion.div
            className="cmd-overlay"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.15 }}
          >
            <Dialog.Content asChild>
              <motion.div
                className="cmd-dialog"
                variants={commandPaletteVariants}
                initial="hidden"
                animate="visible"
                exit="exit"
                onKeyDown={handleKeyDown}
              >
                {/* Search row */}
                <div className="cmd-search-row">
                  <Search size={16} className="cmd-search-icon" />
                  <input
                    ref={inputRef}
                    className="cmd-search-input"
                    placeholder="Search sessions, actions, themes…"
                    value={query}
                    onChange={e => setQuery(e.target.value)}
                  />
                  <kbd className="cmd-kbd">Esc</kbd>
                </div>

                {/* Results */}
                <div className="cmd-results">
                  {filtered.length === 0 ? (
                    <div className="cmd-empty">No results for "{query}"</div>
                  ) : (
                    groups.map(g => {
                      const items = filtered.filter(a => a.group === g.key);
                      if (items.length === 0) return null;
                      return (
                        <div key={g.key}>
                          <div className="cmd-group-label">{g.label}</div>
                          {items.map(item => {
                            const globalIndex = filtered.indexOf(item);
                            return (
                              <div
                                key={item.id}
                                className={`cmd-item${globalIndex === selectedIndex ? " selected" : ""}`}
                                onMouseEnter={() => setSelectedIndex(globalIndex)}
                                onClick={item.onSelect}
                              >
                                <div className="cmd-item-icon">{item.icon}</div>
                                <div className="cmd-item-body">
                                  <div className="cmd-item-title">{item.title}</div>
                                  {item.subtitle && (
                                    <div className="cmd-item-subtitle">{item.subtitle}</div>
                                  )}
                                </div>
                                {item.shortcut && (
                                  <span className="cmd-item-shortcut">{item.shortcut}</span>
                                )}
                              </div>
                            );
                          })}
                        </div>
                      );
                    })
                  )}
                </div>

                {/* Footer */}
                <div className="cmd-footer">
                  <span className="cmd-footer-hint"><kbd className="cmd-kbd">↑↓</kbd> Navigate</span>
                  <span className="cmd-footer-hint"><kbd className="cmd-kbd">↵</kbd> Select</span>
                  <span className="cmd-footer-hint"><kbd className="cmd-kbd">Esc</kbd> Close</span>
                </div>
              </motion.div>
            </Dialog.Content>
          </motion.div>
        </Dialog.Overlay>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
