import React from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Menu, MoreHorizontal, FolderOpen,
  MessageCircle, Zap, Minus, Square, X,
} from "lucide-react";
import type { AppMode, ChatSession, HuntSession } from "@hexguard/shared";
import { Tooltip } from "./Tooltip";
import { slideInRight } from "../lib/motion";

interface Props {
  mode: AppMode;
  hunt?: HuntSession | null;
  activeSession?: ChatSession | null;
  sidebarCollapsed?: boolean;
  onToggleSidebar?: () => void;
  onOpenCommandPalette?: () => void;
  onOpenReports?: () => void;
}

function relativeTime(iso: string) {
  try {
    const diff = Date.now() - new Date(iso).getTime();
    const m = Math.floor(diff / 60000);
    if (m < 1) return "just now";
    if (m < 60) return `${m}m ago`;
    const h = Math.floor(m / 60);
    if (h < 24) return `${h}h ago`;
    return `${Math.floor(h / 24)}d ago`;
  } catch { return ""; }
}

const api = (window as unknown as { hexguard?: Record<string, unknown> }).hexguard;

function WindowControls() {
  return (
    <div className="wc-group">
      <button
        className="wc-btn wc-minimize"
        onClick={() => (api?.windowMinimize as (() => void) | undefined)?.()}
        aria-label="Minimize"
      >
        <Minus size={10} strokeWidth={2.5} />
      </button>
      <button
        className="wc-btn wc-maximize"
        onClick={() => (api?.windowMaximize as (() => void) | undefined)?.()}
        aria-label="Maximize"
      >
        <Square size={9} strokeWidth={2.5} />
      </button>
      <button
        className="wc-btn wc-close"
        onClick={() => (api?.windowClose as (() => void) | undefined)?.()}
        aria-label="Close"
      >
        <X size={10} strokeWidth={2.5} />
      </button>
    </div>
  );
}

export default function Topbar({ mode, hunt, activeSession, sidebarCollapsed, onToggleSidebar, onOpenCommandPalette, onOpenReports }: Props) {
  const isAsk = mode === "ask";

  const sessionName = activeSession?.title ?? (isAsk ? "Security Advisory" : "Hunt Session");
  const sessionSub  = activeSession
    ? `Last active ${relativeTime(activeSession.updatedAt)}`
    : isAsk
      ? "Vulnerability analysis & security guidance"
      : "HexStrike-led HITL vulnerability hunt";

  return (
    <header className="topbar">
      <Tooltip content={sidebarCollapsed ? "Show Sidebar" : "Hide Sidebar"} shortcut="⌘ \\" side="bottom">
        <motion.button
          className="tb-btn"
          onClick={onToggleSidebar}
          whileTap={{ scale: 0.88 }}
        >
          <Menu size={15} strokeWidth={1.8} />
        </motion.button>
      </Tooltip>

      <div className="topbar-divider" />

      {/* Mode badge with animated background */}
      <motion.span
        className={`tb-badge ${isAsk ? "ask" : "auto"}`}
        layout
        animate={{ opacity: 1 }}
        transition={{ duration: 0.22 }}
      >
        {isAsk
          ? <MessageCircle size={12} strokeWidth={2} />
          : <Zap size={12} strokeWidth={2} />
        }
        {isAsk ? "ASK" : "AUTO"}
      </motion.span>

      <div className="topbar-session">
        <span className="topbar-session-name">{sessionName}</span>
        <span className="topbar-session-sub">{sessionSub}</span>
      </div>

      <div className="topbar-spacer" />

      {/* Run status pill — spring-in from right */}
      <AnimatePresence mode="popLayout">
      {!isAsk && hunt && hunt.state !== "idle" && (
          <motion.span
            key={hunt.state}
            className={`tb-run-pill ${hunt.state}`}
            variants={slideInRight}
            initial="hidden"
            animate="visible"
            exit="exit"
          >
            <span className="tb-run-dot" />
            {hunt.state.replace("_", " ")}
          </motion.span>
        )}
      </AnimatePresence>

      <div className="topbar-divider" />

      <Tooltip content="View Reports" side="bottom">
        <motion.button className="tb-btn" whileTap={{ scale: 0.88 }} onClick={onOpenReports}>
          <FolderOpen size={15} strokeWidth={1.8} />
        </motion.button>
      </Tooltip>

      <Tooltip content="Command Palette" shortcut="⌘ K" side="bottom">
        <motion.button
          className="tb-btn"
          whileTap={{ scale: 0.88 }}
          onClick={onOpenCommandPalette}
        >
          <MoreHorizontal size={15} strokeWidth={1.8} />
        </motion.button>
      </Tooltip>

      <div className="topbar-divider" />
      <WindowControls />
    </header>
  );
}



