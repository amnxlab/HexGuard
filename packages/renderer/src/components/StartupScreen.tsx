import React from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Loader2, CheckCircle2, XCircle, AlertTriangle, LogIn, RefreshCw,
} from "lucide-react";
import type { PreflightCheck } from "@hexguard/shared";
import { staggerContainer, fadeUp, scaleIn, springs } from "../lib/motion";

interface Props {
  checks: PreflightCheck[];
  allCriticalPass: boolean;
  onEnter: () => void;
  onRetry: () => void;
}

function statusIcon(status: PreflightCheck["status"]): React.ReactNode {
  switch (status) {
    case "pending":
    case "checking":
      return (
        <motion.span
          animate={{ rotate: 360 }}
          transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
          style={{ display: "inline-flex", color: "var(--accent)" }}
        >
          <Loader2 size={15} />
        </motion.span>
      );
    case "pass":
      return <CheckCircle2 size={15} color="var(--green)" />;
    case "fail":
      return <XCircle size={15} color="var(--red)" />;
    case "warn":
      return <AlertTriangle size={15} color="var(--gold)" />;
  }
}

export default function StartupScreen({ checks, allCriticalPass, onEnter, onRetry }: Props) {
  const anyFail = checks.some(c => c.status === "fail");
  const allDone = checks.every(c => c.status === "pass" || c.status === "fail" || c.status === "warn");
  const criticalBlocked = checks.filter(c => c.critical && (c.status === "fail" || c.status === "warn"));
  const stillChecking = checks.some(c => c.status === "pending" || c.status === "checking");

  const passCount = checks.filter(c => c.status === "pass" || c.status === "warn").length;
  const progress = checks.length > 0 ? Math.round((passCount / checks.length) * 100) : 0;

  return (
    <motion.div
      className="startup-overlay"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
    >
      <motion.div
        className="startup-card"
        variants={scaleIn}
        initial="hidden"
        animate="visible"
      >
        {/* Logo / heading */}
        <div className="startup-logo">
          <motion.img
            src="/icons/Logo.png"
            alt="HexGuard Hunt"
            className="startup-logo-img"
            animate={{ filter: ["drop-shadow(0 0 8px rgba(103,212,255,.3))", "drop-shadow(0 0 20px rgba(103,212,255,.7))", "drop-shadow(0 0 8px rgba(103,212,255,.3))"] }}
            transition={{ duration: 2.5, repeat: Infinity, ease: "easeInOut" }}
          />
        </div>
        <p className="startup-subtitle">Initializing systems…</p>

        {/* Progress bar */}
        <div className="startup-progress-track">
          <motion.div
            className="startup-progress-fill"
            initial={{ width: "0%" }}
            animate={{ width: `${progress}%` }}
            transition={springs.gentle}
          />
        </div>

        {/* Check list — stagger in */}
        <motion.ul
          className="startup-checks"
          variants={staggerContainer}
          initial="hidden"
          animate="visible"
        >
          {checks.map(c => (
            <motion.li
              key={c.id}
              className={`startup-check startup-check--${c.status}`}
              variants={fadeUp}
            >
              <span className="startup-check-icon">{statusIcon(c.status)}</span>
              <span className="startup-check-label">{c.label}</span>
              <span className="startup-check-detail">{c.detail}</span>
            </motion.li>
          ))}
        </motion.ul>

        {/* Actions */}
        <div className="startup-actions">
          {allDone && anyFail && (
            <motion.button
              className="startup-btn startup-btn--secondary"
              onClick={onRetry}
              whileTap={{ scale: 0.95 }}
              style={{ display: "flex", alignItems: "center", gap: 6 }}
            >
              <RefreshCw size={13} /> Retry
            </motion.button>
          )}
          <AnimatePresence>
          {allCriticalPass && (
            <motion.button
              className="startup-btn startup-btn--primary"
              onClick={onEnter}
              variants={scaleIn}
              initial="hidden"
              animate="visible"
              whileHover={{ scale: 1.03 }}
              whileTap={{ scale: 0.95 }}
              style={{ display: "flex", alignItems: "center", gap: 6 }}
            >
              <LogIn size={13} /> Enter HexGuard
            </motion.button>
          )}
          {!allCriticalPass && (
            <button
              className="startup-btn startup-btn--primary"
              disabled
              title={criticalBlocked.length > 0 ? `Required tools missing: ${criticalBlocked.map(c => c.label).join(", ")}` : undefined}
            >
              {stillChecking ? "Installing tools…" : "Required tools missing — cannot enter"}
            </button>
          )}
          </AnimatePresence>
        </div>

        {/* Blocked: list every critical tool that failed with its install command */}
        {!allCriticalPass && !stillChecking && criticalBlocked.length > 0 && (
          <div className="startup-blocked-note">
            <p className="startup-blocked-heading">
              Install the following tools to continue:
            </p>
            <ul className="startup-blocked-list">
              {criticalBlocked.map(c => (
                <li key={c.id}>
                  <span className="startup-blocked-tool">{c.label}</span>
                  <span className="startup-blocked-detail">{c.detail}</span>
                </li>
              ))}
            </ul>
            <p className="startup-blocked-hint">
              See <code>REQUIREMENTS.md</code> for the full quick-start install block.
            </p>
          </div>
        )}

        {/* Warning: non-critical warnings when all critical pass */}
        {allCriticalPass && checks.some(c => !c.critical && c.status === "warn") && (
          <p className="startup-warn-note">
            Some optional tools are missing. Scans will run in fallback mode.
          </p>
        )}
      </motion.div>
    </motion.div>
  );
}

