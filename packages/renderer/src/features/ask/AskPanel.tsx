import React, { useEffect, useRef, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Paperclip, Smile, ArrowUp, Shield, Zap, AlertTriangle } from "lucide-react";
import type { ChatSession } from "@hexguard/shared";
import VoiceInput from "../../components/VoiceInput";
import MarkdownContent from "../../components/MarkdownContent";
import { fadeUp, staggerFast, springs } from "../../lib/motion";

interface Props {
  session: ChatSession | null;
  onSend: (prompt: string) => void;
  loading: boolean;
  onNewSession: () => void;
}

function formatTime(ts: string) {
  try { return new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }); }
  catch { return ""; }
}

// Group consecutive messages by time window (same minute)
function groupByMinute(messages: ChatSession["messages"]) {
  const groups: Array<{ time: string; messages: ChatSession["messages"] }> = [];
  let lastMin = "";
  for (const msg of messages) {
    const min = formatTime(msg.timestamp);
    if (min !== lastMin) {
      groups.push({ time: min, messages: [msg] });
      lastMin = min;
    } else {
      groups[groups.length - 1].messages.push(msg);
    }
  }
  return groups;
}

export default function AskPanel({ session, onSend, loading, onNewSession }: Props) {
  const [draft, setDraft]       = useState("");
  const [interimText, setInterim] = useState("");
  const bottomRef  = useRef<HTMLDivElement>(null);
  const textRef    = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [session?.messages.length, loading]);

  function handleKey(e: React.KeyboardEvent) {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); submit(); }
  }

  function submit() {
    const text = draft.trim();
    if (!text || loading) return;
    setDraft("");
    onSend(text);
  }

  if (!session) {
    return (
      <div className="ask-layout">
        <div className="empty-state">
          <motion.div
            className="empty-icon"
            initial={{ scale: 0.5, opacity: 0 }}
            animate={{ scale: 1, opacity: 0.4 }}
            transition={springs.bouncy}
          >💬</motion.div>
          <div className="empty-title">No session selected</div>
          <div className="empty-body">Select a session from the sidebar or create a new one.</div>
          <motion.button
            className="run-btn primary"
            style={{ marginTop: 12, padding: "8px 20px" }}
            onClick={onNewSession}
            whileHover={{ scale: 1.03 }}
            whileTap={{ scale: 0.95 }}
          >
            New Session
          </motion.button>
        </div>
      </div>
    );
  }

  const groups = groupByMinute(session.messages);

  return (
    <div className="ask-layout">
      <div className="message-feed">
        <div className="chat-column">
        <AnimatePresence initial={false}>
        {groups.map((g, gi) => (
          <React.Fragment key={`${session.id}-${gi}`}>
            <motion.div className="msg-time-divider" variants={fadeUp} initial="hidden" animate="visible">{g.time}</motion.div>
            <motion.div variants={staggerFast} initial="hidden" animate="visible"
              style={{ display: "flex", flexDirection: "column" }}>
              {g.messages.map(msg => (
                <motion.div key={msg.id} className={`msg-row ${msg.role}`} variants={fadeUp}>
                  {msg.role !== "user" && (
                    <div className={`msg-avatar ${msg.role}`}>
                      {msg.role === "assistant"
                        ? <img src="/icons/Logo-Emblem.png" alt="HexStrike" className="avatar-logo" />
                        : "ℹ"}
                    </div>
                  )}
                  <div style={{ display: "flex", flexDirection: "column", flex: 1, minWidth: 0 }}>
                    {/* Quota card — replaces bubble entirely */}
                    {msg.role === "assistant" && msg.kind === "quota" ? (
                      <div className="quota-card">
                        <div className="quota-card-header">
                          <AlertTriangle size={13} />
                          Gemini Quota Limit Reached
                        </div>
                        <MarkdownContent content={msg.content} />
                      </div>
                    ) : msg.role === "assistant" && msg.kind === "error" ? (
                      /* Error block — red left border */
                      <div className="error-msg-block">
                        <MarkdownContent content={msg.content} />
                      </div>
                    ) : (
                      <div className="msg-bubble">
                        {msg.role === "user"
                          ? msg.content
                          : <MarkdownContent content={msg.content} />}
                      </div>
                    )}
                    {/* Source attribution badge */}
                    {msg.role === "assistant" && msg.source && (
                      <div className="msg-source-row">
                        {msg.source === "hexstrike" ? (
                          <span className="msg-source-badge hexstrike">
                            <Zap size={9} strokeWidth={2.5} />
                            HexStrike{msg.model ? ` · ${msg.model}` : ""}
                          </span>
                        ) : (
                          <span className="msg-source-badge hexguard">
                            <Shield size={9} strokeWidth={2.5} />
                            HexGuard
                          </span>
                        )}
                      </div>
                    )}
                    <span className="msg-ts">{formatTime(msg.timestamp)}</span>
                  </div>
                </motion.div>
              ))}
            </motion.div>
          </React.Fragment>
        ))}
        </AnimatePresence>

        {/* Typing indicator — 3 bouncing dots */}
        <AnimatePresence>
        {loading && (
          <motion.div
            className="msg-row assistant"
            key="typing"
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 8 }}
            transition={springs.snappy}
          >
            <div className="msg-avatar assistant">
              <img src="/icons/Logo-Emblem.png" alt="HexStrike" className="avatar-logo" />
            </div>
            <div className="msg-bubble" style={{ padding: "10px 16px" }}>
              <div className="typing-indicator">
                <span className="typing-dot" />
                <span className="typing-dot" />
                <span className="typing-dot" />
              </div>
            </div>
          </motion.div>
        )}
        </AnimatePresence>
        <div ref={bottomRef} />
        </div>{/* /chat-column */}
      </div>

      <div className="composer">
        <div className="chat-column">
        <div className="composer-toolbar">
          {/* Attach */}
          <motion.button className="composer-icon-btn" title="Attach file" whileTap={{ scale: 0.88 }}>
            <Paperclip size={14} strokeWidth={1.7} />
          </motion.button>
          {/* Emoji */}
          <motion.button className="composer-icon-btn" title="Add emoji" whileTap={{ scale: 0.88 }}>
            <Smile size={14} strokeWidth={1.7} />
          </motion.button>

          <textarea
            ref={textRef}
            className="composer-textarea"
            placeholder="Ask HexStrike about vulnerabilities, recon techniques, disclosure…"
            value={draft}
            onChange={e => setDraft(e.target.value)}
            onKeyDown={handleKey}
            rows={1}
            disabled={loading}
          />
          {/* Interim voice transcript ghost — shows partial speech while mic is active */}
          <AnimatePresence>
            {interimText && (
              <motion.span
                className="composer-interim-ghost"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.1 }}
              >
                {interimText}
              </motion.span>
            )}
          </AnimatePresence>

          {/* Voice input */}
          <VoiceInput
            onTranscript={text => { setDraft(prev => (prev ? prev + " " + text : text)); setInterim(""); }}
            onInterim={text => setInterim(text)}
            disabled={loading}
          />

          <motion.button
            className="composer-send"
            onClick={submit}
            disabled={!draft.trim() || loading}
            title="Send (Enter)"
            whileHover={draft.trim() && !loading ? { scale: 1.06 } : {}}
            whileTap={draft.trim() && !loading ? { scale: 0.88 } : {}}
          >
            <ArrowUp size={15} strokeWidth={2} />
          </motion.button>
        </div>
        </div>{/* /chat-column */}
      </div>
    </div>
  );
}
