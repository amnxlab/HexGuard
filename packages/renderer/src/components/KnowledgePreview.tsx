import React, { useEffect } from "react";
import { motion } from "framer-motion";
import { X } from "lucide-react";
import MarkdownContent from "./MarkdownContent";

interface Props {
  title: string;
  content: string;
  onClose: () => void;
}

export default function KnowledgePreview({ title, content, onClose }: Props) {
  // Close on Escape
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="kp-overlay" onClick={onClose}>
      <motion.div
        className="kp-modal"
        onClick={e => e.stopPropagation()}
        initial={{ opacity: 0, y: 18, scale: 0.97 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        exit={{ opacity: 0, y: 12, scale: 0.97 }}
        transition={{ duration: 0.18, ease: "easeOut" }}
      >
        <div className="kp-header">
          <span className="kp-title">{title}</span>
          <button className="kp-close" onClick={onClose} title="Close">
            <X size={15} />
          </button>
        </div>
        <div className="kp-body">
          <MarkdownContent content={content} />
        </div>
      </motion.div>
    </div>
  );
}
