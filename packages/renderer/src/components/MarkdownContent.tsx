import React, { useState, useEffect } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";
import {
  oneDark,
  oneLight,
  dracula,
  atomDark,
  vscDarkPlus,
} from "react-syntax-highlighter/dist/esm/styles/prism";
import type { Components } from "react-markdown";

interface Props {
  content: string;
}

const LIGHT_THEMES = new Set(["vscode-light", "solarized-light", "github-light"]);

const PRISM_MAP: Record<string, Record<string, React.CSSProperties>> = {
  "dracula":     dracula,
  "night-owl":   atomDark,
  "vscode-dark": vscDarkPlus,
  "github-dark": vscDarkPlus,
};

function getPrismStyle(themeId: string): Record<string, React.CSSProperties> {
  if (LIGHT_THEMES.has(themeId)) return oneLight;
  return PRISM_MAP[themeId] ?? oneDark;
}

function useAppTheme() {
  const [themeId, setThemeId] = useState<string>(
    () => document.documentElement.getAttribute("data-theme") ?? "hexguard"
  );
  useEffect(() => {
    const obs = new MutationObserver(() => {
      setThemeId(document.documentElement.getAttribute("data-theme") ?? "hexguard");
    });
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    return () => obs.disconnect();
  }, []);
  return themeId;
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  function handleCopy() {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }
  return (
    <button className="prose-copy-btn" onClick={handleCopy} title="Copy code">
      {copied ? (
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
          <polyline points="20 6 9 17 4 12" />
        </svg>
      ) : (
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
          <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
        </svg>
      )}
      <span>{copied ? "Copied!" : "Copy"}</span>
    </button>
  );
}

export default function MarkdownContent({ content }: Props) {
  const themeId = useAppTheme();
  const prismStyle = getPrismStyle(themeId);

  const components: Components = {
    // ── Code ──────────────────────────────────────────────────────────────
    code({ node: _node, className, children, ...props }) {
      const isInline = !className;
      const lang = className?.replace("language-", "") ?? "";
      if (isInline) {
        return (
          <code className="prose-code-inline" {...props}>
            {children}
          </code>
        );
      }
      const rawText = String(children).replace(/\n$/, "");
      return (
        <div className="prose-pre">
          <div className="prose-pre-header">
            <span className="prose-pre-lang">{lang || "code"}</span>
            <CopyButton text={rawText} />
          </div>
          <SyntaxHighlighter
            language={lang || "text"}
            style={prismStyle}
            PreTag="div"
            customStyle={{
              margin: 0,
              padding: "12px 14px",
              background: "transparent",
              fontSize: "12.5px",
              lineHeight: "1.6",
              overflowX: "auto",
            }}
            codeTagProps={{ style: { fontFamily: '"SF Mono", "Fira Code", ui-monospace, monospace' } }}
          >
            {rawText}
          </SyntaxHighlighter>
        </div>
      );
    },

    // ── Links — open externally ───────────────────────────────────────────
    a({ href, children, ...props }) {
      return (
        <a
          href={href}
          target="_blank"
          rel="noopener noreferrer"
          className="prose-link"
          onClick={e => {
            e.preventDefault();
            if (href) {
              const shell = (window as unknown as { hexguard?: { openExternal?: (url: string) => void } }).hexguard;
              if (shell?.openExternal) {
                shell.openExternal(href);
              } else {
                window.open(href, "_blank", "noopener,noreferrer");
              }
            }
          }}
          {...props}
        >
          {children}
        </a>
      );
    },

    // ── Blockquote ────────────────────────────────────────────────────────
    blockquote({ children, ...props }) {
      return (
        <blockquote className="prose-blockquote" {...props}>
          {children}
        </blockquote>
      );
    },

    // ── Tables ────────────────────────────────────────────────────────────
    table({ children, ...props }) {
      return (
        <div className="prose-table-wrap">
          <table className="prose-table" {...props}>{children}</table>
        </div>
      );
    },
    th({ children, ...props }) {
      return <th className="prose-th" {...props}>{children}</th>;
    },
    td({ children, ...props }) {
      return <td className="prose-td" {...props}>{children}</td>;
    },
  };

  return (
    <div className="prose">
      <ReactMarkdown remarkPlugins={[remarkGfm]} components={components}>
        {content}
      </ReactMarkdown>
    </div>
  );
}
