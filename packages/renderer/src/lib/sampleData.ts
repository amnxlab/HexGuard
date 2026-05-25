import type { ChatSession, Project } from "@hexguard/shared";

export const fallbackProjects: Project[] = [
  {
    id: "project-preview-redteam",
    name: "Red Team Baseline",
    description: "Knowledge and sessions for red-team simulation and recon.",
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  }
];

export const fallbackSessions: ChatSession[] = [
  {
    id: "session-preview-1",
    title: "Getting Started",
    projectId: null,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    messages: [
      {
        id: "sys-1",
        role: "system",
        content: "HexGuard Hunt is running in browser preview mode.\n\nWindow.hexguard API is not available — this is expected when opening index.html directly in a browser. Launch the app via Electron to access the full AI security workspace.",
        timestamp: new Date().toISOString(),
        state: "complete"
      },
      {
        id: "ast-1",
        role: "assistant",
        content: "Welcome to HexGuard Hunt.\n\nI'm your AI security advisor powered by HexStrike MCP. Here's what you can do:\n\n• ASK mode — send cybersecurity questions for structured guidance on recon, vulnerability analysis, and responsible disclosure.\n• Autonomous mode — configure supervised simulation workflows with policy enforcement, task chaining, and live monitoring.\n\nHow can I help you today?",
        timestamp: new Date().toISOString(),
        state: "complete"
      }
    ]
  }
];
