export interface AppTheme {
  id: string;
  name: string;
  kind: "dark" | "light";
  swatch: string;
  accent: string;
}

export const THEMES: AppTheme[] = [
  { id: "hexguard",        name: "HexGuard Dark",     kind: "dark",  swatch: "#07111f", accent: "#67d4ff" },
  { id: "vscode-dark",     name: "Dark+ (VS Code)",   kind: "dark",  swatch: "#1e1e1e", accent: "#0078d4" },
  { id: "vscode-light",    name: "Light+ (VS Code)",  kind: "light", swatch: "#ffffff", accent: "#0078d4" },
  { id: "monokai",         name: "Monokai",            kind: "dark",  swatch: "#272822", accent: "#66d9e8" },
  { id: "one-dark",        name: "One Dark Pro",       kind: "dark",  swatch: "#282c34", accent: "#61afef" },
  { id: "dracula",         name: "Dracula",            kind: "dark",  swatch: "#282a36", accent: "#bd93f9" },
  { id: "solarized-dark",  name: "Solarized Dark",    kind: "dark",  swatch: "#002b36", accent: "#268bd2" },
  { id: "solarized-light", name: "Solarized Light",   kind: "light", swatch: "#fdf6e3", accent: "#268bd2" },
  { id: "night-owl",       name: "Night Owl",          kind: "dark",  swatch: "#011627", accent: "#82aaff" },
  { id: "github-dark",     name: "GitHub Dark",        kind: "dark",  swatch: "#0d1117", accent: "#58a6ff" },
  { id: "github-light",    name: "GitHub Light",       kind: "light", swatch: "#f6f8fa", accent: "#0969da" },
  { id: "tokyo-night",     name: "Tokyo Night",        kind: "dark",  swatch: "#1a1b26", accent: "#7aa2f7" },
  { id: "catppuccin",      name: "Catppuccin Mocha",   kind: "dark",  swatch: "#1e1e2e", accent: "#89b4fa" },
  { id: "ayu-dark",        name: "Ayu Dark",           kind: "dark",  swatch: "#0a0e14", accent: "#39bae6" },
  { id: "ayu-mirage",      name: "Ayu Mirage",         kind: "dark",  swatch: "#1f2430", accent: "#5ccfe6" },
  { id: "high-contrast",   name: "High Contrast",      kind: "dark",  swatch: "#000000", accent: "#ffffff" },
];

export const DEFAULT_THEME = "hexguard";

export function applyTheme(id: string): void {
  document.documentElement.setAttribute("data-theme", id);
  try { localStorage.setItem("hexguard-theme", id); } catch { /* ignore */ }
}

export function loadStoredTheme(): string {
  try { return localStorage.getItem("hexguard-theme") ?? DEFAULT_THEME; } catch { return DEFAULT_THEME; }
}
