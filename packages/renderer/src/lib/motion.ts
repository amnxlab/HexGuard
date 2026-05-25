import { type Transition, type Variants } from "framer-motion";

// ─── Spring Configs ──────────────────────────────────────────────────────────

export const springs = {
  gentle: { type: "spring", stiffness: 200, damping: 30, mass: 0.8 },
  snappy: { type: "spring", stiffness: 380, damping: 30, mass: 0.7 },
  bouncy: { type: "spring", stiffness: 500, damping: 20, mass: 0.6 },
  slow: { type: "spring", stiffness: 120, damping: 28, mass: 1 },
} as const satisfies Record<string, Transition>;

// ─── Eased Transitions ───────────────────────────────────────────────────────

export const ease = {
  fast: { duration: 0.12, ease: [0.16, 1, 0.3, 1] } as Transition,
  normal: { duration: 0.22, ease: [0.16, 1, 0.3, 1] } as Transition,
  slow: { duration: 0.4, ease: [0.16, 1, 0.3, 1] } as Transition,
} as const;

// ─── Shared Variants ─────────────────────────────────────────────────────────

export const fadeUp: Variants = {
  hidden: { opacity: 0, y: 12 },
  visible: { opacity: 1, y: 0, transition: springs.gentle },
  exit: { opacity: 0, y: -8, transition: ease.fast },
};

export const fadeIn: Variants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: ease.normal },
  exit: { opacity: 0, transition: ease.fast },
};

export const slideInRight: Variants = {
  hidden: { opacity: 0, x: 12 },
  visible: { opacity: 1, x: 0, transition: springs.snappy },
  exit: { opacity: 0, x: 12, transition: ease.fast },
};

export const slideInLeft: Variants = {
  hidden: { opacity: 0, x: -12 },
  visible: { opacity: 1, x: 0, transition: springs.snappy },
  exit: { opacity: 0, x: -12, transition: ease.fast },
};

export const scaleIn: Variants = {
  hidden: { opacity: 0, scale: 0.92 },
  visible: { opacity: 1, scale: 1, transition: springs.bouncy },
  exit: { opacity: 0, scale: 0.92, transition: ease.fast },
};

export const commandPaletteVariants: Variants = {
  hidden: { opacity: 0, scale: 0.96, y: -8 },
  visible: { opacity: 1, scale: 1, y: 0, transition: springs.snappy },
  exit: { opacity: 0, scale: 0.96, y: -8, transition: ease.fast },
};

// ─── Stagger Containers ──────────────────────────────────────────────────────

export const staggerContainer: Variants = {
  hidden: {},
  visible: {
    transition: { staggerChildren: 0.05, delayChildren: 0.02 },
  },
};

export const staggerFast: Variants = {
  hidden: {},
  visible: {
    transition: { staggerChildren: 0.035, delayChildren: 0 },
  },
};

// ─── Sidebar Panel Variants ──────────────────────────────────────────────────

export const panelCrossfade: Variants = {
  hidden: { opacity: 0, y: 6 },
  visible: { opacity: 1, y: 0, transition: springs.gentle },
  exit: { opacity: 0, y: -6, transition: ease.fast },
};

// ─── Reduced Motion Helper ───────────────────────────────────────────────────

export function noMotion(): boolean {
  if (typeof window === "undefined") return false;
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}
