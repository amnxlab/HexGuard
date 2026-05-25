import * as RadixTooltip from "@radix-ui/react-tooltip";
import { type ReactNode } from "react";

interface TooltipProps {
  content: ReactNode;
  children: ReactNode;
  side?: "top" | "bottom" | "left" | "right";
  shortcut?: string;
  delay?: number;
}

export function Tooltip({
  content,
  children,
  side = "bottom",
  shortcut,
  delay = 600,
}: TooltipProps) {
  return (
    <RadixTooltip.Root delayDuration={delay}>
      <RadixTooltip.Trigger asChild>{children}</RadixTooltip.Trigger>
      <RadixTooltip.Portal>
        <RadixTooltip.Content
          side={side}
          sideOffset={6}
          className="tooltip-content"
        >
          <span className="tooltip-label">{content}</span>
          {shortcut && (
            <span className="tooltip-shortcut">{shortcut}</span>
          )}
          <RadixTooltip.Arrow className="tooltip-arrow" />
        </RadixTooltip.Content>
      </RadixTooltip.Portal>
    </RadixTooltip.Root>
  );
}

export function TooltipProvider({ children }: { children: ReactNode }) {
  return (
    <RadixTooltip.Provider delayDuration={600} skipDelayDuration={200}>
      {children}
    </RadixTooltip.Provider>
  );
}
