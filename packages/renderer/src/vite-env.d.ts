/// <reference types="vite/client" />
import type { HexguardApi } from "@hexguard/shared";
declare global {
  interface Window {
    hexguard?: HexguardApi;
  }
}
