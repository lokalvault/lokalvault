export type VaultState = "missing" | "locked" | "unlocked";

export interface AppStatus {
  state: VaultState;
  daemonRunning: boolean;
  vaultExists: boolean;
  projectCount: number;
  estimatedSessionRemainingMinutes: number | null;
  defaultProject: string | null;
  version: string;
  dotenvWarning: boolean;
}

export interface ProjectSummary {
  name: string;
  secretCount: number;
}

const browserFallbackStatus: AppStatus = {
  state: "locked",
  daemonRunning: false,
  vaultExists: true,
  projectCount: 0,
  estimatedSessionRemainingMinutes: null,
  defaultProject: null,
  version: "browser-preview",
  dotenvWarning: false,
};

async function fallbackInvoke<T>(
  command: string,
  args?: Record<string, unknown>,
): Promise<T> {
  switch (command) {
    case "app_status":
      return browserFallbackStatus as T;
    case "list_projects":
      return [] as T;
    case "list_project_keys":
      return [
        "OPENAI_API_KEY",
        "DATABASE_URL",
        typeof args?.project === "string" ? `${args.project.toUpperCase()}_TOKEN` : "API_TOKEN",
      ] as T;
    default:
      throw new Error(`Unsupported preview command: ${command}`);
  }
}

const tauriBridge = {
  get available() {
    return typeof window !== "undefined" && !!window.__TAURI_INTERNALS__?.invoke;
  },
  get runtimeLabel() {
    return this.available ? "Tauri bridge" : "Browser preview";
  },
  invoke<T>(command: string, args?: Record<string, unknown>): Promise<T> {
    if (typeof window !== "undefined" && window.__TAURI_INTERNALS__?.invoke) {
      return window.__TAURI_INTERNALS__.invoke<T>(command, args);
    }
    return fallbackInvoke<T>(command, args);
  },
};

export function useTauri() {
  return tauriBridge;
}
