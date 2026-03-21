/// <reference types="vite/client" />

interface TauriInternals {
  invoke<T>(command: string, args?: Record<string, unknown>): Promise<T>;
}

interface Window {
  __TAURI_INTERNALS__?: TauriInternals;
}
