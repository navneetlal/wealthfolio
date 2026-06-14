// Event Listeners
import type {
  EventCallback as TauriEventCallback,
  UnlistenFn as TauriUnlistenFn,
} from "@tauri-apps/api/event";
import { listen } from "@tauri-apps/api/event";
import { getCurrent, onOpenUrl } from "@tauri-apps/plugin-deep-link";

import type { EventCallback, UnlistenFn } from "../types";

// Helper to adapt Tauri's event callback to our unified type
const adaptCallback = <T>(handler: EventCallback<T>): TauriEventCallback<T> => {
  return (event) => handler({ event: event.event, payload: event.payload, id: event.id });
};

// Helper to adapt Tauri's unlisten function to our unified type.
// The try-catch guards against a Tauri race condition where unlisten is called
// before the listen_js_script has executed in the webview (e.g. React strict mode
// cleanup), causing "listeners[eventId].handlerId" to be undefined.
const adaptUnlisten = (unlisten: TauriUnlistenFn): UnlistenFn => {
  return async () => {
    try {
      unlisten();
    } catch {
      // Listener was never fully registered or already removed — safe to ignore.
    }
  };
};

const callDeepLinkHandler = <T>(handler: EventCallback<T>, url: string) => {
  handler({ event: "deep-link-received", payload: url as T, id: 0 });
};

export const listenFileDropHover = async <T>(handler: EventCallback<T>): Promise<UnlistenFn> => {
  const unlisten = await listen<T>("tauri://file-drop-hover", adaptCallback(handler));
  return adaptUnlisten(unlisten);
};

export const listenFileDrop = async <T>(handler: EventCallback<T>): Promise<UnlistenFn> => {
  const unlisten = await listen<T>("tauri://file-drop", adaptCallback(handler));
  return adaptUnlisten(unlisten);
};

export const listenFileDropCancelled = async <T>(
  handler: EventCallback<T>,
): Promise<UnlistenFn> => {
  const unlisten = await listen<T>("tauri://file-drop-cancelled", adaptCallback(handler));
  return adaptUnlisten(unlisten);
};

export const listenPortfolioUpdateStart = async <T>(
  handler: EventCallback<T>,
): Promise<UnlistenFn> => {
  const unlisten = await listen<T>("portfolio:update-start", adaptCallback(handler));
  return adaptUnlisten(unlisten);
};

export const listenPortfolioUpdateComplete = async <T>(
  handler: EventCallback<T>,
): Promise<UnlistenFn> => {
  const unlisten = await listen<T>("portfolio:update-complete", adaptCallback(handler));
  return adaptUnlisten(unlisten);
};

export const listenDatabaseRestored = async <T>(handler: EventCallback<T>): Promise<UnlistenFn> => {
  const unlisten = await listen<T>("database-restored", adaptCallback(handler));
  return adaptUnlisten(unlisten);
};

export const listenPortfolioUpdateError = async <T>(
  handler: EventCallback<T>,
): Promise<UnlistenFn> => {
  const unlisten = await listen<T>("portfolio:update-error", adaptCallback(handler));
  return adaptUnlisten(unlisten);
};

export async function listenMarketSyncComplete<T>(handler: EventCallback<T>): Promise<UnlistenFn> {
  const unlisten = await listen<T>("market:sync-complete", adaptCallback(handler));
  return adaptUnlisten(unlisten);
}

export async function listenMarketSyncStart<T>(handler: EventCallback<T>): Promise<UnlistenFn> {
  const unlisten = await listen<T>("market:sync-start", adaptCallback(handler));
  return adaptUnlisten(unlisten);
}

export async function listenMarketSyncError<T>(handler: EventCallback<T>): Promise<UnlistenFn> {
  const unlisten = await listen<T>("market:sync-error", adaptCallback(handler));
  return adaptUnlisten(unlisten);
}

export async function listenBrokerSyncStart<T>(handler: EventCallback<T>): Promise<UnlistenFn> {
  const unlisten = await listen<T>("broker:sync-start", adaptCallback(handler));
  return adaptUnlisten(unlisten);
}

export async function listenBrokerSyncComplete<T>(handler: EventCallback<T>): Promise<UnlistenFn> {
  const unlisten = await listen<T>("broker:sync-complete", adaptCallback(handler));
  return adaptUnlisten(unlisten);
}

export async function listenBrokerSyncError<T>(handler: EventCallback<T>): Promise<UnlistenFn> {
  const unlisten = await listen<T>("broker:sync-error", adaptCallback(handler));
  return adaptUnlisten(unlisten);
}

export async function listenNavigateToRoute<T>(handler: EventCallback<T>): Promise<UnlistenFn> {
  const unlisten = await listen<T>("navigate-to-route", adaptCallback(handler));
  return adaptUnlisten(unlisten);
}

export const getCurrentDeepLinks = async (): Promise<string[]> => {
  return (await getCurrent()) ?? [];
};

export const listenDeepLink = async <T>(handler: EventCallback<T>): Promise<UnlistenFn> => {
  const unlistenFns: UnlistenFn[] = [];

  try {
    const unlisten = await onOpenUrl((urls) => {
      for (const url of urls) {
        callDeepLinkHandler(handler, url);
      }
    });
    unlistenFns.push(adaptUnlisten(unlisten));
  } catch {
    // Fall back to the app-level bridge below if the plugin API is unavailable.
  }

  const bridgeUnlisten = await listen<T>("deep-link-received", adaptCallback(handler));
  unlistenFns.push(adaptUnlisten(bridgeUnlisten));

  return async () => {
    for (const unlisten of unlistenFns) {
      await unlisten();
    }
  };
};
