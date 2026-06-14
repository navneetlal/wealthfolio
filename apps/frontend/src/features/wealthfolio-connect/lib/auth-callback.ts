export type AuthCallbackPayload =
  | { type: "code"; code: string }
  | { type: "error"; message: string };

const TRUSTED_HOSTED_CALLBACK_HOSTS = new Set([
  "connect.wealthfolio.app",
  "connect-staging.wealthfolio.app",
]);

function currentOrigin(): string | null {
  if (typeof window === "undefined") return null;
  return window.location.origin;
}

function isAllowedAuthCallbackUrl(url: URL, appOrigin: string | null): boolean {
  if (url.protocol === "wealthfolio:" && url.hostname === "auth" && url.pathname === "/callback") {
    return true;
  }

  if (
    url.protocol === "https:" &&
    TRUSTED_HOSTED_CALLBACK_HOSTS.has(url.hostname) &&
    url.pathname === "/deeplink"
  ) {
    return true;
  }

  return appOrigin !== null && url.origin === appOrigin && url.pathname === "/auth/callback";
}

export function parseAuthCallbackUrl(
  url: string,
  appOrigin: string | null = currentOrigin(),
): AuthCallbackPayload | null {
  try {
    const urlObj = new URL(url);
    if (!isAllowedAuthCallbackUrl(urlObj, appOrigin)) return null;

    const hashParams = new URLSearchParams(urlObj.hash.substring(1));

    const error =
      urlObj.searchParams.get("error_description") ??
      urlObj.searchParams.get("error") ??
      hashParams.get("error_description") ??
      hashParams.get("error");
    if (error) {
      return { type: "error", message: error };
    }

    const code = urlObj.searchParams.get("code");
    if (code) {
      return { type: "code", code };
    }

    const hasAccessToken =
      hashParams.has("access_token") || urlObj.searchParams.has("access_token") || false;
    if (hasAccessToken) {
      return {
        type: "error",
        message:
          "Unexpected token callback (access_token). This app expects Auth Code + PKCE; ensure Supabase is configured for PKCE and your hosted callback forwards the ?code=... parameter.",
      };
    }

    return null;
  } catch {
    return null;
  }
}
