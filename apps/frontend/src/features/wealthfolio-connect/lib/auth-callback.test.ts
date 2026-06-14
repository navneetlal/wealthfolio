import { describe, expect, it } from "vitest";
import { parseAuthCallbackUrl } from "./auth-callback";

describe("parseAuthCallbackUrl", () => {
  it("accepts the desktop custom auth callback", () => {
    expect(parseAuthCallbackUrl("wealthfolio://auth/callback?code=abc", null)).toEqual({
      type: "code",
      code: "abc",
    });
  });

  it("accepts the hosted callback page used by OAuth", () => {
    expect(parseAuthCallbackUrl("https://connect.wealthfolio.app/deeplink?code=abc", null)).toEqual(
      {
        type: "code",
        code: "abc",
      },
    );
  });

  it("accepts the current app origin web callback", () => {
    expect(
      parseAuthCallbackUrl("http://localhost:1420/auth/callback?code=abc", "http://localhost:1420"),
    ).toEqual({
      type: "code",
      code: "abc",
    });
  });

  it("rejects untrusted URLs that happen to include a code", () => {
    expect(parseAuthCallbackUrl("https://example.com/auth/callback?code=abc", null)).toBeNull();
    expect(parseAuthCallbackUrl("wealthfolio://connect/link-device?code=abc", null)).toBeNull();
  });

  it("reports token callbacks on trusted auth URLs as configuration errors", () => {
    expect(
      parseAuthCallbackUrl("wealthfolio://auth/callback#access_token=token", null),
    ).toMatchObject({
      type: "error",
    });
  });
});
