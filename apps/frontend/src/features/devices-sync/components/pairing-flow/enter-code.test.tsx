import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { EnterCode } from "./enter-code";

const scanner = vi.hoisted(() => ({
  checkPermissions: vi.fn(),
  scan: vi.fn(),
  cancel: vi.fn(),
  Format: { QRCode: "QR_CODE" },
}));
vi.mock("@tauri-apps/plugin-barcode-scanner", () => scanner);
vi.mock("@/hooks/use-platform", () => ({ usePlatform: () => ({ isMobile: true }) }));
vi.mock("@/adapters", () => ({ logger: { info: vi.fn(), error: vi.fn() } }));
vi.mock("react-i18next", () => ({ useTranslation: () => ({ t: (key: string) => key }) }));

beforeEach(() => {
  vi.clearAllMocks();
  scanner.checkPermissions.mockResolvedValue("granted");
  scanner.scan.mockImplementation(() => new Promise(() => {}));
  scanner.cancel.mockResolvedValue(undefined);
});

it("closes on one press even when the native scan promise stays pending", async () => {
  render(<EnterCode onSubmit={vi.fn()} onCancel={vi.fn()} />);
  fireEvent.click(screen.getByText("sync:enterCode.scanQrCode"));
  await waitFor(() => expect(scanner.scan).toHaveBeenCalled());
  const button = document.querySelector(".qr-overlay button")!;
  const press = new Event("pointerdown", { bubbles: true, cancelable: true });
  Object.assign(press, { isPrimary: true, button: 0 });
  fireEvent(button, press);
  await waitFor(() => expect(document.querySelector(".qr-overlay")).toBeNull());
  expect(scanner.cancel).toHaveBeenCalledTimes(1);
  expect(document.body.classList.contains("qr-scan-active")).toBe(false);
});

it("explains when the native scanner reports no camera and restores the form", async () => {
  scanner.scan.mockRejectedValue({
    message: "No camera available on this device (e.g., iOS Simulator)",
  });
  render(<EnterCode onSubmit={vi.fn()} onCancel={vi.fn()} />);
  fireEvent.click(screen.getByText("sync:enterCode.scanQrCode"));
  expect(await screen.findByRole("alert")).toHaveTextContent("sync:enterCode.cameraUnavailable");
  expect(document.body.classList.contains("qr-scan-active")).toBe(false);
});
