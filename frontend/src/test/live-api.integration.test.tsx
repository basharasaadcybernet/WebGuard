import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { App } from "../App";
import type { ScanApiResponse } from "../api/types";

const liveApiUrl = process.env.WEBGUARD_LIVE_API_URL?.replace(/\/$/, "");
const nativeFetch = globalThis.fetch;

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe.skipIf(!liveApiUrl)("local API integration", () => {
  it("renders the exact score, grade, coverage, and finding count returned by the API", async () => {
    let apiPayload: ScanApiResponse | null = null;
    vi.stubGlobal("fetch", async (_input: RequestInfo | URL, init?: RequestInit) => {
      const response = await nativeFetch(`${liveApiUrl}/api/v1/scans`, init);
      apiPayload = await response.clone().json() as ScanApiResponse;
      return response;
    });

    render(<App />);
    const user = userEvent.setup();
    await user.type(screen.getByLabelText("Website address"), "https://example.com");
    await user.click(screen.getByRole("button", { name: /scan website/i }));

    await waitFor(() => expect(apiPayload).not.toBeNull(), { timeout: 30_000 });
    const payload = apiPayload as ScanApiResponse | null;
    if (!payload) throw new Error("The local API did not return a payload.");
    const score = payload.report.score?.score;
    expect(score).not.toBeNull();
    expect(await screen.findByLabelText(`Security posture score ${String(score)} out of 100`, {}, { timeout: 30_000 })).toBeInTheDocument();
    expect(screen.getByText(`Grade ${String(payload.report.score?.grade)}`)).toBeInTheDocument();
    expect(screen.getByText(`Coverage ${Math.round(Number(payload.report.score?.coverage) * 100)}%`)).toBeInTheDocument();
    expect(screen.getAllByText(/TLS certificate|HTTP to HTTPS|Content Security|Referrer|Cookie|Server/i).length).toBeGreaterThan(0);
    expect(document.querySelectorAll(".finding-card")).toHaveLength(payload.report.findings.length);
  }, 35_000);
});
