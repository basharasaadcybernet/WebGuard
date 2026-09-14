import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

import { scanTarget } from "../api/client";

describe("frontend security boundary", () => {
  it("rejects malformed successful API payloads", async () => {
    const fetcher = (): Promise<Response> => Promise.resolve(new Response(JSON.stringify({
      api_version: "v1",
      api_schema_version: "1.0",
      request_id: "id",
      report: { findings: "not-an-array" },
    }), { status: 200, headers: { "content-type": "application/json" } }));
    await expect(scanTarget("https://example.com", { fetcher })).rejects.toMatchObject({ code: "INTERNAL_ERROR" });
  });

  it("enforces the client timeout through AbortSignal", async () => {
    const fetcher = async (_input: RequestInfo | URL, init?: RequestInit): Promise<Response> => new Promise((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")));
    });
    await expect(scanTarget("https://example.com", { fetcher, timeoutMs: 1 })).rejects.toMatchObject({ code: "CLIENT_TIMEOUT" });
  });

  it("contains no raw HTML rendering escape hatch", () => {
    const sources = [
      readFileSync(resolve(process.cwd(), "src/App.tsx"), "utf8"),
      readFileSync(resolve(process.cwd(), "src/components/results/FindingCard.tsx"), "utf8"),
      readFileSync(resolve(process.cwd(), "src/components/results/ResultsView.tsx"), "utf8"),
    ].join("\n");
    expect(sources).not.toContain("dangerouslySetInnerHTML");
  });
});

describe("responsive and motion foundation", () => {
  const css = readFileSync(resolve(process.cwd(), "src/styles.css"), "utf8");

  it("defines intentional desktop, tablet, mobile, and narrow-mobile rules", () => {
    expect(css).toContain("@media (max-width: 960px)");
    expect(css).toContain("@media (max-width: 720px)");
    expect(css).toContain("@media (max-width: 420px)");
    expect(css).toMatch(/overflow-wrap:\s*anywhere/);
    expect(css).toMatch(/overflow-x:\s*auto/);
  });

  it("supports reduced motion without hiding content", () => {
    expect(css).toContain("@media (prefers-reduced-motion: reduce)");
    expect(css).toContain("animation-duration: 0.01ms");
    expect(css).toContain("scroll-behavior: auto");
  });
});
