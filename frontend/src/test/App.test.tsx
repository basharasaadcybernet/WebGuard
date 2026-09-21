import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { App } from "../App";
import type { Finding, RuleContribution } from "../api/types";
import { makeFailedAssessmentReport, makeReport, makeResponse, makeScore } from "./fixtures";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "x-request-id": "safe-request-id" },
  });
}

function mockResponse(body: unknown, status = 200): ReturnType<typeof vi.fn> {
  const fetchMock = vi.fn().mockResolvedValue(jsonResponse(body, status));
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

async function submit(target = "https://example.com"): Promise<void> {
  const user = userEvent.setup();
  render(<App />);
  await user.type(screen.getByLabelText("Website address"), target);
  await user.click(screen.getByRole("button", { name: /scan website/i }));
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("WebGuard application flow", () => {
  it("renders a complete initial state with the real product identity and scope", () => {
    render(<App />);
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("security posture");
    expect(screen.getByRole("link", { name: "Bashar Asaad WebGuard home" })).toBeInTheDocument();
    expect(document.querySelector('img[src="/brand/logo.svg"]')).toBeInTheDocument();
    expect(screen.getByText("Transport")).toBeInTheDocument();
    expect(screen.getByText(/no persistent scan-history database/i)).toBeInTheDocument();
  });

  it("submits the exact URL without frontend normalization", async () => {
    const fetchMock = mockResponse(makeResponse());
    await submit("https://example.com/path?view=1");
    await screen.findByRole("heading", { name: "https://example.com/" });
    expect(fetchMock).toHaveBeenCalledOnce();
    const options = fetchMock.mock.calls[0]?.[1] as RequestInit;
    expect(options.body).toBe(JSON.stringify({ target: "https://example.com/path?view=1" }));
  });

  it("supports keyboard submission", async () => {
    const fetchMock = mockResponse(makeResponse());
    const user = userEvent.setup();
    render(<App />);
    await user.type(screen.getByLabelText("Website address"), "https://example.com{Enter}");
    await screen.findByRole("heading", { name: "https://example.com/" });
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("rejects an incomplete target before calling the API", async () => {
    const fetchMock = mockResponse(makeResponse());
    await submit("example.com");
    expect(screen.getByRole("alert")).toHaveTextContent("including https:// or http://");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("shows a truthful loading state and supports cancellation", async () => {
    vi.stubGlobal("fetch", vi.fn((_url: string, options?: RequestInit) => new Promise((_resolve, reject) => {
      options?.signal?.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")));
    })));
    await submit();
    expect(screen.getByRole("heading", { name: /analyzing security posture/i })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /cancel assessment/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent("assessment was cancelled");
  });

  it("renders the backend score, grade, coverage, categories, and findings", async () => {
    mockResponse(makeResponse());
    await submit();
    expect(await screen.findByLabelText("Security posture score 82 out of 100")).toBeInTheDocument();
    expect(screen.getByText("Grade B")).toBeInTheDocument();
    expect(screen.getByText("Coverage 100%")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Category breakdown" })).toBeInTheDocument();
    expect(screen.getByText("TLS certificate validation")).toBeInTheDocument();
  });

  it("renders an exact backend 100/A result", async () => {
    mockResponse(makeResponse({ score: makeScore({ raw_score: "100.0", score: 100, grade: "A" }) }));
    await submit();
    expect(await screen.findByLabelText("Security posture score 100 out of 100")).toBeInTheDocument();
    expect(screen.getByText("Grade A")).toBeInTheDocument();
  });

  it("renders a poor capped result without replacing the raw score", async () => {
    mockResponse(makeResponse({
      score: makeScore({
        raw_score: "90.0",
        score: 59,
        grade: "F",
        cap: { rule_id: "TLS-001", trigger_status: "FAIL", maximum_score: 59, reason: "TLS certificate validation failed." },
      }),
    }));
    await submit();
    expect(await screen.findByLabelText("Security posture score 59 out of 100")).toBeInTheDocument();
    expect(screen.getByText("Grade F")).toBeInTheDocument();
    expect(screen.getByText(/Raw score 90/)).toBeInTheDocument();
    expect(screen.getByText(/TLS certificate validation failed/)).toBeInTheDocument();
  });

  it("never converts a withheld score to zero", async () => {
    mockResponse(makeResponse({ score: makeScore({ raw_score: null, score: null, grade: null, coverage: "0.45", withholding_reasons: ["Coverage is below 70%."] }) }));
    await submit();
    expect(await screen.findByRole("heading", { name: "Score unavailable" })).toBeInTheDocument();
    expect(screen.getByText("Coverage is below 70%.")).toBeInTheDocument();
    expect(screen.queryByText("0", { selector: ".score-ring strong" })).not.toBeInTheDocument();
  });

  it("separates partial-scan operational errors from security findings", async () => {
    mockResponse(makeResponse({
      completion_state: "PARTIAL",
      scan_metadata: { ...makeReport().scan_metadata, state: "PARTIAL" },
      operational_errors: [{ kind: "CHECK", code: "check.evaluation_failed", message: "One passive check could not complete.", rule_id: "HDR-001" }],
    }));
    await submit();
    expect(await screen.findByText(/completed only part/i)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Operational limitations" })).toBeInTheDocument();
    expect(screen.getByText(/not FAIL security findings/i)).toBeInTheDocument();
    expect(screen.getByText(/1 check not evaluated/i)).toBeInTheDocument();
  });

  it("renders a valid failed assessment with established findings and withheld score", async () => {
    mockResponse(makeResponse(makeFailedAssessmentReport()));
    await submit();
    expect(await screen.findByRole("heading", { name: "Assessment incomplete" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "https://forsa.sy/" })).toBeInTheDocument();
    expect(screen.getByText("FAILED")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Score unavailable" })).toBeInTheDocument();
    expect(screen.getByText("Coverage 14%")).toBeInTheDocument();
    expect(screen.getByText(/below the configured minimum/)).toBeInTheDocument();
    expect(screen.getByText("HTTP to HTTPS redirect")).toBeInTheDocument();
    expect(screen.getByText("HTTPS availability")).toBeInTheDocument();
    expect(screen.getByText("Connection timed out")).toBeInTheDocument();
    expect(screen.getByText(/17 checks not evaluated/i)).toBeInTheDocument();
    expect(screen.getByText(/required page observations were unavailable/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /try again or scan another site/i })).toBeInTheDocument();
    expect(screen.queryByText(/internal problem/i)).not.toBeInTheDocument();
  });

  it("renders an untrusted TLS failed assessment as valid report data", async () => {
    mockResponse(makeResponse(makeFailedAssessmentReport("untrusted")));
    await submit();
    expect(await screen.findByRole("heading", { name: "Assessment incomplete" })).toBeInTheDocument();
    expect(screen.getByText("TLS certificate trust")).toBeInTheDocument();
    expect(screen.getByText("TLS certificate not trusted")).toBeInTheDocument();
    expect(screen.getByText("Coverage 20%")).toBeInTheDocument();
    expect(screen.queryByText(/internal problem/i)).not.toBeInTheDocument();
  });

  it.each([
    [429, "RATE_LIMITED", "Too many scans"],
    [503, "SERVICE_BUSY", "scan capacity"],
    [504, "SCAN_TIMEOUT", "longer than the service allows"],
  ])("maps API status %s to safe user copy", async (status, code, copy) => {
    mockResponse({ code, message: "internal unsafe diagnostics", request_id: "public-id" }, status);
    await submit();
    expect(await screen.findByRole("alert")).toHaveTextContent(copy);
    expect(screen.queryByText(/internal unsafe diagnostics/)).not.toBeInTheDocument();
  });

  it("handles an unavailable API without exposing an exception", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("socket secrets")));
    await submit();
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("API could not be reached");
    expect(alert).not.toHaveTextContent("socket secrets");
  });

  it("reserves the internal problem message for an HTTP 500", async () => {
    mockResponse({ code: "INTERNAL_ERROR", message: "unsafe server detail", request_id: "public-id" }, 500);
    await submit();
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("WebGuard encountered an internal problem");
    expect(alert).not.toHaveTextContent("unsafe server detail");
  });

  it("filters findings deterministically by severity", async () => {
    mockResponse(makeResponse());
    await submit();
    const filters = screen.getByLabelText("Filter findings by severity");
    await userEvent.click(within(filters).getByRole("button", { name: /high/i }));
    expect(screen.getByText("TLS certificate validation")).toBeInTheDocument();
    expect(screen.queryByText("Content Security Policy")).not.toBeInTheDocument();
  });

  it("uses a keyboard-accessible native details disclosure", async () => {
    mockResponse(makeResponse());
    await submit();
    const card = screen.getByText("TLS certificate validation").closest("details");
    expect(card).not.toHaveAttribute("open");
    fireEvent.click(within(card as HTMLElement).getByText("TLS certificate validation"));
    expect(card).toHaveAttribute("open");
    expect(within(card as HTMLElement).getByText("Evidence")).toBeInTheDocument();
  });

  it("groups three no-cookie rule outcomes into one not-applicable observation", async () => {
    const report = makeReport();
    const cookieFindings: Finding[] = ["cookies.secure", "cookies.http_only", "cookies.same_site"].map((id) => ({
      id,
      title: id,
      category: "Cookie Security",
      status: "INFO",
      evaluation_state: "NOT_APPLICABLE",
      severity: "INFO",
      description: "No cookies were observed, so this attribute was not applicable.",
      evidence: [{ label: "Observation", value: "No cookies were observed in the landing response or redirect chain.", source_url: "https://example.com/" }],
      recommendation: "No action is suggested from this observation alone.",
      references: [],
    }));
    const cookieContributions: RuleContribution[] = cookieFindings.map((finding) => ({
      rule_id: finding.id,
      category: finding.category,
      state: "NOT_APPLICABLE",
      configured_points: "3.0",
      available_points: "0.0",
      earned_points: "0.0",
      deduction: "0.0",
      credit_fraction: null,
      reason: finding.description,
      exclusion_reason: "Rule was not applicable.",
    }));
    report.findings = [...report.findings, ...cookieFindings];
    report.score = makeScore({
      rule_contributions: [...makeScore().rule_contributions, ...cookieContributions],
    });
    mockResponse(makeResponse(report));

    await submit();

    expect(await screen.findByRole("heading", { name: "Cookie Security" })).toBeInTheDocument();
    expect(screen.getAllByText("NOT APPLICABLE")).toHaveLength(1);
    expect(screen.queryByRole("heading", { name: "cookies.secure" })).not.toBeInTheDocument();
  });

  it("does not repeat an identical finding description in scoring impact", async () => {
    const report = makeReport();
    const description = report.findings[0]!.description;
    report.score = makeScore({
      rule_contributions: [{ ...makeScore().rule_contributions[0]!, reason: description }],
    });
    mockResponse(makeResponse(report));

    await submit();
    const card = (await screen.findByText("TLS certificate validation")).closest("details") as HTMLElement;
    fireEvent.click(within(card).getByText("TLS certificate validation"));

    expect(within(card).getAllByText(description)).toHaveLength(1);
    expect(within(card).getByText("Scoring impact")).toBeInTheDocument();
  });

  it("renders malicious report strings as text and never creates injected DOM", async () => {
    const marker = '<img src="x" onerror="window.pwned=true"><script>window.pwned=true</script>';
    const report = makeReport();
    report.target = { ...report.target!, display_url: `<script>target()</script>${marker}` };
    report.findings[0] = {
      ...report.findings[0]!,
      title: `<svg onload=alert(1)>unsafe title</svg>`,
      evidence: [{ label: "Untrusted", value: marker, source_url: null }],
    };
    mockResponse(makeResponse(report));
    await submit();
    expect(await screen.findByText(/<script>target\(\)<\/script>/)).toBeInTheDocument();
    expect(screen.getByText(/<svg onload=alert\(1\)>unsafe title/)).toBeInTheDocument();
    expect(document.querySelector('img[src="x"]')).toBeNull();
    expect(document.querySelector("script:not([type])")).toBeNull();
    expect((window as Window & { pwned?: boolean }).pwned).toBeUndefined();
  });

  it("renders only validated HTTP(S) reference links with safe attributes", async () => {
    const report = makeReport();
    report.findings[0] = {
      ...report.findings[0]!,
      references: ["javascript:alert(1)", "data:text/html,unsafe", "https://owasp.org/www-project-secure-headers/"],
    };
    mockResponse(makeResponse(report));
    await submit();
    const card = screen.getByText("TLS certificate validation").closest("details") as HTMLElement;
    fireEvent.click(within(card).getByText("TLS certificate validation"));
    const links = within(card).getAllByRole("link");
    expect(links).toHaveLength(1);
    expect(links[0]).toHaveAttribute("href", "https://owasp.org/www-project-secure-headers/");
    expect(links[0]).toHaveAttribute("target", "_blank");
    expect(links[0]).toHaveAttribute("rel", "noopener noreferrer");
  });
});
