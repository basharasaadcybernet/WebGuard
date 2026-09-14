import { ApiClientError } from "./errors";
import type { ApiErrorCode, ApiErrorResponse, ScanApiResponse } from "./types";

const configuredBaseUrlValue: unknown = import.meta.env.VITE_WEBGUARD_API_URL;
const configuredBaseUrl = typeof configuredBaseUrlValue === "string"
  ? configuredBaseUrlValue.trim()
  : "";
const apiBaseUrl = configuredBaseUrl.replace(/\/$/, "");
const defaultTimeoutMs = 100_000;

type Fetcher = typeof fetch;

interface ScanOptions {
  signal?: AbortSignal;
  timeoutMs?: number;
  fetcher?: Fetcher;
}

const apiErrorCodes = new Set<ApiErrorCode>([
  "INVALID_REQUEST",
  "INVALID_TARGET",
  "INVALID_HOST",
  "REQUEST_TOO_LARGE",
  "RATE_LIMITED",
  "SERVICE_BUSY",
  "SCAN_TIMEOUT",
  "CLIENT_DISCONNECTED",
  "NOT_FOUND",
  "METHOD_NOT_ALLOWED",
  "INTERNAL_ERROR",
]);

export async function scanTarget(
  target: string,
  { signal, timeoutMs = defaultTimeoutMs, fetcher = fetch }: ScanOptions = {},
): Promise<ScanApiResponse> {
  const timeoutController = new AbortController();
  const timeoutId = window.setTimeout(() => timeoutController.abort(), timeoutMs);
  const combinedController = new AbortController();
  const abortFromCaller = (): void => combinedController.abort();
  const abortFromTimeout = (): void => combinedController.abort();
  signal?.addEventListener("abort", abortFromCaller, { once: true });
  timeoutController.signal.addEventListener("abort", abortFromTimeout, { once: true });

  try {
    const response = await fetcher(`${apiBaseUrl}/api/v1/scans`, {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({ target }),
      signal: combinedController.signal,
    });
    const payload: unknown = await readJson(response);
    if (!response.ok) {
      const apiError = asApiError(payload);
      throw new ApiClientError(apiError?.code ?? codeForStatus(response.status), {
        status: response.status,
        requestId: apiError?.request_id ?? response.headers.get("x-request-id") ?? undefined,
      });
    }
    if (!isScanApiResponse(payload)) {
      throw new ApiClientError("INTERNAL_ERROR", { status: response.status });
    }
    return payload;
  } catch (error) {
    if (error instanceof ApiClientError) {
      throw error;
    }
    if (combinedController.signal.aborted) {
      throw new ApiClientError(signal?.aborted ? "CANCELLED" : "CLIENT_TIMEOUT", {
        cause: error,
      });
    }
    throw new ApiClientError("NETWORK_ERROR", { cause: error });
  } finally {
    window.clearTimeout(timeoutId);
    signal?.removeEventListener("abort", abortFromCaller);
    timeoutController.signal.removeEventListener("abort", abortFromTimeout);
  }
}

async function readJson(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

function asApiError(value: unknown): ApiErrorResponse | null {
  if (!isRecord(value)) return null;
  const code = value.code;
  return typeof code === "string" && apiErrorCodes.has(code as ApiErrorCode)
    ? {
        code: code as ApiErrorCode,
        message: typeof value.message === "string" ? value.message : "",
        request_id: typeof value.request_id === "string" ? value.request_id : "",
      }
    : null;
}

function codeForStatus(status: number): ApiErrorCode {
  if (status === 429) return "RATE_LIMITED";
  if (status === 503) return "SERVICE_BUSY";
  if (status === 504) return "SCAN_TIMEOUT";
  if (status === 400 || status === 413 || status === 422) return "INVALID_REQUEST";
  return "INTERNAL_ERROR";
}

function isScanApiResponse(value: unknown): value is ScanApiResponse {
  if (!isRecord(value) || value.api_version !== "v1" || value.api_schema_version !== "1.0") {
    return false;
  }
  if (typeof value.request_id !== "string" || !isRecord(value.report)) return false;
  const report = value.report;
  return report.report_schema_version === "1.0" &&
    typeof report.webguard_version === "string" &&
    isOneOf(report.completion_state, ["COMPLETED", "PARTIAL", "FAILED"]) &&
    (report.target === null || isTarget(report.target)) &&
    isScanMetadata(report.scan_metadata) &&
    (report.score === null || isScore(report.score)) &&
    isArrayOf(report.severity_summary, isSeverityCount) &&
    isArrayOf(report.findings, isFinding) &&
    isArrayOf(report.operational_errors, isScanError) &&
    isArrayOf(report.methodology, isString) &&
    isArrayOf(report.limitations, isString) &&
    typeof report.disclaimer === "string";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isString(value: unknown): value is string {
  return typeof value === "string";
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

function isOneOf<const T extends readonly string[]>(value: unknown, values: T): value is T[number] {
  return typeof value === "string" && values.includes(value);
}

function isArrayOf(value: unknown, guard: (item: unknown) => boolean): boolean {
  return Array.isArray(value) && value.every(guard);
}

function hasStrings(record: Record<string, unknown>, keys: readonly string[]): boolean {
  return keys.every((key) => typeof record[key] === "string");
}

function isTarget(value: unknown): boolean {
  return isRecord(value) &&
    isOneOf(value.scheme, ["http", "https"]) &&
    hasStrings(value, ["hostname", "path", "display_url"]) &&
    isFiniteNumber(value.port);
}

function isScanMetadata(value: unknown): boolean {
  return isRecord(value) &&
    hasStrings(value, ["scan_id", "started_at", "finished_at", "webguard_version", "ruleset_version"]) &&
    isFiniteNumber(value.duration_ms) &&
    isFiniteNumber(value.redirect_count) &&
    isOneOf(value.state, ["COMPLETED", "PARTIAL", "FAILED"]);
}

function isEvidence(value: unknown): boolean {
  return isRecord(value) &&
    hasStrings(value, ["label", "value"]) &&
    (value.source_url === null || typeof value.source_url === "string");
}

function isFinding(value: unknown): boolean {
  return isRecord(value) &&
    hasStrings(value, ["id", "title", "category", "description"]) &&
    isOneOf(value.status, ["PASS", "INFO", "WARNING", "FAIL", "ERROR"]) &&
    isOneOf(value.evaluation_state, ["APPLICABLE", "NOT_APPLICABLE"]) &&
    (value.severity === null || isOneOf(value.severity, ["HIGH", "MEDIUM", "LOW", "INFO"])) &&
    isArrayOf(value.evidence, isEvidence) &&
    (value.recommendation === null || typeof value.recommendation === "string") &&
    isArrayOf(value.references, isString);
}

function isCategoryScore(value: unknown): boolean {
  return isRecord(value) &&
    hasStrings(value, [
      "category", "configured_weight", "applicable_points", "evaluated_points",
      "available_points", "earned_points", "deductions", "earned_normalized_contribution",
    ]) &&
    (value.normalized_score === null || typeof value.normalized_score === "string") &&
    (value.coverage === null || typeof value.coverage === "string");
}

function isRuleContribution(value: unknown): boolean {
  return isRecord(value) &&
    hasStrings(value, [
      "rule_id", "category", "configured_points", "available_points", "earned_points",
      "deduction", "reason",
    ]) &&
    isOneOf(value.state, ["PASS", "INFO", "WARNING", "FAIL", "ERROR", "NOT_APPLICABLE"]) &&
    (value.credit_fraction === null || typeof value.credit_fraction === "string") &&
    (value.exclusion_reason === null || typeof value.exclusion_reason === "string");
}

function isRuleExclusion(value: unknown): boolean {
  return isRecord(value) &&
    hasStrings(value, ["rule_id", "reason"]) &&
    isOneOf(value.state, ["ERROR", "NOT_APPLICABLE"]);
}

function isScoreCap(value: unknown): boolean {
  return isRecord(value) &&
    hasStrings(value, ["rule_id", "reason"]) &&
    isOneOf(value.trigger_status, ["PASS", "INFO", "WARNING", "FAIL", "ERROR"]) &&
    isFiniteNumber(value.maximum_score) && value.maximum_score >= 0 && value.maximum_score <= 100;
}

function isScore(value: unknown): boolean {
  return isRecord(value) &&
    hasStrings(value, [
      "scoring_version", "configured_points", "applicable_points", "evaluated_points",
      "available_points", "earned_points", "deductions", "coverage", "explanation",
    ]) &&
    (value.raw_score === null || typeof value.raw_score === "string") &&
    (value.score === null || (
      isFiniteNumber(value.score) && value.score >= 0 && value.score <= 100
    )) &&
    (value.grade === null || isOneOf(value.grade, ["A", "B", "C", "D", "F"])) &&
    isArrayOf(value.categories, isCategoryScore) &&
    isArrayOf(value.rule_contributions, isRuleContribution) &&
    isArrayOf(value.exclusions, isRuleExclusion) &&
    (value.cap === null || isScoreCap(value.cap)) &&
    isArrayOf(value.withholding_reasons, isString);
}

function isSeverityCount(value: unknown): boolean {
  return isRecord(value) &&
    isOneOf(value.severity, ["HIGH", "MEDIUM", "LOW", "INFO"]) &&
    isFiniteNumber(value.count);
}

function isScanError(value: unknown): boolean {
  return isRecord(value) &&
    isOneOf(value.kind, ["TARGET", "NETWORK", "CHECK"]) &&
    hasStrings(value, ["code", "message"]) &&
    (value.rule_id === null || typeof value.rule_id === "string");
}
