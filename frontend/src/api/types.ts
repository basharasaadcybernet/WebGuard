export type DecimalString = string;
export type ScanState = "COMPLETED" | "PARTIAL" | "FAILED";
export type Severity = "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type FindingStatus = "PASS" | "INFO" | "WARNING" | "FAIL" | "ERROR";
export type RuleEvaluationState =
  | "PASS"
  | "INFO"
  | "WARNING"
  | "FAIL"
  | "ERROR"
  | "NOT_APPLICABLE";
export type Grade = "A" | "B" | "C" | "D" | "F";
export type ScanErrorKind = "TARGET" | "NETWORK" | "CHECK";

export interface NormalizedTarget {
  scheme: "http" | "https";
  hostname: string;
  port: number;
  path: string;
  display_url: string;
}

export interface Evidence {
  label: string;
  value: string;
  source_url: string | null;
}

export interface Finding {
  id: string;
  title: string;
  category: string;
  status: FindingStatus;
  evaluation_state: "APPLICABLE" | "NOT_APPLICABLE";
  severity: Severity | null;
  description: string;
  evidence: Evidence[];
  recommendation: string | null;
  references: string[];
}

export interface CategoryScore {
  category: string;
  configured_weight: DecimalString;
  applicable_points: DecimalString;
  evaluated_points: DecimalString;
  available_points: DecimalString;
  earned_points: DecimalString;
  deductions: DecimalString;
  normalized_score: DecimalString | null;
  earned_normalized_contribution: DecimalString;
  coverage: DecimalString | null;
}

export interface RuleContribution {
  rule_id: string;
  category: string;
  state: RuleEvaluationState;
  configured_points: DecimalString;
  available_points: DecimalString;
  earned_points: DecimalString;
  deduction: DecimalString;
  credit_fraction: DecimalString | null;
  reason: string;
  exclusion_reason: string | null;
}

export interface RuleExclusion {
  rule_id: string;
  state: "ERROR" | "NOT_APPLICABLE";
  reason: string;
}

export interface AppliedScoreCap {
  rule_id: string;
  trigger_status: FindingStatus;
  maximum_score: number;
  reason: string;
}

export interface ScoreBreakdown {
  raw_score: DecimalString | null;
  score: number | null;
  grade: Grade | null;
  scoring_version: string;
  configured_points: DecimalString;
  applicable_points: DecimalString;
  evaluated_points: DecimalString;
  available_points: DecimalString;
  earned_points: DecimalString;
  deductions: DecimalString;
  coverage: DecimalString;
  categories: CategoryScore[];
  rule_contributions: RuleContribution[];
  exclusions: RuleExclusion[];
  cap: AppliedScoreCap | null;
  withholding_reasons: string[];
  explanation: string;
}

export interface ScanMetadata {
  scan_id: string;
  started_at: string;
  finished_at: string;
  duration_ms: number;
  webguard_version: string;
  ruleset_version: string;
  redirect_count: number;
  state: ScanState;
}

export interface ScanError {
  kind: ScanErrorKind;
  code: string;
  message: string;
  rule_id: string | null;
}

export interface SeverityCount {
  severity: Severity;
  count: number;
}

export interface ReportDocument {
  report_schema_version: "1.0";
  webguard_version: string;
  target: NormalizedTarget | null;
  scan_metadata: ScanMetadata;
  completion_state: ScanState;
  score: ScoreBreakdown | null;
  severity_summary: SeverityCount[];
  findings: Finding[];
  operational_errors: ScanError[];
  methodology: string[];
  limitations: string[];
  disclaimer: string;
}

export interface ScanApiResponse {
  api_version: "v1";
  api_schema_version: "1.0";
  request_id: string;
  report: ReportDocument;
}

export type ApiErrorCode =
  | "INVALID_REQUEST"
  | "INVALID_TARGET"
  | "INVALID_HOST"
  | "REQUEST_TOO_LARGE"
  | "RATE_LIMITED"
  | "SERVICE_BUSY"
  | "SCAN_TIMEOUT"
  | "CLIENT_DISCONNECTED"
  | "NOT_FOUND"
  | "METHOD_NOT_ALLOWED"
  | "INTERNAL_ERROR";

export interface ApiErrorResponse {
  code: ApiErrorCode;
  message: string;
  request_id: string;
}
