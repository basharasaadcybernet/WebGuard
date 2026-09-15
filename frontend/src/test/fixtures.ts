import type {
  CategoryScore,
  Finding,
  ReportDocument,
  RuleContribution,
  ScanApiResponse,
  ScoreBreakdown,
} from "../api/types";

export function makeScore(overrides: Partial<ScoreBreakdown> = {}): ScoreBreakdown {
  return {
    raw_score: "82.0",
    score: 82,
    grade: "B",
    scoring_version: "1.0",
    configured_points: "100.0",
    applicable_points: "100.0",
    evaluated_points: "100.0",
    available_points: "100.0",
    earned_points: "82.0",
    deductions: "18.0",
    coverage: "1.0",
    categories: [
      {
        category: "Transport Security",
        configured_weight: "30.0",
        applicable_points: "30.0",
        evaluated_points: "30.0",
        available_points: "30.0",
        earned_points: "24.0",
        deductions: "6.0",
        normalized_score: "0.8",
        earned_normalized_contribution: "24.0",
        coverage: "1.0",
      },
      {
        category: "Security Headers",
        configured_weight: "25.0",
        applicable_points: "25.0",
        evaluated_points: "25.0",
        available_points: "25.0",
        earned_points: "20.0",
        deductions: "5.0",
        normalized_score: "0.8",
        earned_normalized_contribution: "20.0",
        coverage: "1.0",
      },
    ],
    rule_contributions: [
      {
        rule_id: "TLS-001",
        category: "Transport Security",
        state: "FAIL",
        configured_points: "10.0",
        available_points: "10.0",
        earned_points: "0.0",
        deduction: "10.0",
        credit_fraction: "0.0",
        reason: "The expected transport property was not observed.",
        exclusion_reason: null,
      },
    ],
    exclusions: [],
    cap: null,
    withholding_reasons: [],
    explanation: "The final score and grade are produced by the WebGuard scoring engine.",
    ...overrides,
  };
}

export function makeReport(overrides: Partial<ReportDocument> = {}): ReportDocument {
  return {
    report_schema_version: "1.0",
    webguard_version: "0.1.0.dev0",
    target: {
      scheme: "https",
      hostname: "example.com",
      port: 443,
      path: "/",
      display_url: "https://example.com/",
    },
    scan_metadata: {
      scan_id: "11111111-1111-4111-8111-111111111111",
      started_at: "2026-09-14T10:00:00Z",
      finished_at: "2026-09-14T10:00:01Z",
      duration_ms: 1250,
      webguard_version: "0.1.0.dev0",
      ruleset_version: "1.0",
      redirect_count: 0,
      state: "COMPLETED",
    },
    completion_state: "COMPLETED",
    score: makeScore(),
    severity_summary: [
      { severity: "HIGH", count: 1 },
      { severity: "MEDIUM", count: 1 },
      { severity: "LOW", count: 1 },
      { severity: "INFO", count: 1 },
    ],
    findings: [
      {
        id: "TLS-001",
        title: "TLS certificate validation",
        category: "Transport Security",
        status: "FAIL",
        evaluation_state: "APPLICABLE",
        severity: "HIGH",
        description: "The certificate could not be validated.",
        evidence: [{ label: "Result", value: "certificate verify failed", source_url: null }],
        recommendation: "Install and serve a valid certificate chain.",
        references: ["https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security"],
      },
      {
        id: "HDR-001",
        title: "Content Security Policy",
        category: "Security Headers",
        status: "WARNING",
        evaluation_state: "APPLICABLE",
        severity: "MEDIUM",
        description: "A restrictive policy was not observed.",
        evidence: [{ label: "Header", value: "not present", source_url: "https://example.com/" }],
        recommendation: "Deploy a tested Content-Security-Policy header.",
        references: [],
      },
      {
        id: "CKI-001",
        title: "Cookie attributes",
        category: "Cookie Security",
        status: "WARNING",
        evaluation_state: "APPLICABLE",
        severity: "LOW",
        description: "A cookie can use stronger attributes.",
        evidence: [],
        recommendation: "Review Secure and SameSite attributes.",
        references: [],
      },
      {
        id: "INF-001",
        title: "Server disclosure",
        category: "Information Disclosure / Hygiene",
        status: "INFO",
        evaluation_state: "APPLICABLE",
        severity: "INFO",
        description: "A server product token was observed.",
        evidence: [],
        recommendation: null,
        references: [],
      },
    ],
    operational_errors: [],
    methodology: ["Passive, bounded HTTP observations."],
    limitations: ["This point-in-time assessment does not prove the absence of vulnerabilities."],
    disclaimer: "WebGuard results are informational and are not a guarantee of security.",
    ...overrides,
  };
}

export function makeResponse(reportOverrides: Partial<ReportDocument> = {}): ScanApiResponse {
  return {
    api_version: "v1",
    api_schema_version: "1.0",
    request_id: "22222222-2222-4222-8222-222222222222",
    report: makeReport(reportOverrides),
  };
}

const failedRuleWeights: Record<string, string> = {
  "transport.https_available": "10",
  "transport.http_redirect": "4",
  "transport.tls_validity": "6",
  "transport.tls_hostname": "4",
  "transport.tls_expiry": "3",
  "transport.https_downgrade": "3",
  "headers.strict_transport_security": "7",
  "headers.content_security_policy": "10",
  "headers.x_content_type_options": "5",
  "headers.referrer_policy": "4",
  "headers.permissions_policy": "2",
  "headers.clickjacking_protection": "7",
  "cookies.secure": "7",
  "cookies.http_only": "3",
  "cookies.same_site": "5",
  "content.mixed_content": "10",
  "hygiene.security_txt": "4",
  "hygiene.server_disclosure": "3",
  "hygiene.x_powered_by": "3",
};

function categoryForRule(ruleId: string): string {
  const prefix = ruleId.split(".")[0];
  return {
    transport: "Transport Security",
    headers: "Security Headers",
    cookies: "Cookie Security",
    content: "Content Protection",
    hygiene: "Information Disclosure / Hygiene",
  }[prefix ?? ""] ?? "Unknown";
}

const failedFindings: Finding[] = [
  {
    id: "transport.http_redirect",
    title: "HTTP to HTTPS redirect",
    category: "Transport Security",
    status: "FAIL",
    evaluation_state: "APPLICABLE",
    severity: "MEDIUM",
    description: "The tested HTTP endpoint did not direct clients to HTTPS.",
    evidence: [{ label: "Observation", value: "HTTP remained available.", source_url: "http://forsa.sy/" }],
    recommendation: "Redirect HTTP requests directly to HTTPS.",
    references: [],
  },
  {
    id: "transport.https_available",
    title: "HTTPS availability",
    category: "Transport Security",
    status: "FAIL",
    evaluation_state: "APPLICABLE",
    severity: "MEDIUM",
    description: "WebGuard could not obtain a verified HTTPS response.",
    evidence: [{ label: "Observation", value: "No verified HTTPS response was available.", source_url: "https://forsa.sy/" }],
    recommendation: "Provide a reachable verified HTTPS endpoint.",
    references: [],
  },
];

function failedCategories(evaluated: string): CategoryScore[] {
  return [
    {
      category: "Transport Security",
      configured_weight: "30",
      applicable_points: "30",
      evaluated_points: evaluated,
      available_points: evaluated,
      earned_points: "0",
      deductions: evaluated,
      normalized_score: "0",
      earned_normalized_contribution: "0",
      coverage: evaluated === "14" ? "0.467" : "0.667",
    },
    ...["Security Headers", "Cookie Security", "Content Protection", "Information Disclosure / Hygiene"].map((category) => ({
      category,
      configured_weight: category === "Security Headers" ? "35" : category === "Cookie Security" ? "15" : "10",
      applicable_points: category === "Security Headers" ? "35" : category === "Cookie Security" ? "15" : "10",
      evaluated_points: "0",
      available_points: "0",
      earned_points: "0",
      deductions: "0",
      normalized_score: null,
      earned_normalized_contribution: "0",
      coverage: "0",
    })),
  ];
}

export function makeFailedAssessmentReport(
  mode: "timeout" | "untrusted" = "timeout",
): ReportDocument {
  const tlsTrustFinding: Finding = {
    id: "transport.tls_validity",
    title: "TLS certificate trust",
    category: "Transport Security",
    status: "FAIL",
    evaluation_state: "APPLICABLE",
    severity: "HIGH",
    description: "The TLS certificate chain was not trusted.",
    evidence: [{ label: "Observation", value: "Certificate trust validation failed.", source_url: "https://forsa.sy/" }],
    recommendation: "Install a complete trusted certificate chain.",
    references: [],
  };
  const findings = mode === "untrusted" ? [...failedFindings, tlsTrustFinding] : failedFindings;
  const evaluatedIds = new Set(findings.map((finding) => finding.id));
  const contributions: RuleContribution[] = Object.entries(failedRuleWeights).map(
    ([ruleId, configuredPoints]) => evaluatedIds.has(ruleId)
      ? {
          rule_id: ruleId,
          category: categoryForRule(ruleId),
          state: "FAIL",
          configured_points: configuredPoints,
          available_points: configuredPoints,
          earned_points: "0",
          deduction: configuredPoints,
          credit_fraction: "0",
          reason: findings.find((finding) => finding.id === ruleId)!.description,
          exclusion_reason: null,
        }
      : {
          rule_id: ruleId,
          category: categoryForRule(ruleId),
          state: "NOT_EVALUATED",
          configured_points: configuredPoints,
          available_points: "0",
          earned_points: "0",
          deduction: "0",
          credit_fraction: null,
          reason: "The check could not evaluate the available observations.",
          exclusion_reason: "Rule evaluation failed; its points were excluded.",
        },
  );
  const unevaluated = contributions.filter((item) => item.state === "NOT_EVALUATED");
  const evaluated = mode === "untrusted" ? "20" : "14";
  const coverage = mode === "untrusted" ? "0.200" : "0.140";
  const networkCode = mode === "untrusted"
    ? "tls.certificate_untrusted"
    : "network.connection_timeout";
  const networkMessage = mode === "untrusted"
    ? "The TLS certificate chain could not be trusted."
    : "The protected request exceeded its configured timeout.";

  return makeReport({
    target: { scheme: "https", hostname: "forsa.sy", port: 443, path: "/", display_url: "https://forsa.sy/" },
    completion_state: "FAILED",
    scan_metadata: { ...makeReport().scan_metadata, state: "FAILED" },
    score: makeScore({
      raw_score: null,
      score: null,
      grade: null,
      applicable_points: "100",
      evaluated_points: evaluated,
      available_points: evaluated,
      earned_points: "0",
      deductions: evaluated,
      coverage,
      categories: failedCategories(evaluated),
      rule_contributions: contributions,
      exclusions: unevaluated.map((item) => ({
        rule_id: item.rule_id,
        state: "NOT_EVALUATED",
        reason: item.exclusion_reason!,
      })),
      withholding_reasons: [
        `Evaluated coverage ${coverage} is below the configured minimum 0.700.`,
      ],
      explanation: "Scan incomplete — insufficient coverage for a reliable score.",
    }),
    severity_summary: [
      { severity: "HIGH", count: mode === "untrusted" ? 1 : 0 },
      { severity: "MEDIUM", count: 2 },
      { severity: "LOW", count: 0 },
      { severity: "INFO", count: 0 },
    ],
    findings,
    operational_errors: [
      { kind: "NETWORK", code: networkCode, message: networkMessage, rule_id: null },
      ...unevaluated.map((item) => ({
        kind: "CHECK" as const,
        code: "check.evaluation_failed",
        message: "The check could not evaluate the available observations.",
        rule_id: item.rule_id,
      })),
    ],
  });
}
