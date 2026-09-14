import { useMemo, useState } from "react";

import type { Finding, RuleContribution, Severity } from "../../api/types";
import { FindingCard } from "./FindingCard";

type FindingFilter = "ALL" | Severity;
const filters: FindingFilter[] = ["ALL", "HIGH", "MEDIUM", "LOW", "INFO"];
const cookieRuleIds = new Set(["cookies.secure", "cookies.http_only", "cookies.same_site"]);

function CookieNotApplicableCard({ findings }: { findings: Finding[] }) {
  return (
    <details className="finding-card cookie-context-card">
      <summary>
        <div className="finding-summary-copy">
          <span className="severity-badge not-applicable-badge"><span aria-hidden="true" />N/A</span>
          <div><h3>Cookie Security</h3><p>3 rule-level observations</p></div>
        </div>
        <div className="finding-status"><span>NOT APPLICABLE</span></div>
      </summary>
      <div className="finding-detail">
        <section><h4>Context</h4><p>No cookies were observed in the validated landing response or redirect chain. Cookie attributes were therefore not applicable and received no security credit.</p></section>
        <section><h4>Rule-level data retained</h4><ul className="context-rule-list">{findings.map((finding) => <li key={finding.id}><code>{finding.id}</code></li>)}</ul></section>
      </div>
    </details>
  );
}

export function FindingsSection({ findings, contributions }: { findings: Finding[]; contributions: RuleContribution[] }) {
  const [filter, setFilter] = useState<FindingFilter>("ALL");
  const contributionMap = useMemo(
    () => new Map(contributions.map((item) => [item.rule_id, item])),
    [contributions],
  );
  const cookieContext = findings.filter((finding) => cookieRuleIds.has(finding.id));
  const groupCookieContext = cookieContext.length === 3
    && cookieContext.every((finding) => finding.evaluation_state === "NOT_APPLICABLE"
      && finding.evidence.some((item) => item.value.toLowerCase().includes("no cookies were observed")));
  const presentedFindings = groupCookieContext
    ? findings.filter((finding) => !cookieRuleIds.has(finding.id))
    : findings;
  const showCookieContext = groupCookieContext && (filter === "ALL" || filter === "INFO");
  const filtered = presentedFindings.filter((finding) => filter === "ALL" || (finding.severity ?? "INFO") === filter);
  const countFor = (candidate: FindingFilter): number => candidate === "ALL"
    ? presentedFindings.length + (groupCookieContext ? 1 : 0)
    : presentedFindings.filter((finding) => (finding.severity ?? "INFO") === candidate).length
      + (groupCookieContext && candidate === "INFO" ? 1 : 0);

  return (
    <section className="findings-section" aria-labelledby="findings-title">
      <div className="section-heading findings-heading">
        <div><p className="eyebrow">Observed posture</p><h2 id="findings-title">Findings and recommendations</h2></div>
        <p>Open a finding for evidence, practical guidance, references, and scoring impact.</p>
      </div>
      <div className="filter-row" aria-label="Filter findings by severity">
        {filters.map((candidate) => (
          <button
            type="button"
            key={candidate}
            className={filter === candidate ? "active" : ""}
            aria-pressed={filter === candidate}
            onClick={() => setFilter(candidate)}
          >
            {candidate === "ALL" ? "All" : candidate}<span>{countFor(candidate)}</span>
          </button>
        ))}
      </div>
      <div className="finding-list">
        {showCookieContext ? <CookieNotApplicableCard findings={cookieContext} /> : null}
        {filtered.map((finding) => (
          <FindingCard key={finding.id} finding={finding} contribution={contributionMap.get(finding.id)} />
        ))}
        {!filtered.length && !showCookieContext ? <p className="empty-filter">No findings match this severity filter.</p> : null}
      </div>
    </section>
  );
}
