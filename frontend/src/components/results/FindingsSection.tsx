import { useMemo, useState } from "react";

import type { Finding, RuleContribution, Severity } from "../../api/types";
import { FindingCard } from "./FindingCard";

type FindingFilter = "ALL" | Severity;
const filters: FindingFilter[] = ["ALL", "HIGH", "MEDIUM", "LOW", "INFO"];

export function FindingsSection({ findings, contributions }: { findings: Finding[]; contributions: RuleContribution[] }) {
  const [filter, setFilter] = useState<FindingFilter>("ALL");
  const contributionMap = useMemo(
    () => new Map(contributions.map((item) => [item.rule_id, item])),
    [contributions],
  );
  const filtered = findings.filter((finding) => filter === "ALL" || (finding.severity ?? "INFO") === filter);
  const countFor = (candidate: FindingFilter): number => candidate === "ALL"
    ? findings.length
    : findings.filter((finding) => (finding.severity ?? "INFO") === candidate).length;

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
        {filtered.length ? filtered.map((finding) => (
          <FindingCard key={finding.id} finding={finding} contribution={contributionMap.get(finding.id)} />
        )) : <p className="empty-filter">No findings match this severity filter.</p>}
      </div>
    </section>
  );
}
