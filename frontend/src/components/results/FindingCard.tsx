import type { Finding, RuleContribution } from "../../api/types";
import { formatPoints, safeExternalHref } from "../../utils/format";
import { Icon } from "../Icon";

export function FindingCard({ finding, contribution }: { finding: Finding; contribution?: RuleContribution }) {
  const severity = finding.severity ?? "INFO";
  const safeReferences = finding.references
    .map((reference) => ({ label: reference, href: safeExternalHref(reference) }))
    .filter((reference): reference is { label: string; href: string } => reference.href !== null);

  return (
    <details className={`finding-card severity-${severity.toLowerCase()}`}>
      <summary>
        <div className="finding-summary-copy">
          <span className="severity-badge"><span aria-hidden="true" />{severity}</span>
          <div><h3>{finding.title}</h3><p>{finding.category} · <code>{finding.id}</code></p></div>
        </div>
        <div className="finding-status"><span>{finding.status}</span><Icon name="chevron" /></div>
      </summary>
      <div className="finding-detail">
        <section><h4>Description</h4><p>{finding.description}</p></section>
        {finding.evidence.length ? (
          <section>
            <h4>Evidence</h4>
            <dl className="evidence-list">
              {finding.evidence.map((item, index) => (
                <div key={`${item.label}-${index}`}><dt>{item.label}</dt><dd><code>{item.value}</code>{item.source_url ? <small>{item.source_url}</small> : null}</dd></div>
              ))}
            </dl>
          </section>
        ) : null}
        {finding.recommendation ? <section className="recommendation"><h4>Recommendation</h4><p>{finding.recommendation}</p></section> : null}
        {contribution ? (
          <section>
            <h4>Scoring impact</h4>
            <div className="impact-grid">
              <span>Available <strong>{formatPoints(contribution.available_points)}</strong></span>
              <span>Earned <strong>{formatPoints(contribution.earned_points)}</strong></span>
              <span>Deducted <strong>{formatPoints(contribution.deduction)}</strong></span>
            </div>
            <p className="detail-note">{contribution.reason}</p>
          </section>
        ) : null}
        {safeReferences.length ? (
          <section><h4>References</h4><ul className="reference-list">{safeReferences.map((reference) => (
            <li key={reference.href}><a href={reference.href} target="_blank" rel="noopener noreferrer">{reference.label}<Icon name="external" /></a></li>
          ))}</ul></section>
        ) : null}
      </div>
    </details>
  );
}
