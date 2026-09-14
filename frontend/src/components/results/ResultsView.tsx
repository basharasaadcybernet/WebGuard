import type { ReactNode } from "react";

import type { ReportDocument } from "../../api/types";
import { formatDate, formatDuration, redactTargetForDisplay } from "../../utils/format";
import { Icon } from "../Icon";
import { CategoryBreakdown } from "./CategoryBreakdown";
import { FindingsSection } from "./FindingsSection";
import { OperationalErrors } from "./OperationalErrors";
import { ProfessionalCTA } from "./ProfessionalCTA";
import { ScoreCard } from "./ScoreCard";
import { SeveritySummary } from "./SeveritySummary";

interface ResultsViewProps {
  report: ReportDocument;
  submittedTarget: string;
  onRetry: () => void;
  expertRecommendations?: ReactNode;
}

export function ResultsView({ report, submittedTarget, onRetry, expertRecommendations }: ResultsViewProps) {
  const metadata = report.scan_metadata;
  const target = report.target?.display_url ?? redactTargetForDisplay(submittedTarget);

  if (report.completion_state === "FAILED") {
    return (
      <section className="failed-result" aria-labelledby="failed-title">
        <div className="state-icon"><Icon name="warning" /></div>
        <p className="eyebrow">Assessment failed</p>
        <h2 id="failed-title">WebGuard could not produce a reliable assessment.</h2>
        <p className="failed-target">{target}</p>
        <OperationalErrors errors={report.operational_errors} />
        <button type="button" className="secondary-button" onClick={onRetry}>Try another address</button>
        <p className="permanent-disclaimer">{report.disclaimer}</p>
      </section>
    );
  }

  return (
    <div className="results-view">
      <header className="result-header">
        <div>
          <p className="eyebrow">Assessment complete</p>
          <h2>{target}</h2>
          <div className="result-meta">
            <span className={`state-badge state-${report.completion_state.toLowerCase()}`}><span aria-hidden="true" />{report.completion_state}</span>
            <span>{formatDate(metadata.finished_at)}</span>
            <span>{formatDuration(metadata.duration_ms)}</span>
          </div>
        </div>
        <button type="button" className="secondary-button" onClick={onRetry}><Icon name="scan" />Scan another site</button>
      </header>

      {report.completion_state === "PARTIAL" ? (
        <div className="partial-notice" role="status"><Icon name="info" /><div><strong>WebGuard completed only part of the assessment.</strong><p>Review the operational notes alongside the available findings and coverage.</p></div></div>
      ) : null}

      <div className="overview-grid">
        <ScoreCard score={report.score} />
        <SeveritySummary items={report.severity_summary} />
      </div>
      {report.score ? <CategoryBreakdown categories={report.score.categories} /> : null}
      <OperationalErrors errors={report.operational_errors} />
      <FindingsSection findings={report.findings} contributions={report.score?.rule_contributions ?? []} />
      {expertRecommendations}
      <section className="limitations" aria-labelledby="limitations-title">
        <div><p className="eyebrow">Read with context</p><h2 id="limitations-title">Scope and limitations</h2></div>
        <ul>{report.limitations.map((limitation) => <li key={limitation}><Icon name="info" />{limitation}</li>)}</ul>
        <p className="permanent-disclaimer"><Icon name="shield" />{report.disclaimer}</p>
      </section>
      <ProfessionalCTA />
    </div>
  );
}
