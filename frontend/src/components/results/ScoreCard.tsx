import type { CSSProperties } from "react";

import type { ScoreBreakdown } from "../../api/types";
import { formatPercent, formatPoints } from "../../utils/format";
import { Icon } from "../Icon";

export function ScoreCard({ score }: { score: ScoreBreakdown | null }) {
  if (!score || score.score === null || score.grade === null) {
    const reasons = score?.withholding_reasons ?? ["The assessment did not produce enough evidence."];
    return (
      <article className="score-card score-withheld">
        <div className="score-unavailable"><Icon name="info" /></div>
        <p className="eyebrow">Security posture</p>
        <h3>Score unavailable</h3>
        <p className="coverage-label">Coverage {score ? formatPercent(score.coverage) : "unavailable"}</p>
        <ul>{reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul>
      </article>
    );
  }

  const displayedScore = score.score;
  const ringStyle = { "--score-value": displayedScore } as CSSProperties;
  return (
    <article className={`score-card grade-${score.grade.toLowerCase()}`}>
      <div className="score-ring" style={ringStyle} aria-label={`Security posture score ${displayedScore} out of 100`}>
        <div>
          <strong>{displayedScore}</strong>
          <span>/100</span>
        </div>
      </div>
      <div className="score-copy">
        <p className="eyebrow">Security posture</p>
        <div className="grade-row"><strong>Grade {score.grade}</strong><span>Coverage {formatPercent(score.coverage)}</span></div>
        <p>{score.explanation}</p>
        {score.cap ? (
          <div className="cap-notice">
            <Icon name="warning" />
            <div>
              <strong>Final score capped at {score.cap.maximum_score}</strong>
              <p>Raw score {score.raw_score === null ? "unavailable" : formatPoints(score.raw_score)}. {score.cap.reason}</p>
            </div>
          </div>
        ) : null}
      </div>
    </article>
  );
}
