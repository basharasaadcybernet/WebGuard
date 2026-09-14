import type { CategoryScore } from "../../api/types";
import { formatPercent, formatPoints, percentage } from "../../utils/format";

export function CategoryBreakdown({ categories }: { categories: CategoryScore[] }) {
  return (
    <section className="category-panel" aria-labelledby="category-title">
      <div className="subsection-heading">
        <div><p className="eyebrow">Transparent scoring</p><h3 id="category-title">Category breakdown</h3></div>
        <p>Contribution and coverage come directly from scoring ruleset 1.0.</p>
      </div>
      <div className="category-list">
        {categories.map((category) => {
          const progress = percentage(category.normalized_score) ?? 0;
          return (
            <article className="category-row" key={category.category}>
              <div className="category-main">
                <div className="category-title-row">
                  <h4>{category.category}</h4>
                  <strong>{formatPoints(category.earned_normalized_contribution)}<span> / {formatPoints(category.configured_weight)}</span></strong>
                </div>
                <div className="progress-track" aria-label={`${category.category} normalized score ${Math.round(progress)} percent`}>
                  <span style={{ width: `${progress}%` }} />
                </div>
              </div>
              <dl>
                <div><dt>Available</dt><dd>{formatPoints(category.available_points)} pts</dd></div>
                <div><dt>Coverage</dt><dd>{formatPercent(category.coverage)}</dd></div>
              </dl>
            </article>
          );
        })}
      </div>
    </section>
  );
}
