import type { SeverityCount } from "../../api/types";

const severityNotes = {
  HIGH: "Priority",
  MEDIUM: "Review",
  LOW: "Improve",
  INFO: "Context",
} as const;

export function SeveritySummary({ items }: { items: SeverityCount[] }) {
  return (
    <section className="severity-panel" aria-labelledby="severity-title">
      <div className="subsection-heading">
        <div><p className="eyebrow">Finding signal</p><h3 id="severity-title">Severity summary</h3></div>
        {items.find((item) => item.severity === "HIGH")?.count === 0 ? (
          <p>No HIGH findings detected by WebGuard’s current checks.</p>
        ) : null}
      </div>
      <div className="severity-grid">
        {items.map((item) => (
          <article className={`severity-item severity-${item.severity.toLowerCase()}`} key={item.severity}>
            <span className="severity-symbol" aria-hidden="true" />
            <div><strong>{item.count}</strong><span>{item.severity}</span></div>
            <small>{severityNotes[item.severity]}</small>
          </article>
        ))}
      </div>
    </section>
  );
}
