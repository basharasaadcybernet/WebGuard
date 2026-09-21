import { Icon } from "./Icon";

const benefits = [
  ["Passive by design", "Low-impact observations through WebGuard’s protected network boundary."],
  ["Evidence, not guesswork", "Findings stay tied to concise technical observations."],
  ["Transparent scoring", "Coverage, contributions, exclusions, and caps remain visible."],
  ["Useful next steps", "Each finding explains what was observed and how to improve it."],
] as const;

const areas = ["Transport", "Security headers", "Cookies", "Content", "Security hygiene"];

export function ScopeOverview() {
  return (
    <section className="scope-section" id="coverage" aria-labelledby="coverage-title">
      <div className="section-heading compact-heading">
        <div>
          <p className="eyebrow">A precise first look</p>
          <h2 id="coverage-title">Focused on the controls that matter at the edge.</h2>
        </div>
        <p>
          WebGuard v0.1 evaluates 19 defined passive checks and tells you when evidence is
          incomplete. It does not turn uncertainty into a security claim.
        </p>
      </div>
      <div className="benefit-grid">
        {benefits.map(([title, description], index) => (
          <article className="benefit-card" key={title}>
            <span className="benefit-index">0{index + 1}</span>
            <Icon name={index === 0 ? "shield" : index === 1 ? "document" : index === 2 ? "spark" : "check"} />
            <h3>{title}</h3>
            <p>{description}</p>
          </article>
        ))}
      </div>
      <div className="assessment-areas" aria-label="Assessment areas">
        {areas.map((area) => <span key={area}>{area}</span>)}
      </div>
      <p className="privacy-note">
        <Icon name="lock" /> This interface keeps results only in this page’s current memory. WebGuard v0.1
        has no persistent scan-history database.
      </p>
    </section>
  );
}
