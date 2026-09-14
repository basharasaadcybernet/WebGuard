import { Icon } from "./Icon";

export function ScanProgress({ target, onCancel }: { target: string; onCancel: () => void }) {
  return (
    <section className="scan-progress" aria-live="polite" aria-busy="true">
      <div className="scan-orbit" aria-hidden="true">
        <span /><Icon name="shield" />
      </div>
      <div>
        <p className="eyebrow">Assessment in progress</p>
        <h2>Analyzing security posture…</h2>
        <p className="target-line">{target}</p>
        <p>
          WebGuard is collecting a bounded set of passive observations. No fabricated steps or
          active exploitation are performed.
        </p>
        <button type="button" className="text-button" onClick={onCancel}>Cancel assessment</button>
      </div>
    </section>
  );
}
