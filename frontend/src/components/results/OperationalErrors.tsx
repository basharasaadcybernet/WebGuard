import type { ScanError } from "../../api/types";
import { Icon } from "../Icon";

export function OperationalErrors({ errors }: { errors: ScanError[] }) {
  if (!errors.length) return null;
  return (
    <section className="operational-errors" aria-labelledby="operational-title">
      <div><Icon name="warning" /><div><p className="eyebrow">Assessment coverage</p><h3 id="operational-title">Operational limitations</h3></div></div>
      <p>These are execution limitations, not FAIL security findings. A linked rule was not evaluated and reduces coverage.</p>
      <ul>{errors.map((error, index) => <li key={`${error.code}-${index}`}><strong>{error.code}</strong><span>{error.message}</span>{error.rule_id ? <code>NOT EVALUATED · {error.rule_id}</code> : null}</li>)}</ul>
    </section>
  );
}
