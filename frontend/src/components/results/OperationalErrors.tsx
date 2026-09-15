import type { ScanError } from "../../api/types";
import { Icon } from "../Icon";

const errorTitles: Record<string, string> = {
  "network.connection_timeout": "Connection timed out",
  "network.connection_refused": "Connection refused",
  "network.connection_terminated": "Connection ended early",
  "network.dns_resolution_failed": "DNS resolution failed",
  "network.redirect_rejected": "Redirect rejected",
  "network.destination_blocked": "Destination blocked",
  "tls.handshake_failed": "TLS handshake failed",
  "tls.certificate_untrusted": "TLS certificate not trusted",
  "tls.certificate_expired": "TLS certificate expired",
  "tls.hostname_mismatch": "TLS hostname mismatch",
};

export function OperationalErrors({ errors }: { errors: ScanError[] }) {
  if (!errors.length) return null;
  const unevaluated = errors.filter(
    (error) => error.code === "check.evaluation_failed" && error.rule_id !== null,
  );
  const distinct = errors.filter(
    (error) => error.code !== "check.evaluation_failed" || error.rule_id === null,
  );
  return (
    <section className="operational-errors" aria-labelledby="operational-title">
      <div><Icon name="warning" /><div><p className="eyebrow">Assessment coverage</p><h3 id="operational-title">Operational limitations</h3></div></div>
      <p>These are execution limitations, not FAIL security findings. A linked rule was not evaluated and reduces coverage.</p>
      <ul>
        {distinct.map((error, index) => (
          <li key={`${error.code}-${index}`}>
            <strong>{errorTitles[error.code] ?? "Operational limitation"}</strong>
            <span>{error.message}</span>
            <code>{error.code}</code>
          </li>
        ))}
        {unevaluated.length ? (
          <li className="unevaluated-summary">
            <strong>{unevaluated.length} {unevaluated.length === 1 ? "check" : "checks"} not evaluated</strong>
            <span>The required page observations were unavailable. These checks reduce assessment coverage.</span>
            <details>
              <summary>View affected rules</summary>
              <div>{unevaluated.map((error) => <code key={error.rule_id}>{error.rule_id}</code>)}</div>
            </details>
          </li>
        ) : null}
      </ul>
    </section>
  );
}
