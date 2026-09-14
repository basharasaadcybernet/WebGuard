import { safeContactHref } from "../../utils/format";
import { Icon } from "../Icon";

export function ProfessionalCTA() {
  const configuredContactValue: unknown = import.meta.env.VITE_CYBERNET_CONTACT_URL;
  const href = safeContactHref(
    typeof configuredContactValue === "string" ? configuredContactValue : undefined,
  );
  return (
    <section className="professional-cta" aria-labelledby="cta-title">
      <div className="cta-mark"><Icon name="shield" /></div>
      <div><p className="eyebrow">CyberNet professional services</p><h2 id="cta-title">Need help prioritizing or remediating these findings?</h2><p>Turn posture observations into a focused improvement plan with a professional security review.</p></div>
      {href ? (
        <a className="primary-button" href={href} target={href.startsWith("mailto:") ? undefined : "_blank"} rel={href.startsWith("mailto:") ? undefined : "noopener noreferrer"}>Request a security review<Icon name="arrow" /></a>
      ) : (
        <button className="primary-button disabled-action" type="button" disabled title="Contact destination is not configured">Request a security review<Icon name="arrow" /></button>
      )}
    </section>
  );
}
