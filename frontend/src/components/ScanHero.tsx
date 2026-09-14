import { useId, useState, type FormEvent } from "react";

import { validateTarget } from "../utils/target";
import { Icon } from "./Icon";

interface ScanHeroProps {
  busy: boolean;
  initialValue?: string;
  onSubmit: (target: string) => void;
}

export function ScanHero({ busy, initialValue = "", onSubmit }: ScanHeroProps) {
  const [target, setTarget] = useState(initialValue);
  const [error, setError] = useState<string | null>(null);
  const inputId = useId();
  const errorId = `${inputId}-error`;

  const submit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    const validation = validateTarget(target);
    setTarget(validation.value);
    setError(validation.error);
    if (!validation.error) onSubmit(validation.value);
  };

  return (
    <section className="hero" id="scan" aria-labelledby="hero-title">
      <div className="hero-glow" aria-hidden="true" />
      <div className="hero-copy">
        <div className="eyebrow"><span /> Web Security Posture Auditor</div>
        <h1 id="hero-title">See your website’s security posture with clarity.</h1>
        <p className="hero-intro">
          A focused, evidence-based assessment of the protections visible from the public web—
          without exploitation or credentials.
        </p>
      </div>

      <form className="scan-form" onSubmit={submit} noValidate>
        <label htmlFor={inputId}>Website address</label>
        <div className={`url-control${error ? " has-error" : ""}`}>
          <span className="url-icon"><Icon name="shield" /></span>
          <input
            id={inputId}
            type="url"
            inputMode="url"
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck="false"
            autoComplete="url"
            maxLength={2048}
            placeholder="https://example.com"
            value={target}
            onChange={(event) => {
              setTarget(event.target.value);
              if (error) setError(null);
            }}
            aria-describedby={error ? errorId : undefined}
            aria-invalid={Boolean(error)}
            disabled={busy}
          />
          <button className="primary-button" type="submit" disabled={busy}>
            {busy ? "Scanning…" : "Scan website"}
            <Icon name="arrow" />
          </button>
        </div>
        {error ? <p className="field-error" id={errorId} role="alert">{error}</p> : null}
        <div className="form-meta">
          <span><Icon name="lock" /> No credentials required</span>
          <span><Icon name="clock" /> A bounded, point-in-time assessment</span>
        </div>
      </form>

      <details className="safety-note">
        <summary><Icon name="info" /> What this assessment means <Icon name="chevron" /></summary>
        <p>
          WebGuard passively inspects transport security, response headers, cookies, bounded page
          content, and disclosure hygiene. It does not exploit the site, test authorization, or
          prove that a website is free of vulnerabilities.
        </p>
      </details>
    </section>
  );
}
