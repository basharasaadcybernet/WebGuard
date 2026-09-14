import { ApiClientError, messageForError } from "../api/errors";
import { Icon } from "./Icon";

export function ErrorState({ error, onRetry }: { error: Error; onRetry: () => void }) {
  const requestId = error instanceof ApiClientError ? error.requestId : null;
  return (
    <section className="error-state" role="alert" aria-labelledby="error-title">
      <span className="error-icon"><Icon name="warning" /></span>
      <div>
        <p className="eyebrow">Assessment not completed</p>
        <h2 id="error-title">We couldn’t finish this scan.</h2>
        <p>{messageForError(error)}</p>
        {requestId ? <p className="request-id">Request ID: <code>{requestId}</code></p> : null}
        <button className="secondary-button" type="button" onClick={onRetry}>Review the address</button>
      </div>
    </section>
  );
}
