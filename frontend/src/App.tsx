import { useCallback } from "react";

import { AppHeader } from "./components/AppHeader";
import { ErrorState } from "./components/ErrorState";
import { ResultsView } from "./components/results/ResultsView";
import { ScanHero } from "./components/ScanHero";
import { ScanProgress } from "./components/ScanProgress";
import { ScopeOverview } from "./components/ScopeOverview";
import { SiteFooter } from "./components/SiteFooter";
import { useScan } from "./hooks/useScan";

export function App() {
  const { state, start, cancel, reset } = useScan();
  const returnToForm = useCallback((): void => {
    reset();
    window.requestAnimationFrame(() => {
      document.querySelector<HTMLInputElement>("#scan input")?.focus();
      document.getElementById("scan")?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  }, [reset]);

  return (
    <div className="app-shell" id="top">
      <AppHeader />
      <main>
        <ScanHero busy={state.status === "scanning"} onSubmit={(target) => void start(target)} />
        <div className="content-shell">
          {state.status === "idle" ? <ScopeOverview /> : null}
          {state.status === "scanning" ? <ScanProgress target={state.target} onCancel={cancel} /> : null}
          {state.status === "error" ? <ErrorState error={state.error} onRetry={returnToForm} /> : null}
          {state.status === "success" ? (
            <ResultsView report={state.response.report} submittedTarget={state.target} onRetry={returnToForm} />
          ) : null}
        </div>
      </main>
      <SiteFooter />
    </div>
  );
}
