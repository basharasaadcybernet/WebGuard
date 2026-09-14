import { useCallback, useEffect, useRef, useState } from "react";

import { scanTarget } from "../api/client";
import type { ApiClientError } from "../api/errors";
import type { ScanApiResponse } from "../api/types";

export type ScanViewState =
  | { status: "idle" }
  | { status: "scanning"; target: string }
  | { status: "success"; target: string; response: ScanApiResponse }
  | { status: "error"; target: string; error: ApiClientError | Error };

export function useScan(): {
  state: ScanViewState;
  start: (target: string) => Promise<void>;
  cancel: () => void;
  reset: () => void;
} {
  const [state, setState] = useState<ScanViewState>({ status: "idle" });
  const controllerRef = useRef<AbortController | null>(null);

  const start = useCallback(async (target: string): Promise<void> => {
    controllerRef.current?.abort();
    const controller = new AbortController();
    controllerRef.current = controller;
    setState({ status: "scanning", target });
    try {
      const response = await scanTarget(target, { signal: controller.signal });
      if (!controller.signal.aborted) {
        setState({ status: "success", target, response });
      }
    } catch (error) {
      setState({
        status: "error",
        target,
        error: error instanceof Error ? error : new Error("Unknown scan error"),
      });
    } finally {
      if (controllerRef.current === controller) controllerRef.current = null;
    }
  }, []);

  const cancel = useCallback((): void => {
    controllerRef.current?.abort();
  }, []);

  const reset = useCallback((): void => {
    controllerRef.current?.abort();
    setState({ status: "idle" });
  }, []);

  useEffect(() => () => controllerRef.current?.abort(), []);

  return { state, start, cancel, reset };
}
