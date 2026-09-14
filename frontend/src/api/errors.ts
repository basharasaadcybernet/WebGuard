import type { ApiErrorCode } from "./types";

export type ClientErrorCode = ApiErrorCode | "NETWORK_ERROR" | "CANCELLED" | "CLIENT_TIMEOUT";

const messages: Record<ClientErrorCode, string> = {
  INVALID_REQUEST: "Enter a complete HTTP or HTTPS website address and try again.",
  INVALID_TARGET: "WebGuard could not accept that target. Check the address and try again.",
  INVALID_HOST: "The API host configuration rejected this request.",
  REQUEST_TOO_LARGE: "The submitted request is larger than WebGuard accepts.",
  RATE_LIMITED: "Too many scans were requested. Please wait a moment before trying again.",
  SERVICE_BUSY: "WebGuard is currently at scan capacity. Please try again shortly.",
  SCAN_TIMEOUT: "The assessment took longer than the service allows. Please try again.",
  CLIENT_DISCONNECTED: "The assessment stopped because the connection was interrupted.",
  NOT_FOUND: "The WebGuard API endpoint is unavailable.",
  METHOD_NOT_ALLOWED: "The WebGuard API rejected this operation.",
  INTERNAL_ERROR: "WebGuard encountered an internal problem. Please try again later.",
  NETWORK_ERROR: "The WebGuard API could not be reached. Confirm that the local service is running.",
  CANCELLED: "The assessment was cancelled. You can start it again when ready.",
  CLIENT_TIMEOUT: "The browser stopped waiting for the assessment. Please try again.",
};

export class ApiClientError extends Error {
  public readonly code: ClientErrorCode;
  public readonly status: number | null;
  public readonly requestId: string | null;

  public constructor(
    code: ClientErrorCode,
    options: { status?: number; requestId?: string; cause?: unknown } = {},
  ) {
    super(messages[code], { cause: options.cause });
    this.name = "ApiClientError";
    this.code = code;
    this.status = options.status ?? null;
    this.requestId = options.requestId ?? null;
  }
}

export function messageForError(error: unknown): string {
  return error instanceof ApiClientError
    ? error.message
    : "WebGuard could not complete the request. Please try again.";
}
