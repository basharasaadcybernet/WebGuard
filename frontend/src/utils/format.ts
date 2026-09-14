export function percentage(value: string | null): number | null {
  if (value === null) return null;
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return null;
  return Math.min(100, Math.max(0, parsed * 100));
}

export function formatPercent(value: string | null): string {
  const parsed = percentage(value);
  return parsed === null ? "Not applicable" : `${Math.round(parsed)}%`;
}

export function formatPoints(value: string): string {
  const parsed = Number(value);
  return Number.isFinite(parsed)
    ? new Intl.NumberFormat("en", { maximumFractionDigits: 1 }).format(parsed)
    : "—";
}

export function formatDuration(milliseconds: number): string {
  if (milliseconds < 1000) return `${milliseconds} ms`;
  return `${(milliseconds / 1000).toFixed(milliseconds < 10_000 ? 1 : 0)} s`;
}

export function formatDate(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.valueOf())
    ? "Unknown time"
    : new Intl.DateTimeFormat("en", {
        dateStyle: "medium",
        timeStyle: "short",
      }).format(date);
}

export function safeExternalHref(value: string): string | null {
  try {
    const url = new URL(value);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) return null;
    return url.href;
  } catch {
    return null;
  }
}

export function safeContactHref(value: string | undefined): string | null {
  if (!value?.trim()) return null;
  try {
    const url = new URL(value);
    if (!['http:', 'https:', 'mailto:'].includes(url.protocol)) return null;
    return value;
  } catch {
    return null;
  }
}

export function redactTargetForDisplay(value: string): string {
  try {
    const url = new URL(value);
    url.username = "";
    url.password = "";
    url.hash = "";
    if (url.search) url.search = "?[redacted]";
    return url.toString();
  } catch {
    return "Submitted target";
  }
}
