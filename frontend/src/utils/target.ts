export interface TargetValidation {
  value: string;
  error: string | null;
}

export function validateTarget(value: string): TargetValidation {
  const target = value.trim();
  if (!target) {
    return { value: target, error: "Enter a website address to scan." };
  }
  if (target.length > 2048) {
    return { value: target, error: "The website address is too long." };
  }
  try {
    const parsed = new URL(target);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return { value: target, error: "Use a complete HTTP or HTTPS address." };
    }
    if (parsed.username || parsed.password) {
      return { value: target, error: "Website addresses containing credentials are not accepted." };
    }
  } catch {
    return {
      value: target,
      error: "Enter a complete address, including https:// or http://.",
    };
  }
  return { value: target, error: null };
}
