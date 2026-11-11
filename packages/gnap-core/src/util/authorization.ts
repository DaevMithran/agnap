/** The `Authorization: GNAP <token>` scheme, RFC 9635 section 7.2. */
export const GNAP_AUTH_SCHEME = 'GNAP';

/** Extract the token from `Authorization: GNAP <value>`. Null when absent or another scheme. */
export function gnapAuthorizationValue(header: string | null): string | null {
  if (header === null) return null;
  const m = /^GNAP\s+(\S+)\s*$/i.exec(header);
  return m?.[1] ?? null;
}
