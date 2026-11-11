/**
 * Read a body while counting, stopping as soon as the limit is passed. A
 * declared Content-Length over the limit is refused without reading at all.
 * Null means too large.
 */
export async function readBodyLimited(request: Request, limit: number): Promise<Uint8Array | null> {
  const declared = Number(request.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > limit) return null;
  if (request.body === null) return new Uint8Array();
  const reader = request.body.getReader() as ReadableStreamDefaultReader<Uint8Array>;
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limit) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.byteLength;
  }
  return out;
}

/** Read one path from an already parsed JSON value. Undefined on any shape mismatch. */
export function peek(value: unknown, path: string[]): unknown {
  let v = value;
  for (const p of path) {
    if (typeof v !== 'object' || v === null) return undefined;
    v = (v as Record<string, unknown>)[p];
  }
  return v;
}

export function parseJson(bytes: Uint8Array): unknown {
  try {
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    return undefined;
  }
}

/**
 * The `@target-uri` a server verifies against. Behind a TLS-terminating
 * proxy the scheme and host the client signed differ from what the process
 * sees, so a deployment sets `publicUrl` and the origin is taken from there.
 */
export function resolveTargetUri(requestUrl: string, publicUrl?: string): string {
  if (publicUrl === undefined) return requestUrl;
  const incoming = new URL(requestUrl);
  return `${new URL(publicUrl).origin}${incoming.pathname}${incoming.search}`;
}
