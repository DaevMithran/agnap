/**
 * `node:http` to fetch handler, so the CLI and the loopback tests can run
 * the server without a framework. Around forty lines, and the only place
 * the package touches a socket.
 */
import { createServer as createHttpServer } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { DEFAULT_SOCKET_BODY_LIMIT } from '../config.js';
import { checkBodyLimit } from './handler.js';
import type { FetchHandler, RunningServer, ServeOptions } from '../types/http.js';

class BodyTooLarge extends Error {
  override readonly name = 'BodyTooLarge';
}

export function serve(handler: FetchHandler, options: ServeOptions = {}): Promise<RunningServer> {
  const host = options.host ?? '127.0.0.1';
  const limit = checkBodyLimit(options.maxBodyBytes ?? DEFAULT_SOCKET_BODY_LIMIT);
  const http = createHttpServer((req, res) => {
    void toRequest(req, host, limit)
      .then(handler)
      .then((response) => send(res, response))
      .catch((e: unknown) => {
        if (e instanceof BodyTooLarge) {
          res.statusCode = 413;
          res.setHeader('content-type', 'application/json');
          res.setHeader('connection', 'close');
          res.end(JSON.stringify({ error: { code: 'invalid_request', description: e.message } }));
          req.destroy();
          return;
        }
        res.statusCode = 500;
        res.setHeader('content-type', 'application/json');
        res.end(
          JSON.stringify({ error: { code: 'invalid_request', description: 'internal error' } }),
        );
        console.error(e);
      });
  });
  return new Promise((resolve, reject) => {
    http.once('error', reject);
    http.listen(options.port ?? 0, host, () => {
      const addr = http.address();
      const port = typeof addr === 'object' && addr !== null ? addr.port : options.port;
      resolve({
        url: `http://${host}:${port}`,
        close: () => new Promise((r, j) => http.close((err) => (err ? j(err) : r()))),
      });
    });
  });
}

async function toRequest(
  req: IncomingMessage,
  fallbackHost: string,
  limit: number,
): Promise<Request> {
  const declared = Number(req.headers['content-length']);
  if (Number.isFinite(declared) && declared > limit) {
    throw new BodyTooLarge(`request body exceeds ${limit} bytes`);
  }
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    total += (chunk as Buffer).byteLength;
    if (total > limit) throw new BodyTooLarge(`request body exceeds ${limit} bytes`);
    chunks.push(chunk as Buffer);
  }
  const body = Buffer.concat(chunks);
  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers)) {
    if (v === undefined) continue;
    if (Array.isArray(v)) for (const x of v) headers.append(k, x);
    else headers.set(k, v);
  }
  const host = req.headers.host ?? fallbackHost;
  const url = `http://${host}${req.url ?? '/'}`;
  const init: RequestInit = { method: req.method ?? 'GET', headers };
  if (body.length > 0) init.body = body;
  return new Request(url, init);
}

async function send(res: ServerResponse, response: Response): Promise<void> {
  res.statusCode = response.status;
  response.headers.forEach((v, k) => res.setHeader(k, v));
  const body = Buffer.from(await response.arrayBuffer());
  res.end(body.length > 0 ? body : undefined);
}
