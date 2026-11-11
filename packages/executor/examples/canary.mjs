#!/usr/bin/env node
// A stand-in downstream API for trying agnapd: logs every request it gets
// and answers 200. Run: node canary.mjs [port]  (default 4200)
/* global process, console */
import { createServer } from 'node:http';

const port = Number(process.argv[2] ?? 4200);
let count = 0;
createServer((req, res) => {
  let body = '';
  req.on('data', (chunk) => (body += chunk));
  req.on('end', () => {
    count += 1;
    console.log(
      JSON.stringify({
        n: count,
        method: req.method,
        url: req.url,
        auth: req.headers.authorization ?? null,
        body,
      }),
    );
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true, n: count }));
  });
}).listen(port, '127.0.0.1', () => console.log(`canary on http://127.0.0.1:${port}`));
