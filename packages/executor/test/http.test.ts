import { describe, expect, it } from 'vitest';
import { HttpConnector } from '../src/index.js';
import type { HttpConnectorOptions } from '../src/index.js';

const context = { rootGrant: 'g', signal: new AbortController().signal };

function connector(
  answer: (request: Request) => Response | Promise<Response>,
  extra: Partial<HttpConnectorOptions> = {},
) {
  const seen: Request[] = [];
  const http = new HttpConnector({
    baseUrl: 'http://api.test/v1',
    operations: {
      list: { method: 'GET', path: '/repos/{+repository}/issues', query: ['state'] },
      label: { method: 'GET', path: '/labels/{name}' },
      comment: { method: 'POST', path: '/repos/{+repository}/comments', body: ['body', 'draft'] },
    },
    credential: { header: 'authorization', value: () => 'Bearer s3cret' },
    fetch: async (request) => {
      seen.push(request);
      return answer(request);
    },
    ...extra,
  });
  return { http, seen };
}

describe('HttpConnector', () => {
  it('fills the path template, query and JSON body, and adds the credential', async () => {
    const { http, seen } = connector(() => Response.json({ ok: true }));
    expect(
      await http.call(
        { operation: 'list', arguments: { repository: 'acme/docs', state: 'open' } },
        context,
      ),
    ).toEqual({ kind: 'done', result: { ok: true } });
    expect(seen[0]!.url).toBe('http://api.test/v1/repos/acme/docs/issues?state=open');
    expect(seen[0]!.headers.get('authorization')).toBe('Bearer s3cret');

    await http.call({ operation: 'label', arguments: { name: 'needs review/x' } }, context);
    expect(seen[1]!.url).toBe('http://api.test/v1/labels/needs%20review%2Fx');

    await http.call(
      { operation: 'comment', arguments: { repository: 'acme/docs', body: 'hi', draft: false } },
      context,
    );
    expect(seen[2]!.method).toBe('POST');
    expect(await seen[2]!.json()).toEqual({ body: 'hi', draft: false });
  });

  it('fails without effect when a path argument is missing', async () => {
    const { http, seen } = connector(() => Response.json({}));
    expect(await http.call({ operation: 'list', arguments: {} }, context)).toMatchObject({
      kind: 'failed',
      effect: 'none',
    });
    expect(seen).toHaveLength(0);
  });

  it('classifies failures: 4xx had no effect, 5xx on POST may have, 5xx on GET did not', async () => {
    const status = { value: 400 };
    const { http } = connector(() => new Response('no', { status: status.value }));
    const post = { operation: 'comment', arguments: { repository: 'a/b', body: 'x' } };
    const get = { operation: 'list', arguments: { repository: 'a/b' } };
    expect(await http.call(post, context)).toMatchObject({ kind: 'failed', effect: 'none' });
    status.value = 503;
    expect(await http.call(post, context)).toMatchObject({ kind: 'failed', effect: 'unknown' });
    expect(await http.call(get, context)).toMatchObject({ kind: 'failed', effect: 'none' });
  });

  it('a network error on POST has unknown effect; a missing credential sends nothing', async () => {
    const { http } = connector(() => Promise.reject(new Error('reset')));
    expect(
      await http.call(
        { operation: 'comment', arguments: { repository: 'a/b', body: 'x' } },
        context,
      ),
    ).toMatchObject({ kind: 'failed', effect: 'unknown' });

    const { http: noKey, seen } = connector(() => Response.json({}), {
      credential: {
        header: 'authorization',
        value: () => {
          throw new Error('GITHUB_TOKEN is not set');
        },
      },
    });
    expect(
      await noKey.call(
        { operation: 'comment', arguments: { repository: 'a/b', body: 'x' } },
        context,
      ),
    ).toMatchObject({ kind: 'failed', effect: 'none' });
    expect(seen).toHaveLength(0);
  });
});
