/**
 * A very small router in the Express shape: `router.post('/continue/:id', cb)`.
 * Enough for a handful of routes with one path parameter each. No framework,
 * no middleware chain. The handler reads the body once and hands every route
 * the same context.
 */
import type { Method, RouteCallback, RouteContext } from '../types/http.js';

interface Route {
  method: Method;
  source: string;
  pattern: RegExp;
  names: string[];
  callback: RouteCallback;
}

export class Router {
  readonly #routes: Route[] = [];

  get(pattern: string, callback: RouteCallback): this {
    return this.on('GET', pattern, callback);
  }
  post(pattern: string, callback: RouteCallback): this {
    return this.on('POST', pattern, callback);
  }
  delete(pattern: string, callback: RouteCallback): this {
    return this.on('DELETE', pattern, callback);
  }

  on(method: Method, pattern: string, callback: RouteCallback): this {
    const names: string[] = [];
    const source = pattern
      .split('/')
      .map((seg) => {
        if (seg.startsWith(':')) {
          names.push(seg.slice(1));
          return '([A-Za-z0-9_-]+)';
        }
        return seg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      })
      .join('/');
    this.#routes.push({
      method,
      source: pattern,
      pattern: new RegExp(`^${source || '/'}$`),
      names,
      callback,
    });
    return this;
  }

  /** Every registered method and pattern, for the spec sync test. */
  table(): { method: Method; pattern: string }[] {
    return this.#routes.map((r) => ({ method: r.method, pattern: r.source }));
  }

  /** The matching route's response, or null when nothing matches. */
  async dispatch(ctx: Omit<RouteContext, 'params'>): Promise<Response | null> {
    for (const route of this.#routes) {
      if (route.method !== ctx.method) continue;
      const m = route.pattern.exec(ctx.path);
      if (m === null) continue;
      const params: Record<string, string> = {};
      route.names.forEach((name, i) => {
        params[name] = m[i + 1] as string;
      });
      return route.callback({ ...ctx, params });
    }
    return null;
  }
}
