/**
 * @agnap/gnap-server
 *
 * An RFC-conformant GNAP authorization server profile: grant (RFC 9635 §2),
 * polling continuation (§5), token revocation (§6.2) and resource server
 * introspection (RFC 9767 §3.3). Generic over access type and decision
 * step. A fetch handler with no framework. Node runtime today.
 *
 * The router and the route table are internal. Mount the fetch handler.
 */
export * from './types/index.js';
export * from './config.js';
export { createServer, defaultSelectAudiences } from './protocol/server.js';
export { pendingOwner, fixedList } from './protocol/decision.js';
export { StaticResourceServerRegistry } from './protocol/registry.js';
export { MemoryStore } from './store/memory.js';
export { createHandler, checkBodyLimit } from './http/handler.js';
export { resolveTargetUri } from './http/body.js';
export { serve } from './http/node.js';
