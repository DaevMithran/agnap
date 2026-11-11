/** Defaults. Every one is overridable in `ServerConfig`, `HandlerOptions` or `ServeOptions`. */
export const DEFAULT_TOKEN_TTL_SECONDS = 600;
/** How long an unclaimed grant may remain pending or approved. */
export const DEFAULT_GRANT_TTL_SECONDS = 600;
export const DEFAULT_CONTINUE_WAIT_SECONDS = 5;
/** Largest request body the handler accepts, in bytes. */
export const DEFAULT_MAX_BODY_BYTES = 64 * 1024;
/** The Node adapter's own limit, applied at the socket before a Request is built. */
export const DEFAULT_SOCKET_BODY_LIMIT = 64 * 1024;
