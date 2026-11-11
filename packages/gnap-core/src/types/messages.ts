/** RFC 9635 and RFC 9767 wire types generated from the OpenAPI contract. */
import type { components } from '../generated/as.js';

type Schemas = components['schemas'];

export type ProofMethod = 'httpsig';
export type KeyObject = Schemas['KeyObject'];
export type ClientInstance = Schemas['ClientInstance'];
export type TokenFlag = NonNullable<Schemas['AccessTokenRequest']['flags']>[number];
export type GrantRequest = Schemas['GrantRequest'];
export type TokenManagement = Schemas['TokenManagement'];
export type AccessToken = Schemas['AccessToken'];
export type ContinueResponse = Schemas['Continue'];
export type GrantResponse =
  | (Schemas['IssuedGrantResponse'] & { continue?: never })
  | (Schemas['PendingGrantResponse'] & { access_token?: never });

/** RFC 9635 section 5. A polling continuation carries no body. */
export type ContinueRequest = Record<string, never>;

export type GnapErrorCode = Exclude<
  Schemas['ErrorResponse']['error']['code'],
  'invalid_resource_server' | 'invalid_access'
>;
export type IntrospectionErrorCode = Extract<
  Schemas['ErrorResponse']['error']['code'],
  'invalid_request' | 'invalid_resource_server' | 'invalid_access'
>;
export type ErrorResponse = Schemas['ErrorResponse'];
export type IntrospectionRequest = Schemas['IntrospectionRequest'];
export type IntrospectionResponse = Schemas['IntrospectionResponse'];
