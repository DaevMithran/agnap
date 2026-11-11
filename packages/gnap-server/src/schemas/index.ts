/** Runtime validators generated from the local-owner OpenAPI components. */
import { createAjv } from '@agnap/gnap-core';
import { localOwnerSchema } from '../generated/local-owner-schema.js';
import type { components } from '../generated/local-owner.js';

const SCHEMA_ID = 'urn:agnap:openapi:local-owner:0.2.0';
const ajv = createAjv();
ajv.addSchema(localOwnerSchema);

export const validateOwnerResolution = ajv.compile<components['schemas']['OwnerResolution']>({
  $ref: `${SCHEMA_ID}#/$defs/OwnerResolution`,
});
export const validatePendingGrantList = ajv.compile<components['schemas']['PendingGrantList']>({
  $ref: `${SCHEMA_ID}#/$defs/PendingGrantList`,
});
export const validateOwnerResolutionResult = ajv.compile<
  components['schemas']['OwnerResolutionResult']
>({
  $ref: `${SCHEMA_ID}#/$defs/OwnerResolutionResult`,
});

/** Wire types of the local owner extension, as `GET /local/grants` and `POST /local/grants/{id}` carry them. */
export type PendingGrant = components['schemas']['PendingGrant'];
export type PendingGrantList = components['schemas']['PendingGrantList'];
export type OwnerResolutionBody = components['schemas']['OwnerResolution'];
export type OwnerResolutionResultBody = components['schemas']['OwnerResolutionResult'];
