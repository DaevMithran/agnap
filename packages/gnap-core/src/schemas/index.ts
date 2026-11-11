/** Runtime validators generated from the OpenAPI component schemas. */
import { Ajv2020 } from 'ajv/dist/2020.js';
import addFormatsModule from 'ajv-formats';
import type { ErrorObject, ValidateFunction } from 'ajv';
import { asSchema } from '../generated/as-schema.js';
import type { components } from '../generated/as.js';

const SCHEMA_ID = 'urn:agnap:openapi:as:0.2.0';
const addFormats = addFormatsModule.default;

/** The shared JSON Schema 2020-12 configuration for every AGNAP package. */
export function createAjv(): Ajv2020 {
  const instance = new Ajv2020({ allErrors: true, allowUnionTypes: true, strict: true });
  addFormats(instance);
  return instance;
}

const ajv = createAjv();
ajv.addSchema(asSchema);

export type { ValidateFunction } from 'ajv';

function validator<T>(name: keyof components['schemas']): ValidateFunction<T> {
  return ajv.compile<T>({ $ref: `${SCHEMA_ID}#/$defs/${name}` });
}

export const validateEd25519PublicJwk =
  validator<components['schemas']['Ed25519PublicJwk']>('Ed25519PublicJwk');
export const validateRawAccessItem =
  validator<components['schemas']['AccessObject']>('AccessObject');
export const validateGrantRequest =
  validator<components['schemas']['GrantRequest']>('GrantRequest');
export const validateIntrospectionRequest =
  validator<components['schemas']['IntrospectionRequest']>('IntrospectionRequest');
export const validateGrantResponse =
  validator<components['schemas']['GrantResponse']>('GrantResponse');
export const validateIntrospectionResponse =
  validator<components['schemas']['IntrospectionResponse']>('IntrospectionResponse');
export const validateErrorResponse =
  validator<components['schemas']['ErrorResponse']>('ErrorResponse');

/** Compact Ajv failures into the protocol's one-line error description. */
export function formatIssues(errors: ErrorObject[] | null | undefined): string {
  if (errors === null || errors === undefined || errors.length === 0) return 'invalid request';
  return errors
    .map((error) => {
      const path = error.instancePath.replace(/^\//, '').replaceAll('/', '.');
      const missing =
        error.keyword === 'required' && typeof error.params.missingProperty === 'string'
          ? [path, error.params.missingProperty].filter(Boolean).join('.')
          : path;
      return `${missing.length === 0 ? '$' : missing}: ${error.message ?? error.keyword}`;
    })
    .join('; ');
}
