import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import openapiTS, { astToString, COMMENT_HEADER } from 'openapi-typescript';
import { format, resolveConfig } from 'prettier';
import { parse } from 'yaml';

const here = dirname(fileURLToPath(import.meta.url));
const specs = resolve(here, '..');
const root = resolve(specs, '../..');
const check = process.argv.includes('--check');

async function readYaml(path) {
  return parse(await readFile(resolve(specs, path), 'utf8'));
}

async function emitTypes(document, path) {
  // openapi-typescript annotates the document while resolving discriminators.
  // Keep the parsed source pristine for the runtime JSON Schema bundle.
  const ast = await openapiTS(JSON.parse(JSON.stringify(document)));
  await emit(path, `${COMMENT_HEADER}${astToString(ast)}`);
}

async function emit(path, contents) {
  const target = resolve(root, path);
  const formatted = await format(contents, {
    ...(await resolveConfig(target)),
    filepath: target,
  });
  if (check) {
    const current = await readFile(target, 'utf8').catch(() => '');
    if (current !== formatted) throw new Error(`${path} is stale; run pnpm generate`);
    return;
  }
  await mkdir(dirname(target), { recursive: true });
  await writeFile(target, formatted);
}

function rewriteRefs(value, from, to) {
  if (Array.isArray(value)) return value.map((item) => rewriteRefs(item, from, to));
  if (value === null || typeof value !== 'object') return value;
  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => [
      key,
      key === '$ref' && typeof item === 'string'
        ? item.replace(from, to)
        : rewriteRefs(item, from, to),
    ]),
  );
}

const OPENAPI_ONLY_SCHEMA_KEYWORDS = new Set(['discriminator', 'xml', 'externalDocs', 'example']);
const SCHEMA_MAP_KEYWORDS = new Set([
  'properties',
  'patternProperties',
  'dependentSchemas',
  '$defs',
]);
const SCHEMA_ARRAY_KEYWORDS = new Set(['allOf', 'anyOf', 'oneOf', 'prefixItems']);
const SCHEMA_VALUE_KEYWORDS = new Set([
  'not',
  'if',
  'then',
  'else',
  'items',
  'contains',
  'additionalProperties',
  'unevaluatedProperties',
  'unevaluatedItems',
  'propertyNames',
  'contentSchema',
]);

/** Remove OpenAPI annotations only at schema-keyword positions, never from user property names. */
function jsonSchemaOnly(schema) {
  if (typeof schema === 'boolean' || schema === null || typeof schema !== 'object') return schema;
  const out = {};
  for (const [key, value] of Object.entries(schema)) {
    if (OPENAPI_ONLY_SCHEMA_KEYWORDS.has(key)) continue;
    if (SCHEMA_MAP_KEYWORDS.has(key) && value !== null && typeof value === 'object') {
      out[key] = Object.fromEntries(
        Object.entries(value).map(([name, child]) => [name, jsonSchemaOnly(child)]),
      );
    } else if (SCHEMA_ARRAY_KEYWORDS.has(key) && Array.isArray(value)) {
      out[key] = value.map(jsonSchemaOnly);
    } else if (SCHEMA_VALUE_KEYWORDS.has(key)) {
      out[key] = jsonSchemaOnly(value);
    } else {
      out[key] = value;
    }
  }
  return out;
}

function schemaBundle(document, id) {
  const rewritten = rewriteRefs(document.components.schemas, '#/components/schemas/', '#/$defs/');
  return {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: id,
    $defs: Object.fromEntries(
      Object.entries(rewritten).map(([name, schema]) => [name, jsonSchemaOnly(schema)]),
    ),
  };
}

function schemaModule(name, schema) {
  return `/** Generated from @agnap/specs. Do not edit. */\nexport const ${name} = ${JSON.stringify(schema, null, 2)};\n`;
}

const asDocument = await readYaml('openapi/as.yaml');
const ownerDocument = await readYaml('openapi/local-owner.yaml');
const agentSchema = JSON.parse(
  await readFile(resolve(specs, 'schema/agent-operation.json'), 'utf8'),
);

await emitTypes(asDocument, 'packages/gnap-core/src/generated/as.ts');
await emit(
  'packages/gnap-core/src/generated/as-schema.ts',
  schemaModule('asSchema', schemaBundle(asDocument, 'urn:agnap:openapi:as:0.2.0')),
);

await emitTypes(ownerDocument, 'packages/gnap-server/src/generated/local-owner.ts');
await emit(
  'packages/gnap-server/src/generated/local-owner-schema.ts',
  schemaModule(
    'localOwnerSchema',
    schemaBundle(ownerDocument, 'urn:agnap:openapi:local-owner:0.2.0'),
  ),
);

const $defs = agentSchema.$defs ?? {};
const agentRoot = Object.fromEntries(
  Object.entries(agentSchema).filter(([key]) => !['$schema', '$id', '$defs'].includes(key)),
);
const agentComponents = Object.fromEntries(
  Object.entries({ AgentOperationAccess: agentRoot, ...$defs }).map(([name, schema]) => [
    name,
    rewriteRefs(schema, '#/$defs/', '#/components/schemas/'),
  ]),
);
await emitTypes(
  {
    openapi: '3.1.0',
    info: { title: 'Agent operation access type', version: '0.2.0' },
    paths: {},
    components: { schemas: agentComponents },
  },
  'packages/access-types/src/generated/agent-operation.ts',
);
await emit(
  'packages/access-types/src/generated/agent-operation-schema.ts',
  schemaModule('agentOperationSchema', agentSchema),
);
