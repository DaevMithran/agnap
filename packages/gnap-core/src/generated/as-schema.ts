/** Generated from @agnap/specs. Do not edit. */
export const asSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'urn:agnap:openapi:as:0.2.0',
  $defs: {
    GrantRequest: {
      type: 'object',
      properties: {
        access_token: {
          $ref: '#/$defs/AccessTokenRequest',
        },
        client: {
          $ref: '#/$defs/ClientInstance',
        },
        interact: {
          type: 'object',
          description:
            'Accepted for shape compatibility and ignored. This profile uses asynchronous authorization.',
        },
        subject: {
          type: 'object',
          description: 'Accepted and ignored.',
        },
      },
      required: ['access_token', 'client'],
      additionalProperties: false,
    },
    AccessTokenRequest: {
      type: 'object',
      properties: {
        access: {
          $ref: '#/$defs/Access',
        },
        label: {
          type: 'string',
          description: 'Accepted for a single token request but not echoed in the response.',
        },
        flags: {
          type: 'array',
          items: {
            type: 'string',
            enum: ['bearer', 'durable'],
          },
          description: 'Any flag is refused with `invalid_flag`.',
        },
      },
      required: ['access'],
      additionalProperties: false,
    },
    Access: {
      type: 'array',
      minItems: 1,
      items: {
        $ref: '#/$defs/AccessObject',
      },
    },
    AccessObject: {
      type: 'object',
      description:
        'RFC 9635 section 8. `type` selects the registered handler, which defines the remaining fields.',
      properties: {
        type: {
          type: 'string',
        },
      },
      required: ['type'],
      additionalProperties: true,
    },
    ClientInstance: {
      type: 'object',
      properties: {
        key: {
          $ref: '#/$defs/KeyObject',
        },
        class_id: {
          type: 'string',
        },
        display: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
            },
            uri: {
              type: 'string',
            },
            logo_uri: {
              type: 'string',
            },
          },
          additionalProperties: false,
        },
      },
      required: ['key'],
      additionalProperties: false,
    },
    KeyObject: {
      type: 'object',
      properties: {
        proof: {
          oneOf: [
            {
              type: 'string',
              enum: ['httpsig'],
            },
            {
              type: 'object',
              properties: {
                method: {
                  type: 'string',
                  enum: ['httpsig'],
                },
                alg: {
                  type: 'string',
                  enum: ['ed25519'],
                },
                'content-digest-alg': {
                  type: 'string',
                  enum: ['sha-256'],
                },
              },
              required: ['method'],
              additionalProperties: false,
            },
          ],
        },
        jwk: {
          $ref: '#/$defs/Ed25519PublicJwk',
        },
      },
      required: ['proof', 'jwk'],
      additionalProperties: false,
    },
    Ed25519PublicJwk: {
      type: 'object',
      properties: {
        kid: {
          type: 'string',
          minLength: 1,
        },
        alg: {
          type: 'string',
          enum: ['EdDSA'],
        },
        use: {
          type: 'string',
          enum: ['sig'],
        },
        kty: {
          type: 'string',
          enum: ['OKP'],
        },
        crv: {
          type: 'string',
          enum: ['Ed25519'],
        },
        x: {
          type: 'string',
          pattern: '^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$',
        },
      },
      required: ['kid', 'alg', 'kty', 'crv', 'x'],
      additionalProperties: false,
    },
    GrantResponse: {
      description: 'Exactly one of `access_token` or `continue`.',
      oneOf: [
        {
          $ref: '#/$defs/IssuedGrantResponse',
        },
        {
          $ref: '#/$defs/PendingGrantResponse',
        },
      ],
    },
    IssuedGrantResponse: {
      type: 'object',
      properties: {
        access_token: {
          $ref: '#/$defs/AccessToken',
        },
      },
      required: ['access_token'],
      additionalProperties: false,
    },
    PendingGrantResponse: {
      type: 'object',
      properties: {
        continue: {
          $ref: '#/$defs/Continue',
        },
      },
      required: ['continue'],
      additionalProperties: false,
    },
    AccessToken: {
      type: 'object',
      properties: {
        value: {
          type: 'string',
        },
        access: {
          $ref: '#/$defs/Access',
        },
        expires_in: {
          type: 'integer',
          minimum: 1,
        },
        manage: {
          $ref: '#/$defs/TokenManagement',
        },
      },
      required: ['value', 'access', 'expires_in', 'manage'],
      additionalProperties: false,
    },
    TokenManagement: {
      type: 'object',
      description:
        'RFC 9635 section 3.2.1. `access_token.value` is the token management access token, distinct from the access token and bound to the client key.',
      properties: {
        uri: {
          type: 'string',
          format: 'uri',
        },
        access_token: {
          type: 'object',
          properties: {
            value: {
              type: 'string',
            },
          },
          required: ['value'],
          additionalProperties: false,
        },
      },
      required: ['uri', 'access_token'],
      additionalProperties: false,
    },
    Continue: {
      type: 'object',
      description: 'RFC 9635 section 3.1.',
      properties: {
        uri: {
          type: 'string',
          format: 'uri',
        },
        wait: {
          type: 'integer',
          minimum: 0,
        },
        access_token: {
          type: 'object',
          properties: {
            value: {
              type: 'string',
            },
          },
          required: ['value'],
          additionalProperties: false,
        },
      },
      required: ['uri', 'wait', 'access_token'],
      additionalProperties: false,
    },
    IntrospectionRequest: {
      type: 'object',
      description: 'RFC 9767 section 3.3.',
      properties: {
        access_token: {
          type: 'string',
          minLength: 1,
        },
        proof: {
          type: 'string',
          enum: ['httpsig'],
        },
        resource_server: {
          oneOf: [
            {
              type: 'string',
              description: 'Registered resource server identifier.',
              minLength: 1,
            },
            {
              type: 'object',
              properties: {
                key: {
                  $ref: '#/$defs/KeyObject',
                },
              },
              required: ['key'],
              additionalProperties: false,
            },
          ],
        },
        access: {
          $ref: '#/$defs/Access',
        },
      },
      required: ['access_token', 'resource_server'],
      additionalProperties: false,
    },
    IntrospectionResponse: {
      description: 'When `active` is false no other field is present.',
      oneOf: [
        {
          type: 'object',
          properties: {
            active: {
              const: false,
            },
          },
          required: ['active'],
          additionalProperties: false,
        },
        {
          type: 'object',
          properties: {
            active: {
              const: true,
            },
            access: {
              $ref: '#/$defs/Access',
            },
            key: {
              $ref: '#/$defs/KeyObject',
            },
            iss: {
              type: 'string',
              format: 'uri',
              description: 'Grant endpoint URL of the issuing server.',
            },
            exp: {
              type: 'integer',
            },
            iat: {
              type: 'integer',
            },
          },
          required: ['active', 'access', 'iss'],
          additionalProperties: false,
        },
      ],
    },
    ErrorResponse: {
      type: 'object',
      properties: {
        error: {
          type: 'object',
          properties: {
            code: {
              type: 'string',
              enum: [
                'invalid_request',
                'invalid_client',
                'invalid_interaction',
                'invalid_flag',
                'invalid_rotation',
                'key_rotation_not_supported',
                'invalid_continuation',
                'user_denied',
                'request_denied',
                'unknown_user',
                'unknown_interaction',
                'too_fast',
                'too_many_attempts',
                'invalid_resource_server',
                'invalid_access',
              ],
            },
            description: {
              type: 'string',
            },
          },
          required: ['code'],
          additionalProperties: false,
        },
      },
      required: ['error'],
      additionalProperties: false,
    },
  },
};
