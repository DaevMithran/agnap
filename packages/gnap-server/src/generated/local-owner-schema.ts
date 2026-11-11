/** Generated from @agnap/specs. Do not edit. */
export const localOwnerSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'urn:agnap:openapi:local-owner:0.2.0',
  $defs: {
    AccessObject: {
      type: 'object',
      properties: {
        type: {
          type: 'string',
        },
      },
      required: ['type'],
      additionalProperties: true,
    },
    PendingGrant: {
      type: 'object',
      properties: {
        id: {
          type: 'string',
        },
        created_at: {
          type: 'string',
          format: 'date-time',
        },
        expires_at: {
          type: 'string',
          format: 'date-time',
        },
        client_kid: {
          type: 'string',
        },
        client_thumbprint: {
          type: 'string',
        },
        client_display: {
          type: 'object',
          description: 'RFC 9635 `client.display` as the client stated it. Unverified.',
          properties: {
            name: {
              type: 'string',
            },
            uri: {
              type: 'string',
            },
          },
          additionalProperties: false,
        },
        requested_access: {
          type: 'array',
          minItems: 1,
          items: {
            $ref: '#/$defs/AccessObject',
          },
        },
      },
      required: [
        'id',
        'created_at',
        'expires_at',
        'client_kid',
        'client_thumbprint',
        'requested_access',
      ],
      additionalProperties: false,
    },
    PendingGrantList: {
      type: 'object',
      properties: {
        grants: {
          type: 'array',
          items: {
            $ref: '#/$defs/PendingGrant',
          },
        },
      },
      required: ['grants'],
      additionalProperties: false,
    },
    OwnerResolution: {
      oneOf: [
        {
          $ref: '#/$defs/DenyResolution',
        },
        {
          $ref: '#/$defs/ApproveResolution',
        },
      ],
    },
    DenyResolution: {
      type: 'object',
      properties: {
        decision: {
          const: 'deny',
        },
      },
      required: ['decision'],
      additionalProperties: false,
    },
    ApproveResolution: {
      type: 'object',
      properties: {
        decision: {
          const: 'approve',
        },
        access: {
          type: 'array',
          minItems: 1,
          description: 'Narrowed access. Must be contained in the requested access.',
          items: {
            $ref: '#/$defs/AccessObject',
          },
        },
        audiences: {
          type: 'array',
          description: 'Resource server ids. Must be able to serve the approved access.',
          items: {
            type: 'string',
          },
        },
      },
      required: ['decision'],
      additionalProperties: false,
    },
    OwnerResolutionResult: {
      type: 'object',
      properties: {
        state: {
          type: 'string',
          enum: ['approved', 'denied'],
        },
      },
      required: ['state'],
      additionalProperties: false,
    },
    ErrorResponse: {
      type: 'object',
      properties: {
        error: {
          type: 'object',
          properties: {
            code: {
              const: 'invalid_request',
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
