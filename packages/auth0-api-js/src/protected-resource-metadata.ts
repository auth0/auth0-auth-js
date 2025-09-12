/**
 * RFC 9728 - OAuth 2.0 Protected Resource Metadata
 * https://datatracker.ietf.org/doc/html/rfc9728
 */

import { MissingRequiredArgumentError } from "./errors.js";

/**
 * Authorization scheme enum for the resource
 */
export enum AuthorizationScheme {
  BEARER = "Bearer",
  DPOP = "DPoP",
  MAC = "MAC",
}

/**
 * Token endpoint authentication methods
 */
export enum TokenEndpointAuthMethod {
  CLIENT_SECRET_BASIC = "client_secret_basic",
  CLIENT_SECRET_POST = "client_secret_post",
  CLIENT_SECRET_JWT = "client_secret_jwt",
  PRIVATE_KEY_JWT = "private_key_jwt",
  TLS_CLIENT_AUTH = "tls_client_auth",
  SELF_SIGNED_TLS_CLIENT_AUTH = "self_signed_tls_client_auth",
  NONE = "none",
}

/**
 * Supported signing algorithms
 */
export enum SigningAlgorithm {
  RS256 = "RS256",
  RS384 = "RS384",
  RS512 = "RS512",
  ES256 = "ES256",
  ES384 = "ES384",
  ES512 = "ES512",
  PS256 = "PS256",
  PS384 = "PS384",
  PS512 = "PS512",
  HS256 = "HS256",
  HS384 = "HS384",
  HS512 = "HS512",
}

/**
 * Response types supported
 */
export enum ResponseType {
  CODE = "code",
  TOKEN = "token",
  ID_TOKEN = "id_token",
}

/**
 * Grant types supported
 */
export enum GrantType {
  AUTHORIZATION_CODE = "authorization_code",
  IMPLICIT = "implicit",
  PASSWORD = "password",
  CLIENT_CREDENTIALS = "client_credentials",
  REFRESH_TOKEN = "refresh_token",
  JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer",
  SAML2_BEARER = "urn:ietf:params:oauth:grant-type:saml2-bearer",
  DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code",
}

/**
 * Interface for Protected Resource Metadata
 */
export interface IProtectedResourceMetadata {
  resource: string;
  authorization_servers: string[];
  jwks_uri?: string;
  scopes_supported?: string[];
  bearer_methods_supported?: AuthorizationScheme[];
  resource_documentation?: string;
  resource_policy_uri?: string;
  resource_tos_uri?: string;
  token_endpoint_auth_methods_supported?: TokenEndpointAuthMethod[];
  revocation_endpoint_auth_methods_supported?: TokenEndpointAuthMethod[];
  introspection_endpoint_auth_methods_supported?: TokenEndpointAuthMethod[];
  token_endpoint_auth_signing_alg_values_supported?: SigningAlgorithm[];
  revocation_endpoint_auth_signing_alg_values_supported?: SigningAlgorithm[];
  introspection_endpoint_auth_signing_alg_values_supported?: SigningAlgorithm[];
}

/**
 * Builder for creating a ProtectedResourceMetadata instance
 *
 * @example
 * ```typescript
 * const metadata = new ProtectedResourceMetadataBuilder('https://api.example.com', ['https://auth.example.com'])
 *   .withJwksUri('https://api.example.com/.well-known/jwks.json')
 *   .withScopesSupported(['read', 'write'])
 *   .build();
 * // serialize to json
 * const json = metadata.toJSON();
 * ```
 */
export class ProtectedResourceMetadataBuilder {
  private readonly props: Partial<IProtectedResourceMetadata> &
    Pick<IProtectedResourceMetadata, "resource" | "authorization_servers">;

  /**
   * Constructor for the builder
   * @param resource - The protected resource identifier (REQUIRED)
   * @param authorization_servers - Array of authorization server URLs (REQUIRED)
   */
  constructor(resource: string, authorization_servers: string[]) {
    if (!resource?.trim()) {
      throw new MissingRequiredArgumentError("resource");
    }
    if (
      !Array.isArray(authorization_servers) ||
      authorization_servers.length === 0
    ) {
      throw new MissingRequiredArgumentError("authorization_servers");
    }
    this.props = { resource, authorization_servers };
  }

  get properties(): IProtectedResourceMetadata {
    return this.props;
  }

  /**
   * Builds the ProtectedResourceMetadata
   */
  public build() {
    return new ProtectedResourceMetadata(this);
  }

  /**
   * Builder method to add JWKS URI
   */
  withJwksUri(jwks_uri: string): this {
    this.props.jwks_uri = jwks_uri;
    return this;
  }

  /**
   * Builder method to add supported scopes
   */
  withScopesSupported(scopes_supported: string[]): this {
    this.props.scopes_supported = [...scopes_supported];
    return this;
  }

  /**
   * Builder method to add supported bearer methods
   */
  withBearerMethodsSupported(
    bearer_methods_supported: AuthorizationScheme[]
  ): this {
    this.props.bearer_methods_supported = [...bearer_methods_supported];
    return this;
  }

  /**
   * Builder method to add resource documentation URL
   */
  withResourceDocumentation(resource_documentation: string): this {
    this.props.resource_documentation = resource_documentation;
    return this;
  }

  /**
   * Builder method to add resource policy URI
   */
  withResourcePolicyUri(resource_policy_uri: string): this {
    this.props.resource_policy_uri = resource_policy_uri;
    return this;
  }

  /**
   * Builder method to add resource terms of service URI
   */
  withResourceTosUri(resource_tos_uri: string): this {
    this.props.resource_tos_uri = resource_tos_uri;
    return this;
  }

  /**
   * Builder method to add token endpoint auth methods
   */
  withTokenEndpointAuthMethodsSupported(
    methods: TokenEndpointAuthMethod[]
  ): this {
    this.props.token_endpoint_auth_methods_supported = [...methods];
    return this;
  }

  /**
   * Builder method to add revocation endpoint auth methods
   */
  withRevocationEndpointAuthMethodsSupported(
    methods: TokenEndpointAuthMethod[]
  ): this {
    this.props.revocation_endpoint_auth_methods_supported = [...methods];
    return this;
  }

  /**
   * Builder method to add introspection endpoint auth methods
   */
  withIntrospectionEndpointAuthMethodsSupported(
    methods: TokenEndpointAuthMethod[]
  ): this {
    this.props.introspection_endpoint_auth_methods_supported = [...methods];
    return this;
  }

  /**
   * Builder method to add token endpoint auth signing algorithms
   */
  withTokenEndpointAuthSigningAlgValuesSupported(
    algorithms: SigningAlgorithm[]
  ): this {
    this.props.token_endpoint_auth_signing_alg_values_supported = [
      ...algorithms,
    ];
    return this;
  }

  /**
   * Builder method to add revocation endpoint auth signing algorithms
   */
  withRevocationEndpointAuthSigningAlgValuesSupported(
    algorithms: SigningAlgorithm[]
  ): this {
    this.props.revocation_endpoint_auth_signing_alg_values_supported = [
      ...algorithms,
    ];
    return this;
  }

  /**
   * Builder method to add introspection endpoint auth signing algorithms
   */
  withIntrospectionEndpointAuthSigningAlgValuesSupported(
    algorithms: SigningAlgorithm[]
  ): this {
    this.props.introspection_endpoint_auth_signing_alg_values_supported = [
      ...algorithms,
    ];
    return this;
  }
}

class ProtectedResourceMetadata {
  readonly #resource: string;
  readonly #authorization_servers: string[];
  readonly #jwks_uri?: string;
  readonly #scopes_supported?: string[];
  readonly #bearer_methods_supported?: AuthorizationScheme[];
  readonly #resource_documentation?: string;
  readonly #resource_policy_uri?: string;
  readonly #resource_tos_uri?: string;
  readonly #token_endpoint_auth_methods_supported?: TokenEndpointAuthMethod[];
  readonly #revocation_endpoint_auth_methods_supported?: TokenEndpointAuthMethod[];
  readonly #introspection_endpoint_auth_methods_supported?: TokenEndpointAuthMethod[];
  readonly #token_endpoint_auth_signing_alg_values_supported?: SigningAlgorithm[];
  readonly #revocation_endpoint_auth_signing_alg_values_supported?: SigningAlgorithm[];
  readonly #introspection_endpoint_auth_signing_alg_values_supported?: SigningAlgorithm[];

  constructor(builder: ProtectedResourceMetadataBuilder) {
    const props = builder.properties;
    this.#resource = props.resource;
    this.#authorization_servers = [...props.authorization_servers];
    this.#jwks_uri = props.jwks_uri;
    this.#scopes_supported = props.scopes_supported
      ? [...props.scopes_supported]
      : undefined;
    this.#bearer_methods_supported = props.bearer_methods_supported
      ? [...props.bearer_methods_supported]
      : undefined;
    this.#resource_documentation = props.resource_documentation;
    this.#resource_policy_uri = props.resource_policy_uri;
    this.#resource_tos_uri = props.resource_tos_uri;
    this.#token_endpoint_auth_methods_supported =
      props.token_endpoint_auth_methods_supported
        ? [...props.token_endpoint_auth_methods_supported]
        : undefined;
    this.#revocation_endpoint_auth_methods_supported =
      props.revocation_endpoint_auth_methods_supported
        ? [...props.revocation_endpoint_auth_methods_supported]
        : undefined;
    this.#introspection_endpoint_auth_methods_supported =
      props.introspection_endpoint_auth_methods_supported
        ? [...props.introspection_endpoint_auth_methods_supported]
        : undefined;
    this.#token_endpoint_auth_signing_alg_values_supported =
      props.token_endpoint_auth_signing_alg_values_supported
        ? [...props.token_endpoint_auth_signing_alg_values_supported]
        : undefined;
    this.#revocation_endpoint_auth_signing_alg_values_supported =
      props.revocation_endpoint_auth_signing_alg_values_supported
        ? [...props.revocation_endpoint_auth_signing_alg_values_supported]
        : undefined;
    this.#introspection_endpoint_auth_signing_alg_values_supported =
      props.introspection_endpoint_auth_signing_alg_values_supported
        ? [...props.introspection_endpoint_auth_signing_alg_values_supported]
        : undefined;
  }

  /**
   * Convert to JSON representation
   */
  public toJSON(): IProtectedResourceMetadata {
    return {
      resource: this.#resource,
      authorization_servers: [...this.#authorization_servers],

      ...(this.#jwks_uri !== undefined && { jwks_uri: this.#jwks_uri }),
      ...(this.#scopes_supported !== undefined && {
        scopes_supported: [...this.#scopes_supported],
      }),
      ...(this.#bearer_methods_supported !== undefined && {
        bearer_methods_supported: [...this.#bearer_methods_supported],
      }),
      ...(this.#resource_documentation !== undefined && {
        resource_documentation: this.#resource_documentation,
      }),
      ...(this.#resource_policy_uri !== undefined && {
        resource_policy_uri: this.#resource_policy_uri,
      }),
      ...(this.#resource_tos_uri !== undefined && {
        resource_tos_uri: this.#resource_tos_uri,
      }),
      ...(this.#token_endpoint_auth_methods_supported !== undefined && {
        token_endpoint_auth_methods_supported: [
          ...this.#token_endpoint_auth_methods_supported,
        ],
      }),
      ...(this.#revocation_endpoint_auth_methods_supported !== undefined && {
        revocation_endpoint_auth_methods_supported: [
          ...this.#revocation_endpoint_auth_methods_supported,
        ],
      }),
      ...(this.#introspection_endpoint_auth_methods_supported !== undefined && {
        introspection_endpoint_auth_methods_supported: [
          ...this.#introspection_endpoint_auth_methods_supported,
        ],
      }),
      ...(this.#token_endpoint_auth_signing_alg_values_supported !==
        undefined && {
        token_endpoint_auth_signing_alg_values_supported: [
          ...this.#token_endpoint_auth_signing_alg_values_supported,
        ],
      }),
      ...(this.#revocation_endpoint_auth_signing_alg_values_supported !==
        undefined && {
        revocation_endpoint_auth_signing_alg_values_supported: [
          ...this.#revocation_endpoint_auth_signing_alg_values_supported,
        ],
      }),
      ...(this.#introspection_endpoint_auth_signing_alg_values_supported !==
        undefined && {
        introspection_endpoint_auth_signing_alg_values_supported: [
          ...this.#introspection_endpoint_auth_signing_alg_values_supported,
        ],
      }),
    };
  }
}
