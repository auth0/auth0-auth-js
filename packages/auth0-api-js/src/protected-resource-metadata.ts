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
  resource_name?: string;
  resource_documentation?: string;
  resource_policy_uri?: string;
  resource_tos_uri?: string;
  tls_client_certificate_bound_access_tokens?: boolean;
  authorization_details_types_supported?: string[];
  dpop_signing_alg_values_supported?: string[];
  dpop_bound_access_tokens_required?: boolean;
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
   * Builder method to add resource_name
   */
  withResourceName(resource_name: string): this {
    this.props.resource_name = resource_name;
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
   * Builder method to enable TLS client certificate bound access tokens
   */
  withTlsClientCertificateBoundAccessTokens(tls_client_certificate_bound_access_tokens: boolean): this {
    this.props.tls_client_certificate_bound_access_tokens = tls_client_certificate_bound_access_tokens;
    return this;
  }

  /**
   * Builder method to add supported authorization details types
   */
  withAuthorizationDetailsTypesSupported(authorization_details_types_supported: string[]): this {
    this.props.authorization_details_types_supported = [...authorization_details_types_supported];
    return this;
  }

  /**
   * Builder method to add supported DPoP signing algorithms
   */
  withDpopSigningAlgValuesSupported(dpop_signing_alg_values_supported: string[]): this {
    this.props.dpop_signing_alg_values_supported = [...dpop_signing_alg_values_supported];
    return this;
  }

  /**
   * Builder method to require DPoP bound access tokens
   */
  withDpopBoundAccessTokensRequired(dpop_bound_access_tokens_required: boolean): this {
    this.props.dpop_bound_access_tokens_required = dpop_bound_access_tokens_required;
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
  readonly #resource_name?: string;
  readonly #tls_client_certificate_bound_access_tokens?: boolean;
  readonly #authorization_details_types_supported?: string[];
  readonly #dpop_signing_alg_values_supported?: string[];
  readonly #dpop_bound_access_tokens_required?: boolean;

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
    this.#resource_name = props.resource_name;
    this.#tls_client_certificate_bound_access_tokens = props.tls_client_certificate_bound_access_tokens;
    this.#authorization_details_types_supported = props.authorization_details_types_supported
      ? [...props.authorization_details_types_supported]
      : undefined;
    this.#dpop_signing_alg_values_supported = props.dpop_signing_alg_values_supported
      ? [...props.dpop_signing_alg_values_supported]
      : undefined;
    this.#dpop_bound_access_tokens_required = props.dpop_bound_access_tokens_required;
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
      ...(this.#resource_name !== undefined && {
        resource_name: this.#resource_name,
      }),
      ...(this.#tls_client_certificate_bound_access_tokens !== undefined && {
        tls_client_certificate_bound_access_tokens: this.#tls_client_certificate_bound_access_tokens,
      }),
      ...(this.#authorization_details_types_supported !== undefined && {
        authorization_details_types_supported: [...this.#authorization_details_types_supported],
      }),
      ...(this.#dpop_signing_alg_values_supported !== undefined && {
        dpop_signing_alg_values_supported: [...this.#dpop_signing_alg_values_supported],
      }),
      ...(this.#dpop_bound_access_tokens_required !== undefined && {
        dpop_bound_access_tokens_required: this.#dpop_bound_access_tokens_required,
      }),
    };
  }
}
