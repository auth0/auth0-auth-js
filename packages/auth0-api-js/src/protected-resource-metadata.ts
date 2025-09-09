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
  readonly resource: string;
  readonly authorization_servers: string[];
  readonly jwks_uri?: string;
  readonly scopes_supported?: string[];
  readonly bearer_methods_supported?: AuthorizationScheme[];
  readonly resource_documentation?: string;
  readonly resource_policy_uri?: string;
  readonly resource_tos_uri?: string;
  readonly token_endpoint_auth_methods_supported?: TokenEndpointAuthMethod[];
  readonly revocation_endpoint_auth_methods_supported?: TokenEndpointAuthMethod[];
  readonly introspection_endpoint_auth_methods_supported?: TokenEndpointAuthMethod[];
  readonly token_endpoint_auth_signing_alg_values_supported?: SigningAlgorithm[];
  readonly revocation_endpoint_auth_signing_alg_values_supported?: SigningAlgorithm[];
  readonly introspection_endpoint_auth_signing_alg_values_supported?: SigningAlgorithm[];
}

/**
 * Immutable Protected Resource Metadata class implementing RFC 9728
 */
export class ProtectedResourceMetadata implements IProtectedResourceMetadata {
  public readonly resource: string;
  public readonly authorization_servers: string[];
  public readonly jwks_uri?: string;
  public readonly scopes_supported?: string[];
  public readonly bearer_methods_supported?: AuthorizationScheme[];
  public readonly resource_documentation?: string;
  public readonly resource_policy_uri?: string;
  public readonly resource_tos_uri?: string;
  public readonly token_endpoint_auth_methods_supported?: TokenEndpointAuthMethod[];
  public readonly revocation_endpoint_auth_methods_supported?: TokenEndpointAuthMethod[];
  public readonly introspection_endpoint_auth_methods_supported?: TokenEndpointAuthMethod[];
  public readonly token_endpoint_auth_signing_alg_values_supported?: SigningAlgorithm[];
  public readonly revocation_endpoint_auth_signing_alg_values_supported?: SigningAlgorithm[];
  public readonly introspection_endpoint_auth_signing_alg_values_supported?: SigningAlgorithm[];

  /**
   * Constructor for ProtectedResourceMetadata
   * @param resource - The protected resource identifier (REQUIRED)
   * @param authorization_servers - Array of authorization server URLs (REQUIRED)
   */
  constructor(resource: string, authorization_servers: string[]) {
    if (!resource?.trim()) {
      throw new MissingRequiredArgumentError("resource");
    }

    if (!Array.isArray(authorization_servers) || authorization_servers.length === 0) {
      throw new MissingRequiredArgumentError("authorization_servers");
    }

    this.resource = resource;
    this.authorization_servers = [...authorization_servers]; // Create immutable copy
  }

  /**
   * Builder method to add JWKS URI
   */
  withJwksUri(jwks_uri: string): ProtectedResourceMetadata {
    return this.clone({ jwks_uri });
  }

  /**
   * Builder method to add supported scopes
   */
  withScopesSupported(scopes_supported: string[]): ProtectedResourceMetadata {
    return this.clone({ scopes_supported: [...scopes_supported] });
  }

  /**
   * Builder method to add supported bearer methods
   */
  withBearerMethodsSupported(
    bearer_methods_supported: AuthorizationScheme[]
  ): ProtectedResourceMetadata {
    return this.clone({
      bearer_methods_supported: [...bearer_methods_supported],
    });
  }

  /**
   * Builder method to add resource documentation URL
   */
  withResourceDocumentation(
    resource_documentation: string
  ): ProtectedResourceMetadata {
    return this.clone({ resource_documentation });
  }

  /**
   * Builder method to add resource policy URI
   */
  withResourcePolicyUri(
    resource_policy_uri: string
  ): ProtectedResourceMetadata {
    return this.clone({ resource_policy_uri });
  }

  /**
   * Builder method to add resource terms of service URI
   */
  withResourceTosUri(resource_tos_uri: string): ProtectedResourceMetadata {
    return this.clone({ resource_tos_uri });
  }

  /**
   * Builder method to add token endpoint auth methods
   */
  withTokenEndpointAuthMethodsSupported(
    methods: TokenEndpointAuthMethod[]
  ): ProtectedResourceMetadata {
    return this.clone({ token_endpoint_auth_methods_supported: [...methods] });
  }

  /**
   * Builder method to add revocation endpoint auth methods
   */
  withRevocationEndpointAuthMethodsSupported(
    methods: TokenEndpointAuthMethod[]
  ): ProtectedResourceMetadata {
    return this.clone({
      revocation_endpoint_auth_methods_supported: [...methods],
    });
  }

  /**
   * Builder method to add introspection endpoint auth methods
   */
  withIntrospectionEndpointAuthMethodsSupported(
    methods: TokenEndpointAuthMethod[]
  ): ProtectedResourceMetadata {
    return this.clone({
      introspection_endpoint_auth_methods_supported: [...methods],
    });
  }

  /**
   * Builder method to add token endpoint auth signing algorithms
   */
  withTokenEndpointAuthSigningAlgValuesSupported(
    algorithms: SigningAlgorithm[]
  ): ProtectedResourceMetadata {
    return this.clone({
      token_endpoint_auth_signing_alg_values_supported: [...algorithms],
    });
  }

  /**
   * Builder method to add revocation endpoint auth signing algorithms
   */
  withRevocationEndpointAuthSigningAlgValuesSupported(
    algorithms: SigningAlgorithm[]
  ): ProtectedResourceMetadata {
    return this.clone({
      revocation_endpoint_auth_signing_alg_values_supported: [...algorithms],
    });
  }

  /**
   * Builder method to add introspection endpoint auth signing algorithms
   */
  withIntrospectionEndpointAuthSigningAlgValuesSupported(
    algorithms: SigningAlgorithm[]
  ): ProtectedResourceMetadata {
    return this.clone({
      introspection_endpoint_auth_signing_alg_values_supported: [...algorithms],
    });
  }

  /**
   * Convert to JSON representation
   */
  toJSON(): IProtectedResourceMetadata {
    const result = {
      resource: this.resource,
      authorization_servers: this.authorization_servers,
      ...(this.jwks_uri !== undefined && { jwks_uri: this.jwks_uri }),
      ...(this.scopes_supported !== undefined && {
        scopes_supported: this.scopes_supported,
      }),
      ...(this.bearer_methods_supported !== undefined && {
        bearer_methods_supported: this.bearer_methods_supported,
      }),
      ...(this.resource_documentation !== undefined && {
        resource_documentation: this.resource_documentation,
      }),
      ...(this.resource_policy_uri !== undefined && {
        resource_policy_uri: this.resource_policy_uri,
      }),
      ...(this.resource_tos_uri !== undefined && {
        resource_tos_uri: this.resource_tos_uri,
      }),
      ...(this.token_endpoint_auth_methods_supported !== undefined && {
        token_endpoint_auth_methods_supported:
          this.token_endpoint_auth_methods_supported,
      }),
      ...(this.revocation_endpoint_auth_methods_supported !== undefined && {
        revocation_endpoint_auth_methods_supported:
          this.revocation_endpoint_auth_methods_supported,
      }),
      ...(this.introspection_endpoint_auth_methods_supported !== undefined && {
        introspection_endpoint_auth_methods_supported:
          this.introspection_endpoint_auth_methods_supported,
      }),
      ...(this.token_endpoint_auth_signing_alg_values_supported !==
        undefined && {
        token_endpoint_auth_signing_alg_values_supported:
          this.token_endpoint_auth_signing_alg_values_supported,
      }),
      ...(this.revocation_endpoint_auth_signing_alg_values_supported !==
        undefined && {
        revocation_endpoint_auth_signing_alg_values_supported:
          this.revocation_endpoint_auth_signing_alg_values_supported,
      }),
      ...(this.introspection_endpoint_auth_signing_alg_values_supported !==
        undefined && {
        introspection_endpoint_auth_signing_alg_values_supported:
          this.introspection_endpoint_auth_signing_alg_values_supported,
      }),
    };

    return result;
  }

  /**
   * Create a ProtectedResourceMetadata instance from JSON
   */
  static fromJSON(data: IProtectedResourceMetadata): ProtectedResourceMetadata {
    const metadata = new ProtectedResourceMetadata(
      data.resource,
      data.authorization_servers
    );

    return metadata.clone({
      jwks_uri: data.jwks_uri,
      scopes_supported: data.scopes_supported
        ? [...data.scopes_supported]
        : undefined,
      bearer_methods_supported: data.bearer_methods_supported
        ? [...data.bearer_methods_supported]
        : undefined,
      resource_documentation: data.resource_documentation,
      resource_policy_uri: data.resource_policy_uri,
      resource_tos_uri: data.resource_tos_uri,
      token_endpoint_auth_methods_supported:
        data.token_endpoint_auth_methods_supported
          ? [...data.token_endpoint_auth_methods_supported]
          : undefined,
      revocation_endpoint_auth_methods_supported:
        data.revocation_endpoint_auth_methods_supported
          ? [...data.revocation_endpoint_auth_methods_supported]
          : undefined,
      introspection_endpoint_auth_methods_supported:
        data.introspection_endpoint_auth_methods_supported
          ? [...data.introspection_endpoint_auth_methods_supported]
          : undefined,
      token_endpoint_auth_signing_alg_values_supported:
        data.token_endpoint_auth_signing_alg_values_supported
          ? [...data.token_endpoint_auth_signing_alg_values_supported]
          : undefined,
      revocation_endpoint_auth_signing_alg_values_supported:
        data.revocation_endpoint_auth_signing_alg_values_supported
          ? [...data.revocation_endpoint_auth_signing_alg_values_supported]
          : undefined,
      introspection_endpoint_auth_signing_alg_values_supported:
        data.introspection_endpoint_auth_signing_alg_values_supported
          ? [...data.introspection_endpoint_auth_signing_alg_values_supported]
          : undefined,
    });
  }

  /**
   * Private method to create a clone with additional properties
   */
  private clone(
    additionalProps: Partial<IProtectedResourceMetadata>
  ): ProtectedResourceMetadata {
    const cloned = Object.create(ProtectedResourceMetadata.prototype);
    Object.assign(cloned, this, additionalProps);
    return cloned;
  }
}
