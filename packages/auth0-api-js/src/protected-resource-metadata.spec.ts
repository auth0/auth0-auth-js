import { describe, it, expect } from 'vitest';
import {
  ProtectedResourceMetadata,
  AuthorizationScheme,
  TokenEndpointAuthMethod,
  SigningAlgorithm,
} from './protected-resource-metadata.js';
import { MissingRequiredArgumentError } from './errors.js';

describe('ProtectedResourceMetadata', () => {
  const VALID_RESOURCE = 'http://localhost:3001/mcp';
  const VALID_AUTH_SERVERS = ['https://a0-mcp.us.auth0.com'];

  describe('constructor', () => {
    it('should create instance with required parameters', () => {
      const metadata = new ProtectedResourceMetadata(VALID_RESOURCE, VALID_AUTH_SERVERS);

      expect(metadata.resource).toBe(VALID_RESOURCE);
      expect(metadata.authorization_servers).toEqual(VALID_AUTH_SERVERS);
      expect(metadata.authorization_servers).not.toBe(VALID_AUTH_SERVERS); // Should be a copy
    });

    it('should throw error for invalid parameters', () => {
      expect(() => new ProtectedResourceMetadata('', VALID_AUTH_SERVERS))
        .toThrow(MissingRequiredArgumentError);

      expect(() => new ProtectedResourceMetadata(VALID_RESOURCE, []))
        .toThrow(MissingRequiredArgumentError);
    });
  });

  describe('builder methods', () => {
    it('should build complex metadata with fluent interface', () => {
      const metadata = new ProtectedResourceMetadata(
        VALID_RESOURCE,
        VALID_AUTH_SERVERS
      )
        .withBearerMethodsSupported([AuthorizationScheme.BEARER])
        .withTokenEndpointAuthMethodsSupported([
          TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
          TokenEndpointAuthMethod.CLIENT_SECRET_POST,
          TokenEndpointAuthMethod.PRIVATE_KEY_JWT
        ])
        .withTokenEndpointAuthSigningAlgValuesSupported([
          SigningAlgorithm.RS256,
          SigningAlgorithm.ES256
        ])
        .withScopesSupported(['read', 'write', 'admin']);

      expect(metadata.resource).toBe(VALID_RESOURCE);
      expect(metadata.authorization_servers).toEqual(VALID_AUTH_SERVERS);
      expect(metadata.bearer_methods_supported).toEqual([AuthorizationScheme.BEARER]);
      expect(metadata.token_endpoint_auth_methods_supported).toEqual([
        TokenEndpointAuthMethod.CLIENT_SECRET_BASIC,
        TokenEndpointAuthMethod.CLIENT_SECRET_POST,
        TokenEndpointAuthMethod.PRIVATE_KEY_JWT
      ]);
      expect(metadata.token_endpoint_auth_signing_alg_values_supported).toEqual([
        SigningAlgorithm.RS256,
        SigningAlgorithm.ES256
      ]);
      expect(metadata.scopes_supported).toEqual(['read', 'write', 'admin']);
    });

    it('should maintain immutability and clone arrays', () => {
      const original = new ProtectedResourceMetadata(VALID_RESOURCE, VALID_AUTH_SERVERS);
      const scopes = ['read', 'write'];
      const modified = original.withScopesSupported(scopes);

      // Test immutability
      expect(original.scopes_supported).toBeUndefined();
      expect(modified.scopes_supported).toEqual(scopes);
      expect(modified).not.toBe(original);

      // Test array cloning
      expect(modified.scopes_supported).not.toBe(scopes);
    });
  });

  describe('serialization', () => {
    it('should convert to JSON with only defined properties', () => {
      const jwksUri = 'https://example.com/.well-known/jwks.json';
      const metadata = new ProtectedResourceMetadata(VALID_RESOURCE, VALID_AUTH_SERVERS)
        .withJwksUri(jwksUri)
        .withScopesSupported(['read', 'write']);

      const json = metadata.toJSON();

      expect(json).toEqual({
        resource: VALID_RESOURCE,
        authorization_servers: VALID_AUTH_SERVERS,
        jwks_uri: jwksUri,
        scopes_supported: ['read', 'write'],
      });
    });

    it('should round-trip through JSON correctly', () => {
      const original = new ProtectedResourceMetadata(VALID_RESOURCE, VALID_AUTH_SERVERS)
        .withScopesSupported(['read', 'write'])
        .withBearerMethodsSupported([AuthorizationScheme.BEARER])
        .withTokenEndpointAuthMethodsSupported([TokenEndpointAuthMethod.CLIENT_SECRET_BASIC]);

      const json = original.toJSON();
      const restored = ProtectedResourceMetadata.fromJSON(json);

      expect(restored.resource).toBe(original.resource);
      expect(restored.authorization_servers).toEqual(original.authorization_servers);
      expect(restored.scopes_supported).toEqual(original.scopes_supported);
      expect(restored.bearer_methods_supported).toEqual(original.bearer_methods_supported);
      expect(restored.token_endpoint_auth_methods_supported).toEqual(original.token_endpoint_auth_methods_supported);
    });
  });
});
