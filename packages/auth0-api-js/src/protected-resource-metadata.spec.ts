import { describe, it, expect } from "vitest";
import {
  ProtectedResourceMetadataBuilder,
  AuthorizationScheme,
} from "./protected-resource-metadata.js";
import { MissingRequiredArgumentError } from "./errors.js";

describe("ProtectedResourceMetadataBuilder", () => {
  const VALID_RESOURCE = "http://localhost:3001/mcp";
  const VALID_AUTH_SERVERS = ["https://a0-mcp.us.auth0.com"];

  describe("constructor", () => {
    it("should create builder instance with required parameters", () => {
      const builder = new ProtectedResourceMetadataBuilder(
        VALID_RESOURCE,
        VALID_AUTH_SERVERS
      );
      const metadata = builder.build();
      const json = metadata.toJSON();

      expect(json.resource).toBe(VALID_RESOURCE);
      expect(json.authorization_servers).toEqual(VALID_AUTH_SERVERS);
      expect(json.authorization_servers).not.toBe(VALID_AUTH_SERVERS); // Should be a copy
    });

    it("should throw error for invalid parameters", () => {
      expect(
        () => new ProtectedResourceMetadataBuilder("", VALID_AUTH_SERVERS)
      ).toThrow(MissingRequiredArgumentError);

      expect(
        () => new ProtectedResourceMetadataBuilder("   ", VALID_AUTH_SERVERS)
      ).toThrow(MissingRequiredArgumentError);

      expect(
        () => new ProtectedResourceMetadataBuilder(VALID_RESOURCE, [])
      ).toThrow(MissingRequiredArgumentError);
    });
  });

  describe("builder methods", () => {
    it("should build complex metadata with fluent interface", () => {
      const metadata = new ProtectedResourceMetadataBuilder(
        VALID_RESOURCE,
        VALID_AUTH_SERVERS
      )
        .withBearerMethodsSupported([AuthorizationScheme.BEARER])
        .withScopesSupported(["read", "write", "admin"])
        .build();

      const json = metadata.toJSON();
      expect(json.resource).toBe(VALID_RESOURCE);
      expect(json.authorization_servers).toEqual(VALID_AUTH_SERVERS);
      expect(json.bearer_methods_supported).toEqual([
        AuthorizationScheme.BEARER,
      ]);
      expect(json.scopes_supported).toEqual(["read", "write", "admin"]);
    });

    it("should support builder chaining", () => {
      const baseBuilder = new ProtectedResourceMetadataBuilder(
        VALID_RESOURCE,
        VALID_AUTH_SERVERS
      );
      const scopes = ["read", "write"];
      const builderWithScopes = baseBuilder.withScopesSupported(scopes);

      // Both references point to the same builder instance
      expect(builderWithScopes).toBe(baseBuilder);

      const metadata = baseBuilder.build();
      const json = metadata.toJSON();

      // The builder should have the scopes that were added
      expect(json.scopes_supported).toEqual(scopes);

      // Test array cloning - returned arrays should be copies
      expect(json.scopes_supported).not.toBe(scopes);
      expect(json.authorization_servers).not.toBe(VALID_AUTH_SERVERS);
    });
  });

  describe("serialization", () => {
    it("should convert to JSON with only defined properties", () => {
      const jwksUri = "https://example.com/.well-known/jwks.json";
      const metadata = new ProtectedResourceMetadataBuilder(
        VALID_RESOURCE,
        VALID_AUTH_SERVERS
      )
        .withJwksUri(jwksUri)
        .withScopesSupported(["read", "write"])
        .build();

      const json = metadata.toJSON();

      expect(json).toEqual({
        resource: VALID_RESOURCE,
        authorization_servers: VALID_AUTH_SERVERS,
        jwks_uri: jwksUri,
        scopes_supported: ["read", "write"],
      });
    });

    it("should serialize metadata correctly", () => {
      const metadata = new ProtectedResourceMetadataBuilder(
        VALID_RESOURCE,
        VALID_AUTH_SERVERS
      )
        .withScopesSupported(["read", "write"])
        .withBearerMethodsSupported([AuthorizationScheme.BEARER])
        .build();

      const json = metadata.toJSON();

      expect(json.resource).toBe(VALID_RESOURCE);
      expect(json.authorization_servers).toEqual(VALID_AUTH_SERVERS);
      expect(json.scopes_supported).toEqual(["read", "write"]);
      expect(json.bearer_methods_supported).toEqual([
        AuthorizationScheme.BEARER,
      ]);

      // Arrays in JSON should be copies, not the same references
      expect(json.authorization_servers).not.toBe(VALID_AUTH_SERVERS);
      expect(json.scopes_supported).not.toBe(["read", "write"]);
    });

    it("should only include defined properties in JSON output", () => {
      const metadata = new ProtectedResourceMetadataBuilder(
        VALID_RESOURCE,
        VALID_AUTH_SERVERS
      )
        .withScopesSupported(["read"])
        .withResourceName("myResource")
        .build();

      const json = metadata.toJSON();

      expect(json).toHaveProperty("resource");
      expect(json).toHaveProperty("resource_name");
      expect(json).toHaveProperty("authorization_servers");
      expect(json).toHaveProperty("scopes_supported");
      expect(json).not.toHaveProperty("jwks_uri");
      expect(json).not.toHaveProperty("bearer_methods_supported");
    });
  });

  describe("data integrity", () => {
    it("should return immutable JSON arrays", () => {
      const metadata = new ProtectedResourceMetadataBuilder(
        VALID_RESOURCE,
        VALID_AUTH_SERVERS
      )
        .withScopesSupported(["read", "write"])
        .build();

      const json = metadata.toJSON();
      const json2 = metadata.toJSON();

      // Each call to toJSON should return new array instances
      expect(json.authorization_servers).not.toBe(json2.authorization_servers);
      expect(json.scopes_supported).not.toBe(json2.scopes_supported);

      // But with same content
      expect(json.authorization_servers).toEqual(json2.authorization_servers);
      expect(json.scopes_supported).toEqual(json2.scopes_supported);
    });

    it("should not share array references with input data", () => {
      const scopes = ["read", "write"];
      const authServers = [...VALID_AUTH_SERVERS];

      const metadata = new ProtectedResourceMetadataBuilder(
        VALID_RESOURCE,
        authServers
      )
        .withScopesSupported(scopes)
        .build();

      const json = metadata.toJSON();

      // Modifying original arrays should not affect the metadata
      scopes.push("admin");
      authServers.push("new-server");

      expect(json.scopes_supported).toEqual(["read", "write"]);
      expect(json.authorization_servers).toEqual(VALID_AUTH_SERVERS);
    });
  });
});
