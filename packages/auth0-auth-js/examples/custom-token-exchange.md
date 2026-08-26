# Custom Token Exchange

[← All examples](../EXAMPLES.md)

- [Custom Token Exchange](#custom-token-exchange)
    - [Basic Exchange](#basic-exchange)
    - [Delegation Exchange with Actor Token](#delegation-exchange-with-actor-token)
    - [Reading the act Claim](#reading-the-act-claim)
    - [M2M Delegation (No ID Token)](#m2m-delegation-no-id-token)
    - [Error Handling](#error-handling)

## Custom Token Exchange

`exchangeToken` implements [RFC 8693 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693) via an Auth0 Token Exchange Profile. It lets you swap a token issued by an external system (an MCP server, a legacy IdP, a partner service) for Auth0 tokens, preserving the user's identity.

### Basic Exchange

```ts
import { AuthClient } from '@auth0/auth0-auth-js';

const authClient = new AuthClient({
  domain: 'your-tenant.auth0.com',
  clientId: 'YOUR_CLIENT_ID',
  clientSecret: 'YOUR_CLIENT_SECRET',
});

const tokens = await authClient.exchangeToken({
  subjectToken: externalToken,
  subjectTokenType: 'urn:acme:legacy-token',
  audience: 'https://api.example.com',
  scope: 'openid profile read:data',
});

console.log(tokens.accessToken);
```

When `organization` is provided and the exchange returns an ID token, its organization claim is validated against the requested value (an `org_` prefix is matched exactly against `org_id`, otherwise the value is matched case-insensitively against `org_name`). A missing or mismatched claim throws an `OrganizationValidationError`.

```ts
const tokens = await authClient.exchangeToken({
  subjectToken: externalToken,
  subjectTokenType: 'urn:acme:legacy-token',
  audience: 'https://api.example.com',
  scope: 'openid profile read:data',
  organization: 'org_abc123',
});
```

### Delegation Exchange with Actor Token

When an intermediate service acts on behalf of a user, pass the service's own token as `actorToken`. Both `actorToken` and `actorTokenType` must be provided together.

```ts
const tokens = await authClient.exchangeToken({
  subjectToken: userToken,
  subjectTokenType: 'urn:ietf:params:oauth:token-type:access_token',
  actorToken: serviceAccountToken,
  actorTokenType: 'urn:ietf:params:oauth:token-type:access_token',
  audience: 'https://api.example.com',
});
```

### Reading the act Claim

When a delegation exchange succeeds, the `act` claim on `TokenResponse` identifies the acting party. It is sourced from the ID token when one is issued, or from the JWT access token in M2M flows where no ID token is returned.

```ts
const tokens = await authClient.exchangeToken({
  subjectToken: userToken,
  subjectTokenType: 'urn:acme:user-token',
  actorToken: serviceToken,
  actorTokenType: 'urn:acme:service-token',
  audience: 'https://api.example.com',
  scope: 'openid',
});

if (tokens.act) {
  console.log(tokens.act.sub);  // Subject of the acting party
  console.log(tokens.act.iss);  // Optional issuer of the actor token
}
```

### M2M Delegation (No ID Token)

In machine-to-machine flows the `openid` scope is not requested, so no ID token is issued. The SDK automatically falls back to reading the `act` claim from the JWT access token. If the access token is opaque, `act` will be `undefined`.

```ts
const tokens = await authClient.exchangeToken({
  subjectToken: serviceAToken,
  subjectTokenType: 'urn:acme:service-token',
  actorToken: serviceBToken,
  actorTokenType: 'urn:acme:service-token',
  audience: 'https://api.example.com',
  // no 'openid' in scope — no id_token will be returned
});

// act is populated from the JWT access token if it carries the claim
console.log(tokens.act?.sub);
```

### Error Handling

```ts
import { AuthClient, TokenExchangeError, OrganizationValidationError } from '@auth0/auth0-auth-js';

try {
  const tokens = await authClient.exchangeToken({
    subjectToken: externalToken,
    subjectTokenType: 'urn:acme:legacy-token',
    audience: 'https://api.example.com',
    organization: 'org_abc123',
  });
} catch (error) {
  if (error instanceof OrganizationValidationError) {
    // The ID token's organization claim did not match the requested organization.
    console.error(error.message);
    console.error(error.code);          // 'organization_validation_error'
  } else if (error instanceof TokenExchangeError) {
    console.error(error.message);       // Human-readable error message
    console.error(error.code);          // 'token_exchange_error'
    console.error(error.cause?.error);  // e.g., 'invalid_grant', 'access_denied'
  }
}
```
