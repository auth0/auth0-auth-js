/**
 * Compile-time type-checking fixture for the fullResponse feature.
 * This file is NOT executed by vitest — it is checked via `tsc --noEmit` in the CI pipeline.
 * Ensures overload discrimination and type exports function correctly.
 *
 * Test coverage:
 *  - T-RG-01 (RG-1 gate): fullResponse overloads compile without error
 *  - T-AUTH-GRANTREQFN-EXPORT: GrantRequestFn re-export from passwordless
 */

import type { AuthClient } from '../src/auth-client.js';
import type { ApiResponse, TokenResponse } from '../src/types.js';
import type { GrantRequestFn } from '../src/passwordless/types.js';
import type { PasskeyCredentialResponse } from '../src/passkey/types.js';

// Dummy client instance (type-level only)
declare const client: AuthClient;

// ----------------------------------------------------------------------------
// T-RG-01: fullResponse overload signatures compile
// ----------------------------------------------------------------------------

async function typeCheckFullResponseOverloads() {
  // getTokenByRefreshToken: no flag → TokenResponse
  const r1: TokenResponse = await client.getTokenByRefreshToken({ refreshToken: 'rt' });

  // getTokenByRefreshToken: fullResponse: true → ApiResponse<TokenResponse>
  const r2: ApiResponse<TokenResponse> = await client.getTokenByRefreshToken({
    refreshToken: 'rt',
    fullResponse: true,
  });

  // getTokenByCode: fullResponse: true
  const r3: ApiResponse<TokenResponse> = await client.getTokenByCode(new URL('https://auth0.local?code=c&state=s'), {
    codeVerifier: 'v',
    fullResponse: true,
  });

  // getTokenByMagicLinkCode: fullResponse: true
  const r4: ApiResponse<TokenResponse> = await client.getTokenByMagicLinkCode(
    new URL('https://auth0.local?code=c&state=s'),
    { expectedState: 's', fullResponse: true }
  );

  // getTokenByPassword: fullResponse: true
  const r5: ApiResponse<TokenResponse> = await client.getTokenByPassword({
    username: 'user',
    password: 'pass',
    fullResponse: true,
  });

  // getTokenByPasswordlessEmail: fullResponse: true
  const r6: ApiResponse<TokenResponse> = await client.getTokenByPasswordlessEmail({
    email: 'e@e.com',
    code: '123456',
    fullResponse: true,
  });

  // getTokenByPasswordlessSms: fullResponse: true
  const r7: ApiResponse<TokenResponse> = await client.getTokenByPasswordlessSms({
    phoneNumber: '+15555555',
    code: '123456',
    fullResponse: true,
  });

  // exchangeToken (profile): fullResponse: true
  const r8: ApiResponse<TokenResponse> = await client.exchangeToken({
    subjectToken: 'st',
    subjectTokenType: 'urn:t',
    fullResponse: true,
  });

  // exchangeToken (vault): fullResponse: true
  const r9: ApiResponse<TokenResponse> = await client.exchangeToken({
    connection: 'conn',
    refreshToken: 'rt',
    fullResponse: true,
  });

  // getTokenForConnection: fullResponse: true
  const r10: ApiResponse<TokenResponse> = await client.getTokenForConnection({
    connection: 'conn',
    refreshToken: 'rt',
    fullResponse: true,
  });

  // backchannelAuthentication: fullResponse: true
  const r11: ApiResponse<TokenResponse> = await client.backchannelAuthentication({
    loginHint: { format: 'iss_sub', iss: 'https://x/', sub: 's' },
    fullResponse: true,
  });

  // getTokenByClientCredentials: fullResponse: true
  const r12: ApiResponse<TokenResponse> = await client.getTokenByClientCredentials({
    fullResponse: true,
  });

  // mfa.verify: fullResponse: true
  const r13: ApiResponse<TokenResponse> = await client.mfa.verify({
    mfaToken: 'mt',
    factorType: 'otp',
    otp: '123456',
    fullResponse: true,
  });

  // passkey.getTokenByPasskey: fullResponse: true
  const r14: ApiResponse<TokenResponse> = await client.passkey.getTokenByPasskey({
    authSession: 'as',
    credential: {} as PasskeyCredentialResponse,
    fullResponse: true,
  });

  // passwordless.getTokenByPasswordlessDbConnection: fullResponse: true
  const r15: ApiResponse<TokenResponse> = await client.passwordless.getTokenByPasswordlessDbConnection({
    email: 'e@e.com',
    code: '123456',
    connection: 'email',
    fullResponse: true,
  });

  // Suppress unused variable warnings
  void [r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15];
}

// ----------------------------------------------------------------------------
// T-NEG-04: backchannelAuthenticationGrant has no fullResponse overload
// ----------------------------------------------------------------------------

async function typeCheckBackchannelAuthenticationGrantNoFullResponse() {
  // @ts-expect-error — fullResponse is not in backchannelAuthenticationGrant's options type
  await client.backchannelAuthenticationGrant({ authReqId: 'id', fullResponse: true });
}

// ----------------------------------------------------------------------------
// T-AUTH-GRANTREQFN-EXPORT: GrantRequestFn is exported from passwordless
// ----------------------------------------------------------------------------

const _grantRequestFnCheck: GrantRequestFn = null!;

// Suppress unused warnings
void typeCheckFullResponseOverloads;
void typeCheckBackchannelAuthenticationGrantNoFullResponse;
void _grantRequestFnCheck;
