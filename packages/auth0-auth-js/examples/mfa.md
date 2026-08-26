# Multi-Factor Authentication (MFA)

[← All examples](../EXAMPLES.md)

- [Using Multi-Factor Authentication (MFA)](#using-multi-factor-authentication-mfa)
    - [Enrolling an Authenticator](#enrolling-an-authenticator)
    - [Listing Authenticators](#listing-authenticators)
    - [Challenging an Authenticator](#challenging-an-authenticator)
    - [Verifying an Authenticator](#verifying-an-authenticator)
    - [Deleting an Authenticator](#deleting-an-authenticator)

## Using Multi-Factor Authentication (MFA)

The SDK provides an MFA client to manage multi-factor authentication for your users. The MFA client is accessible via the `mfa` property on the `AuthClient` instance.

> [!IMPORTANT]
> MFA operations require an MFA token. This token is available on the error's `cause` when the server returns `mfa_required` during the authentication flow. Use the `isMfaRequiredError` type guard to detect this condition and access the token.

[Refer API Docs ](https://auth0.com/docs/api/authentication/muti-factor-authentication/request-mfa-challenge)

### Handling the MFA Required Response

When the server requires multi-factor authentication, token request methods (`getTokenByPassword`, `getTokenByRefreshToken`, `exchangeToken`, `passkey.getTokenByPasskey`) throw their usual error class (`TokenByPasswordError`, `TokenByRefreshTokenError`, `TokenExchangeError`, `PasskeyGetTokenError`) with extra MFA context on `cause`:

| Field | Type | Description |
|-------|------|-------------|
| `cause.error` | `'mfa_required'` | Indicates MFA is required |
| `cause.mfa_token` | `string` | Token to pass to MFA APIs |
| `cause.mfa_requirements` | `{ challenge?: Array<{ type: string }>; enroll?: Array<{ type: string }> }` | Which factors the user must challenge or enroll (optional) |

Use the exported `isMfaRequiredError` type guard to detect and narrow the error:

```ts
import { AuthClient, isMfaRequiredError } from '@auth0/auth0-auth-js';

const authClient = new AuthClient({
  domain: '<AUTH0_DOMAIN>',
  clientId: '<AUTH0_CLIENT_ID>',
  clientSecret: '<AUTH0_CLIENT_SECRET>',
});

try {
  const tokens = await authClient.getTokenByPassword({
    username: 'user@example.com',
    password: 'password123',
  });
} catch (error) {
  if (isMfaRequiredError(error)) {
    // TypeScript narrows: error.cause.mfa_token is guaranteed to be a string
    const { mfa_token, mfa_requirements } = error.cause;

    if (mfa_requirements?.enroll?.length) {
      // User needs to enroll a new factor — see "Enrolling an Authenticator" below
      const enrollment = await authClient.mfa.enrollAuthenticator({
        mfaToken: mfa_token,
        authenticatorTypes: ['otp'],
      });
    } else {
      // User has enrolled factors — see "Challenging an Authenticator" below
      const challenge = await authClient.mfa.challengeAuthenticator({
        mfaToken: mfa_token,
        challengeType: 'otp',
      });
    }
  }
}
```

The same pattern works for refresh token and token exchange flows:

```ts
import { isMfaRequiredError } from '@auth0/auth0-auth-js';

try {
  const tokens = await authClient.getTokenByRefreshToken({
    refreshToken: 'existing_refresh_token',
  });
} catch (error) {
  if (isMfaRequiredError(error)) {
    // Step-up MFA required for this audience/scope
    const challenge = await authClient.mfa.challengeAuthenticator({
      mfaToken: error.cause.mfa_token,
      challengeType: 'otp',
    });
  }
}
```

### Enrolling an Authenticator

To enroll a new MFA authenticator, use the `enrollAuthenticator` method. This example shows how to enroll an OTP authenticator (for TOTP apps like Google Authenticator or Auth0):

```ts
import { AuthClient } from '@auth0/auth0-auth-js';

const authClient = new AuthClient({
  domain: '<AUTH0_DOMAIN>',
  clientId: '<AUTH0_CLIENT_ID>',
  clientSecret: '<AUTH0_CLIENT_SECRET>',
});

// Enroll an OTP authenticator
const mfaToken = '<mfa_token_from_challenge>';
const enrollmentResponse = await authClient.mfa.enrollAuthenticator({
  authenticatorTypes: ['otp'],
  mfaToken,
});

// The response contains the secret and QR code URI for user to scan
// enrollmentResponse.secret - Base32-encoded secret for TOTP generation
// enrollmentResponse.barcodeUri - URI for generating QR code
```

You can also enroll SMS-based authenticators:

```ts
// Enroll an SMS authenticator
const smsEnrollment = await authClient.mfa.enrollAuthenticator({
  authenticatorTypes: ['oob'],
  oobChannels: ['sms'],
  phoneNumber: '+1234567890',
  mfaToken,
});
```

### Listing Authenticators

To retrieve all enrolled authenticators for a user, use the `listAuthenticators` method:

```ts
const mfaToken = '<mfa_token>';
const authenticators = await authClient.mfa.listAuthenticators({ mfaToken });

// authenticators is an array of Authenticator objects
// Each authenticator has: id, authenticatorType, active, name, oobChannels (for OOB types), type
```

### Challenging an Authenticator

To initiate an MFA challenge for verification, use the `challengeAuthenticator` method:

```ts
const mfaToken = '<mfa_token>';

// Challenge with OTP
const otpChallenge = await authClient.mfa.challengeAuthenticator({
  challengeType: 'otp',
  mfaToken,
});

// Challenge with SMS (OOB)
const smsChallenge = await authClient.mfa.challengeAuthenticator({
  challengeType: 'oob',
  authenticatorId: 'sms|dev_abc123',
  mfaToken,
});

// For OOB challenges, the response includes an oobCode
// smsChallenge.oobCode - Out-of-band code for verification
```

### Verifying an Authenticator

To complete the MFA flow, use the `verify` method to exchange the user's submitted factor for tokens:

```ts
const mfaToken = '<mfa_token>';

// Verify with OTP (code from the user's authenticator app)
const tokens = await authClient.mfa.verify({
  mfaToken,
  factorType: 'otp',
  otp: '<otp_code>',
});

// Verify with OOB (code delivered by SMS, voice or email)
const oobTokens = await authClient.mfa.verify({
  mfaToken,
  factorType: 'oob',
  oobCode: '<oob_code_from_challenge>',
});

// Only when the challenge response came back with bindingMethod 'prompt': the user
// must also enter the code delivered over the channel, passed as bindingCode.
const promptBoundTokens = await authClient.mfa.verify({
  mfaToken,
  factorType: 'oob',
  oobCode: '<oob_code_from_challenge>',
  bindingCode: '<binding_code>',
});

// Verify with a recovery code
const recoveryTokens = await authClient.mfa.verify({
  mfaToken,
  factorType: 'recovery-code',
  recoveryCode: '<recovery_code>',
});

// tokens.accessToken, tokens.idToken, tokens.refreshToken
// tokens.recoveryCode - A new recovery code, when one is issued. Display it to the
// user once; it cannot be retrieved again.
```

An `MfaVerifyError` is thrown when verification fails (e.g., invalid code, expired token).

### Deleting an Authenticator

To remove a previously enrolled authenticator, use the `deleteAuthenticator` method:

```ts
const mfaToken = '<mfa_token>';
const authenticatorId = 'totp|dev_abc123';

await authClient.mfa.deleteAuthenticator({ authenticatorId, mfaToken });
```
