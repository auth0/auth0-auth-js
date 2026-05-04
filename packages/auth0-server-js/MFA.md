# Multi-Factor Authentication (MFA)

The `auth0-server-js` SDK supports the full MFA lifecycle — listing enrolled authenticators, enrolling new ones, challenging, and verifying — through the `serverClient.mfa` sub-client.

> [!NOTE]
> MFA support is in Early Access. For background, see the [Auth0 MFA documentation](https://auth0.com/docs/secure/multi-factor-authentication).

> [!IMPORTANT]
> `serverClient.mfa` is only available when using a **static domain** configuration. It is not supported in [resolver mode](./EXAMPLES.md#multiple-custom-domains-mcd).

## Table of Contents

- [Setup](#setup)
- [Handling MFA Required](#handling-mfa-required)
- [Listing Authenticators](#listing-authenticators)
- [Enrolling an Authenticator](#enrolling-an-authenticator)
  - [OTP (Authenticator App)](#otp-authenticator-app)
  - [SMS / Voice](#sms--voice)
  - [Email](#email)
- [Challenging an Authenticator](#challenging-an-authenticator)
- [Verifying MFA](#verifying-mfa)
  - [Verify with OTP](#verify-with-otp)
  - [Verify with OOB (SMS / Voice / Email)](#verify-with-oob-sms--voice--email)
  - [Verify with Recovery Code](#verify-with-recovery-code)
- [Session Persistence](#session-persistence)
- [Complete Flow Examples](#complete-flow-examples)
  - [Enrollment Flow](#enrollment-flow)
  - [Challenge Flow](#challenge-flow)
- [Error Handling](#error-handling)

## Setup

Enable MFA in your [Auth0 Dashboard](https://manage.auth0.com) under **Security** > **Multi-factor Auth**, then instantiate `ServerClient` with a static domain:

```ts
import { ServerClient } from '@auth0/auth0-server-js';

const serverClient = new ServerClient({
  domain: '<AUTH0_DOMAIN>',
  clientId: '<AUTH0_CLIENT_ID>',
  clientSecret: '<AUTH0_CLIENT_SECRET>',
  transactionStore: myTransactionStore,
  stateStore: myStateStore,
});
```

## Handling MFA Required

When `getAccessToken()` triggers an MFA requirement, Auth0 returns an `mfa_required` error. The SDK surfaces this as `MfaRequiredError`, which carries the `mfaToken` needed to proceed:

```ts
import { MfaRequiredError } from '@auth0/auth0-server-js';

try {
  const tokenSet = await serverClient.getAccessToken(storeOptions);
} catch (err) {
  if (err instanceof MfaRequiredError) {
    const { mfaToken } = err; // raw MFA token from Auth0

    const authenticators = await serverClient.mfa.listAuthenticators({ mfaToken });

    if (authenticators.length === 0) {
      // No authenticators enrolled — run the enrollment flow
    } else {
      // Authenticators exist — run the challenge flow
    }
  }
}
```

> [!NOTE]
> Unlike some other SDKs, the `mfaToken` exposed by `MfaRequiredError` in `auth0-server-js` is the **raw** token from Auth0. There is no additional encryption step required before passing it to `serverClient.mfa` methods.

## Listing Authenticators

Retrieve the authenticators the user has already enrolled:

```ts
import { MfaListAuthenticatorsError } from '@auth0/auth0-server-js';

try {
  const authenticators = await serverClient.mfa.listAuthenticators({ mfaToken });

  for (const auth of authenticators) {
    console.log(auth.id);              // e.g. 'totp|dev_abc123'
    console.log(auth.authenticatorType); // 'otp' | 'oob' | 'recovery-code'
    console.log(auth.active);
    // OOB authenticators also expose: auth.oobChannels ('sms' | 'voice' | 'email' | 'auth0')
  }
} catch (err) {
  if (err instanceof MfaListAuthenticatorsError) {
    console.error('Failed to list authenticators:', err.message);
  }
}
```

### Passing `storeOptions`

Like all SDK methods, `listAuthenticators` accepts `storeOptions` as a second argument:

```ts
const authenticators = await serverClient.mfa.listAuthenticators(
  { mfaToken },
  storeOptions
);
```

## Enrolling an Authenticator

### OTP (Authenticator App)

```ts
import { MfaEnrollmentError } from '@auth0/auth0-server-js';

try {
  const enrollment = await serverClient.mfa.enrollAuthenticator({
    mfaToken,
    authenticatorTypes: ['otp'],
  });

  // enrollment is OtpEnrollmentResponse
  console.log(enrollment.barcodeUri); // otpauth://totp/... — render as QR code
  console.log(enrollment.secret);     // base32 secret for manual entry
} catch (err) {
  if (err instanceof MfaEnrollmentError) {
    console.error('Enrollment failed:', err.message);
  }
}
```

### SMS / Voice

```ts
const enrollment = await serverClient.mfa.enrollAuthenticator({
  mfaToken,
  authenticatorTypes: ['oob'],
  oobChannels: ['sms'],       // or ['voice']
  phoneNumber: '+12025551234', // E.164 format
});

// enrollment is OobEnrollmentResponse
console.log(enrollment.oobCode); // save for verify step
```

### Email

```ts
const enrollment = await serverClient.mfa.enrollAuthenticator({
  mfaToken,
  authenticatorTypes: ['oob'],
  oobChannels: ['email'],
  // email is optional — omit to use the user's registered email
});

console.log(enrollment.oobCode);
```

## Challenging an Authenticator

After listing authenticators, initiate a challenge on the selected one:

```ts
import { MfaChallengeError } from '@auth0/auth0-server-js';

try {
  const challenge = await serverClient.mfa.challengeAuthenticator({
    mfaToken,
    challengeType: 'oob',          // or 'otp'
    authenticatorId: 'sms|dev_abc', // from listAuthenticators
  });

  // For OOB challenges: save challenge.oobCode for verify step
  console.log(challenge.oobCode);
  console.log(challenge.bindingMethod); // 'prompt' means user enters a code
} catch (err) {
  if (err instanceof MfaChallengeError) {
    console.error('Challenge failed:', err.message);
  }
}
```

> [!NOTE]
> For OTP authenticators you do not need to call `challengeAuthenticator` — simply prompt the user to open their authenticator app and read the code, then call `verify` directly.

## Verifying MFA

### Verify with OTP

```ts
import { MfaVerifyError } from '@auth0/auth0-server-js';

try {
  const result = await serverClient.mfa.verify(
    {
      mfaToken,
      factorType: 'otp',
      otp: '123456', // 6-digit code from authenticator app
    },
    storeOptions
  );

  console.log(result.accessToken);
  console.log(result.idToken);
  console.log(result.refreshToken);

  if (result.recoveryCode) {
    // Shown on first enrollment — store it securely for the user
    console.log('Save your recovery code:', result.recoveryCode);
  }
} catch (err) {
  if (err instanceof MfaVerifyError) {
    console.error('Verification failed:', err.message, err.cause);
  }
}
```

### Verify with OOB (SMS / Voice / Email)

```ts
const result = await serverClient.mfa.verify(
  {
    mfaToken,
    factorType: 'oob',
    oobCode: challenge.oobCode,  // from challengeAuthenticator
    bindingCode: '123456',       // code received via SMS / email
  },
  storeOptions
);
```

### Verify with Recovery Code

```ts
const result = await serverClient.mfa.verify(
  {
    mfaToken,
    factorType: 'recovery-code',
    recoveryCode: 'XXXX-XXXX-XXXX',
  },
  storeOptions
);

if (result.recoveryCode) {
  // A new recovery code is issued after the old one is used
  console.log('New recovery code:', result.recoveryCode);
}
```

## Session Persistence

`verify()` always persists the new tokens to the session store after a successful verification — the session is updated automatically following the same pattern as `completeInteractiveLogin`. After calling `verify`, `getSession()` and `getUser()` will reflect the authenticated state:

```ts
await serverClient.mfa.verify({ mfaToken, factorType: 'otp', otp: '123456' }, storeOptions);

const session = await serverClient.getSession(storeOptions);
console.log(session?.user?.sub); // authenticated user
```

To target a specific audience when storing the token set, pass `audience` in the verify options:

```ts
await serverClient.mfa.verify(
  {
    mfaToken,
    factorType: 'otp',
    otp: '123456',
    audience: 'https://api.example.com',
  },
  storeOptions
);
```

## Complete Flow Examples

### Enrollment Flow

When the user has no authenticators and needs to enroll:

```ts
import { MfaRequiredError, MfaVerifyError } from '@auth0/auth0-server-js';

async function handleMfaEnrollment(mfaToken: string, storeOptions?: StoreOptions) {
  // 1. Enroll OTP authenticator
  const enrollment = await serverClient.mfa.enrollAuthenticator({
    mfaToken,
    authenticatorTypes: ['otp'],
  });

  // 2. Display QR code to the user (e.g. render enrollment.barcodeUri as a QR image)
  displayQrCode(enrollment.barcodeUri);

  // 3. Collect OTP code from user
  const otp = await promptUserForCode();

  // 4. Verify and persist session
  const result = await serverClient.mfa.verify(
    { mfaToken, factorType: 'otp', otp },
    storeOptions
  );

  if (result.recoveryCode) {
    displayRecoveryCode(result.recoveryCode); // show once, store securely
  }

  return result;
}
```

### Challenge Flow

When the user already has enrolled authenticators:

```ts
async function handleMfaChallenge(mfaToken: string, storeOptions?: StoreOptions) {
  // 1. List enrolled authenticators
  const authenticators = await serverClient.mfa.listAuthenticators({ mfaToken });

  // 2. Select one (or let the user choose)
  const selected = authenticators[0];

  if (selected.authenticatorType === 'otp') {
    // OTP: no challenge needed — prompt directly
    const otp = await promptUserForCode('Enter code from your authenticator app');
    return serverClient.mfa.verify({ mfaToken, factorType: 'otp', otp }, storeOptions);
  }

  // OOB: issue a challenge first
  const challengeType = selected.authenticatorType === 'oob' ? 'oob' : 'otp';
  const challenge = await serverClient.mfa.challengeAuthenticator({
    mfaToken,
    challengeType,
    authenticatorId: selected.id,
  });

  const bindingCode = await promptUserForCode('Enter the code you received');

  return serverClient.mfa.verify(
    {
      mfaToken,
      factorType: 'oob',
      oobCode: challenge.oobCode!,
      bindingCode,
    },
    storeOptions
  );
}
```

### Tying it all together

```ts
import { MfaRequiredError } from '@auth0/auth0-server-js';

async function getAccessTokenWithMfa(storeOptions?: StoreOptions) {
  try {
    return await serverClient.getAccessToken(storeOptions);
  } catch (err) {
    if (!(err instanceof MfaRequiredError)) throw err;

    const { mfaToken } = err;
    const authenticators = await serverClient.mfa.listAuthenticators({ mfaToken });

    const result =
      authenticators.length === 0
        ? await handleMfaEnrollment(mfaToken, storeOptions)
        : await handleMfaChallenge(mfaToken, storeOptions);

    return result.accessToken;
  }
}
```

## Error Handling

| Error | Thrown by | `code` |
|---|---|---|
| `MfaRequiredError` | `getAccessToken()` | `mfa_required` |
| `MfaListAuthenticatorsError` | `mfa.listAuthenticators()` | `mfa_list_authenticators_error` |
| `MfaEnrollmentError` | `mfa.enrollAuthenticator()` | `mfa_enrollment_error` |
| `MfaChallengeError` | `mfa.challengeAuthenticator()` | `mfa_challenge_error` |
| `MfaDeleteAuthenticatorError` | `mfa.deleteAuthenticator()` | `mfa_delete_authenticator_error` |
| `MfaVerifyError` | `mfa.verify()` | `mfa_verify_error` |

All errors except `MfaRequiredError` expose a `cause` object with `error` and `error_description` from the Auth0 API response:

```ts
import {
  MfaRequiredError,
  MfaVerifyError,
  MfaChallengeError,
} from '@auth0/auth0-server-js';

try {
  const tokenSet = await serverClient.getAccessToken(storeOptions);
} catch (err) {
  if (err instanceof MfaRequiredError) {
    // err.mfaToken — proceed with MFA flow
  } else {
    throw err;
  }
}

try {
  await serverClient.mfa.verify({ mfaToken, factorType: 'otp', otp }, storeOptions);
} catch (err) {
  if (err instanceof MfaVerifyError) {
    console.error(err.cause?.error);             // e.g. 'invalid_grant'
    console.error(err.cause?.error_description); // e.g. 'Invalid otp_code.'
  }
}
```
