# Examples

This document contains examples of how to use the `@auth0/auth0-browser-js` SDK, including spa-js compatible methods.

## Table of Contents

- [Basic Setup](#basic-setup)
- [Login Flow (Native Methods)](#login-flow-native-methods)
- [Login Flow (spa-js Compatible)](#login-flow-spa-js-compatible)
- [Popup Authentication](#popup-authentication)
- [Accessing User Information](#accessing-user-information)
- [Token Management](#token-management)
- [Authenticated Fetcher](#authenticated-fetcher)
- [Multi-Factor Authentication (MFA)](#multi-factor-authentication-mfa)
- [DPoP (Demonstrating Proof-of-Possession)](#dpop-demonstrating-proof-of-possession)
- [Custom Token Exchange](#custom-token-exchange)
- [Storage Options](#storage-options)
- [Cache Management](#cache-management)
- [Logout](#logout)
- [Error Handling](#error-handling)
- [Complete SPA Example](#complete-spa-example)

## Basic Setup

```typescript
import { BrowserClient } from '@auth0/auth0-browser-js';

const auth0 = new BrowserClient({
  domain: 'your-tenant.auth0.com',
  clientId: 'your-client-id',
  secret: 'your-encryption-secret', // Used to encrypt data in localStorage
  authorizationParams: {
    redirect_uri: window.location.origin + '/callback',
    scope: 'openid profile email',
  },
});
```

### Storage Options

```typescript
// Use sessionStorage (cleared when tab closes)
const auth0 = new BrowserClient({
  domain: 'your-tenant.auth0.com',
  clientId: 'your-client-id',
  secret: 'your-encryption-secret',
  cacheLocation: 'sessionstorage',
  authorizationParams: {
    redirect_uri: window.location.origin + '/callback',
  },
});

// Use in-memory storage (no secret required, cleared on page reload)
const auth0 = new BrowserClient({
  domain: 'your-tenant.auth0.com',
  clientId: 'your-client-id',
  cacheLocation: 'memory',
  authorizationParams: {
    redirect_uri: window.location.origin + '/callback',
  },
});
```

## Login Flow (Native Methods)

### Starting the Login Process

```typescript
async function login() {
  const authorizationUrl = await auth0.startInteractiveLogin();
  window.location.href = authorizationUrl.href;
}

// With custom parameters
async function loginWithOptions() {
  const authorizationUrl = await auth0.startInteractiveLogin({
    authorizationParams: {
      audience: 'https://api.example.com',
      scope: 'openid profile email read:posts',
    },
  });
  window.location.href = authorizationUrl.href;
}

// With app state (preserved across the login flow)
async function loginWithState() {
  const authorizationUrl = await auth0.startInteractiveLogin({
    appState: {
      returnTo: '/dashboard',
      tab: 'settings',
    },
  });
  window.location.href = authorizationUrl.href;
}
```

### Handling the Callback

```typescript
async function handleCallback() {
  const url = new URL(window.location.href);
  const { appState } = await auth0.completeInteractiveLogin(url);

  // Redirect based on appState
  if (appState?.returnTo) {
    window.location.href = appState.returnTo;
  } else {
    window.location.href = '/';
  }
}
```

## Login Flow (spa-js Compatible)

These methods provide compatibility with `@auth0/auth0-spa-js`:

```typescript
// Automatically redirects to Auth0
await auth0.loginWithRedirect({
  authorizationParams: {
    audience: 'https://api.example.com',
    scope: 'openid profile email',
  },
  appState: {
    returnTo: '/dashboard',
  },
});

// Handle the callback
const { appState } = await auth0.handleRedirectCallback();
if (appState?.returnTo) {
  window.location.href = appState.returnTo;
}
```

## Popup Authentication

Open a popup window for authentication instead of redirecting:

```typescript
// Login with popup
async function loginWithPopup() {
  try {
    await auth0.loginWithPopup({
      authorizationParams: {
        audience: 'https://api.example.com',
        scope: 'openid profile email',
      },
    });

    const user = await auth0.getUser();
    console.log('Logged in:', user);
  } catch (error) {
    if (error.name === 'PopupTimeoutError') {
      console.error('Popup timed out');
    } else if (error.name === 'PopupCancelledError') {
      console.error('User closed the popup');
    } else {
      console.error('Popup login failed:', error);
    }
  }
}

// Get additional scopes via popup
async function getTokenWithPopup() {
  const accessToken = await auth0.getTokenWithPopup({
    authorizationParams: {
      audience: 'https://api.example.com',
      scope: 'read:admin',
    },
  });

  console.log('Got token with new scope:', accessToken);
}

// Configure popup behavior
await auth0.loginWithPopup(
  {
    authorizationParams: {
      audience: 'https://api.example.com',
    },
  },
  {
    timeoutInSeconds: 120, // Custom timeout
    closePopup: true, // Close popup after success
  }
);
```

## Accessing User Information

### Get the Current User

```typescript
async function getCurrentUser() {
  const user = await auth0.getUser();

  if (user) {
    console.log('User ID:', user.sub);
    console.log('Email:', user.email);
    console.log('Name:', user.name);
  } else {
    console.log('No user logged in');
  }
}
```

### Check Authentication Status (spa-js compatible)

```typescript
const isAuthenticated = await auth0.isAuthenticated();
if (isAuthenticated) {
  console.log('User is logged in');
}
```

### Get ID Token Claims (spa-js compatible)

```typescript
const claims = await auth0.getIdTokenClaims();
if (claims) {
  console.log('ID Token:', claims.__raw);
  console.log('Issuer:', claims.iss);
  console.log('Subject:', claims.sub);
  console.log('Email:', claims.email);
}
```

### Get the Full Session

```typescript
async function getSession() {
  const session = await auth0.getSession();

  if (session) {
    console.log('User:', session.user);
    console.log('ID Token:', session.idToken);
    console.log('Refresh Token:', session.refreshToken);
    console.log('Token Sets:', session.tokenSets);
  }
}
```

### Check Session Validity (spa-js compatible)

```typescript
// Silently check if session is still valid
await auth0.checkSession();
```

## Token Management

### Get Access Token (Native)

```typescript
// Get access token for the default audience
async function getAccessToken() {
  const tokenSet = await auth0.getAccessToken();

  console.log('Access Token:', tokenSet.accessToken);
  console.log('Expires At:', new Date(tokenSet.expiresAt * 1000));
  console.log('Scope:', tokenSet.scope);
}

// Get access token for a specific audience
async function getAccessTokenForAudience() {
  const tokenSet = await auth0.getAccessToken({
    audience: 'https://api.example.com',
  });

  return tokenSet.accessToken;
}

// Get access token with specific scopes (MRRT)
async function getAccessTokenWithScopes() {
  const tokenSet = await auth0.getAccessToken({
    audience: 'https://api.example.com',
    scope: 'read:posts write:posts',
  });

  return tokenSet.accessToken;
}
```

### Get Access Token (spa-js Compatible)

```typescript
// Get just the token string
const accessToken = await auth0.getTokenSilently({
  authorizationParams: {
    audience: 'https://api.example.com',
    scope: 'read:posts',
  },
});

// Get detailed token response
const tokenDetails = await auth0.getTokenSilently({
  authorizationParams: {
    audience: 'https://api.example.com',
  },
  detailedResponse: true,
});

console.log('Access Token:', tokenDetails.access_token);
console.log('ID Token:', tokenDetails.id_token);
console.log('Expires In:', tokenDetails.expires_in);
console.log('Scope:', tokenDetails.scope);
```

### Making API Calls

```typescript
async function callAPI() {
  const tokenSet = await auth0.getAccessToken({
    audience: 'https://api.example.com',
  });

  const response = await fetch('https://api.example.com/posts', {
    headers: {
      Authorization: `Bearer ${tokenSet.accessToken}`,
    },
  });

  return response.json();
}
```

## Authenticated Fetcher

Use the built-in fetcher to automatically inject tokens:

```typescript
// Create a fetcher with base URL
const fetcher = auth0.createFetcher({
  baseUrl: 'https://api.example.com',
});

// Make authenticated requests
const posts = await fetcher.fetchWithAuth('/posts', {
  method: 'GET',
});

// Create a post
const newPost = await fetcher.fetchWithAuth('/posts', {
  method: 'POST',
  body: JSON.stringify({ title: 'My Post' }),
  headers: {
    'Content-Type': 'application/json',
  },
}, {
  audience: 'https://api.example.com',
  scope: 'write:posts',
});

// Custom token getter
const customFetcher = auth0.createFetcher({
  getAccessToken: async () => {
    const token = await auth0.getTokenSilently({ detailedResponse: true });
    return token;
  },
});
```

## Multi-Factor Authentication (MFA)

Manage MFA authenticators for the current user:

```typescript
// List enrolled authenticators
const authenticators = await auth0.mfa.listAuthenticators({
  mfaToken: mfaToken, // Obtained from MFA challenge
});

console.log('Enrolled authenticators:', authenticators);

// Enroll OTP authenticator (Google Authenticator, etc.)
const otpEnrollment = await auth0.mfa.enrollAuthenticator({
  authenticatorTypes: ['otp'],
  mfaToken: mfaToken,
});

console.log('Secret:', otpEnrollment.secret);
console.log('QR Code URI:', otpEnrollment.barcodeUri);

// Enroll SMS authenticator
const smsEnrollment = await auth0.mfa.enrollAuthenticator({
  authenticatorTypes: ['oob'],
  oobChannels: ['sms'],
  phoneNumber: '+1234567890',
  mfaToken: mfaToken,
});

// Challenge an authenticator
const challenge = await auth0.mfa.challengeAuthenticator({
  challengeType: 'otp',
  mfaToken: mfaToken,
});

console.log('Challenge:', challenge);

// Delete an authenticator
await auth0.mfa.deleteAuthenticator({
  authenticatorId: 'totp|dev_abc123',
  mfaToken: mfaToken,
});
```

## DPoP (Demonstrating Proof-of-Possession)

Enable DPoP for enhanced security:

```typescript
// Enable DPoP when creating the client
const auth0 = new BrowserClient({
  domain: 'your-tenant.auth0.com',
  clientId: 'your-client-id',
  secret: 'your-encryption-secret',
  useDpop: true,
  authorizationParams: {
    redirect_uri: window.location.origin + '/callback',
  },
});

// Generate a DPoP proof
const proof = await auth0.generateDpopProof({
  url: 'https://api.example.com/posts',
  method: 'GET',
  accessToken: accessToken,
  nonce: nonce, // Optional server nonce
});

// Make request with DPoP
const response = await fetch('https://api.example.com/posts', {
  headers: {
    Authorization: `DPoP ${accessToken}`,
    DPoP: proof,
  },
});

// Handle DPoP nonce
const dpopNonce = response.headers.get('DPoP-Nonce');
if (dpopNonce) {
  auth0.setDpopNonce(dpopNonce);
}

// Use the fetcher (handles DPoP automatically)
const fetcher = auth0.createFetcher({
  baseUrl: 'https://api.example.com',
});

const posts = await fetcher.fetchWithAuth('/posts');
```

## Custom Token Exchange

Exchange external tokens for Auth0 tokens (RFC 8693):

```typescript
// Exchange a legacy token for Auth0 tokens
const tokenResponse = await auth0.loginWithCustomTokenExchange({
  subjectTokenType: 'urn:acme:legacy-token',
  subjectToken: legacySystemToken,
  audience: 'https://api.example.com',
  scope: 'openid offline_access',
  extra: {
    device_id: 'device-12345',
    session_id: 'sess-abc',
  },
});

console.log('Access Token:', tokenResponse.accessToken);
console.log('ID Token:', tokenResponse.idToken);
console.log('Refresh Token:', tokenResponse.refreshToken);

// Tokens are automatically stored in the session
const user = await auth0.getUser();
console.log('User:', user);
```

## Storage Options

### Using Session Storage

```typescript
const auth0 = new BrowserClient({
  domain: 'your-tenant.auth0.com',
  clientId: 'your-client-id',
  secret: 'your-encryption-secret',
  cacheLocation: 'sessionstorage', // Cleared when tab closes
  authorizationParams: {
    redirect_uri: window.location.origin + '/callback',
  },
});
```

### Using Memory Storage

```typescript
const auth0 = new BrowserClient({
  domain: 'your-tenant.auth0.com',
  clientId: 'your-client-id',
  cacheLocation: 'memory', // No secret required, cleared on reload
  authorizationParams: {
    redirect_uri: window.location.origin + '/callback',
  },
});
```

### Custom Storage Implementation

```typescript
import {
  BrowserClient,
  AbstractStateStore,
  AbstractTransactionStore,
  StateData,
  TransactionData,
  LogoutTokenClaims,
} from '@auth0/auth0-browser-js';

class CustomStateStore extends AbstractStateStore {
  constructor() {
    super({ secret: 'your-encryption-secret' });
  }

  async set(identifier: string, state: StateData): Promise<void> {
    const encrypted = await this.encrypt(identifier, state, Date.now() / 1000 + 7 * 24 * 60 * 60);
    // Store encrypted data in your custom storage
  }

  async get(identifier: string): Promise<StateData | undefined> {
    // Retrieve encrypted data from your storage
    const encrypted = '...';
    if (encrypted) {
      return await this.decrypt(identifier, encrypted);
    }
    return undefined;
  }

  async delete(identifier: string): Promise<void> {
    // Delete from your storage
  }

  async deleteByLogoutToken(claims: LogoutTokenClaims): Promise<void> {
    // Handle logout token
  }
}

const auth0 = new BrowserClient({
  domain: 'your-tenant.auth0.com',
  clientId: 'your-client-id',
  stateStore: new CustomStateStore(),
  transactionStore: new CustomTransactionStore(),
  authorizationParams: {
    redirect_uri: window.location.origin + '/callback',
  },
});
```

## Cache Management

```typescript
// Get all cache keys
const keys = auth0.getCacheKeys();
console.log('Cache keys:', keys);

// Clear all cached data
await auth0.clearCache();

// Clear cache but keep refresh token
await auth0.clearCache({ keepRefreshToken: true });
```

## Logout

### Basic Logout

```typescript
async function logout() {
  await auth0.logout({
    returnTo: window.location.origin,
  });
}

// New format (spa-js compatible)
await auth0.logout({
  logoutParams: {
    returnTo: window.location.origin,
    federated: true, // Logout from identity provider too
  },
});

// Custom redirect function
await auth0.logout({
  logoutParams: {
    returnTo: window.location.origin,
  },
  openUrl: async (url) => {
    // Custom redirect logic
    window.location.href = url;
  },
});

// Don't redirect, just clear session
await auth0.logout({
  openUrl: false,
});
```

## Error Handling

```typescript
import {
  MissingTransactionError,
  MissingSessionError,
  MissingRequiredArgumentError,
  PopupTimeoutError,
  PopupCancelledError,
  PopupOpenError,
  TimeoutError,
} from '@auth0/auth0-browser-js';

async function handleLogin() {
  try {
    await auth0.loginWithRedirect();
  } catch (error) {
    if (error instanceof MissingRequiredArgumentError) {
      console.error('Missing required configuration:', error.message);
    } else {
      console.error('Login failed:', error);
    }
  }
}

async function handleCallback() {
  try {
    await auth0.handleRedirectCallback();
    window.location.href = '/';
  } catch (error) {
    if (error instanceof MissingTransactionError) {
      console.error('No transaction found. Please start the login process again.');
    } else {
      console.error('Callback handling failed:', error);
    }
  }
}

async function handlePopupLogin() {
  try {
    await auth0.loginWithPopup();
  } catch (error) {
    if (error instanceof PopupTimeoutError) {
      console.error('Popup timed out');
    } else if (error instanceof PopupCancelledError) {
      console.error('User closed the popup');
    } else if (error instanceof PopupOpenError) {
      console.error('Failed to open popup (may be blocked)');
    } else {
      console.error('Popup login failed:', error);
    }
  }
}
```

## Complete SPA Example

```typescript
import { BrowserClient } from '@auth0/auth0-browser-js';

class Auth {
  private auth0: BrowserClient;

  constructor() {
    this.auth0 = new BrowserClient({
      domain: 'your-tenant.auth0.com',
      clientId: 'your-client-id',
      secret: 'your-encryption-secret',
      authorizationParams: {
        redirect_uri: window.location.origin + '/callback',
        scope: 'openid profile email offline_access',
        audience: 'https://api.example.com',
      },
    });
  }

  async login() {
    await this.auth0.loginWithRedirect({
      appState: {
        returnTo: window.location.pathname,
      },
    });
  }

  async loginWithPopup() {
    await this.auth0.loginWithPopup();
  }

  async handleCallback() {
    const { appState } = await this.auth0.handleRedirectCallback();
    return appState?.returnTo || '/';
  }

  async logout() {
    await this.auth0.logout({
      logoutParams: {
        returnTo: window.location.origin,
      },
    });
  }

  async isAuthenticated(): Promise<boolean> {
    return await this.auth0.isAuthenticated();
  }

  async getUser() {
    return await this.auth0.getUser();
  }

  async getAccessToken() {
    return await this.auth0.getTokenSilently();
  }

  async callAPI(endpoint: string, options: RequestInit = {}) {
    const accessToken = await this.getAccessToken();

    const response = await fetch(endpoint, {
      ...options,
      headers: {
        ...options.headers,
        Authorization: `Bearer ${accessToken}`,
      },
    });

    return response.json();
  }

  // Use authenticated fetcher for cleaner code
  getFetcher() {
    return this.auth0.createFetcher({
      baseUrl: 'https://api.example.com',
    });
  }
}

// Usage
const auth = new Auth();

// Check if user is on callback page
if (window.location.pathname === '/callback') {
  auth.handleCallback().then((returnTo) => {
    window.location.href = returnTo;
  });
}

// Login button click
document.getElementById('login-btn')?.addEventListener('click', () => {
  auth.login();
});

// Popup login button
document.getElementById('popup-login-btn')?.addEventListener('click', async () => {
  await auth.loginWithPopup();
  // Refresh UI
  const user = await auth.getUser();
  console.log('Logged in:', user);
});

// Logout button click
document.getElementById('logout-btn')?.addEventListener('click', () => {
  auth.logout();
});

// Show user info
auth.getUser().then((user) => {
  if (user) {
    document.getElementById('user-name')!.textContent = user.name || user.email || 'User';
  }
});

// Make API call with fetcher
const fetcher = auth.getFetcher();
fetcher.fetchWithAuth('/posts').then((posts) => {
  console.log('Posts:', posts);
});
```
