# Migration Guide: @auth0/auth0-spa-js → @auth0/auth0-browser-js

This guide helps you migrate from `@auth0/auth0-spa-js` to `@auth0/auth0-browser-js`.

## Why Migrate?

`@auth0/auth0-browser-js` offers several advantages:

- **Enhanced Security**: All tokens are encrypted at rest in storage
- **Better Storage Options**: Choose between localStorage, sessionStorage, or in-memory storage
- **Direct Instantiation**: No factory function - use `new BrowserClient()` directly
- **MFA API**: Built-in MFA management without additional SDK
- **DPoP Support**: Demonstrating Proof-of-Possession for enhanced token security
- **Authenticated Fetcher**: Automatic token injection for API calls
- **Custom Token Exchange**: Built-in support for RFC 8693 token exchange
- **Multi-Resource Refresh Tokens (MRRT)**: Request tokens for multiple audiences with a single refresh token

## Quick Comparison

| Feature | @auth0/auth0-spa-js | @auth0/auth0-browser-js |
|---------|---------------------|------------------------|
| Initialization | Factory function (`createAuth0Client`) | Direct instantiation (`new BrowserClient()`) |
| Default Storage | In-memory (unencrypted) | localStorage (encrypted) |
| Storage Options | In-memory only | localStorage, sessionStorage, memory |
| Token Encryption | ❌ No | ✅ Yes (for localStorage/sessionStorage) |
| Initial Session Check | Automatic (in factory) | Manual (`checkSession()`) |
| MFA API | ❌ Not included | ✅ Built-in |
| DPoP Support | ❌ Not included | ✅ Available |
| Authenticated Fetcher | ❌ Not included | ✅ Built-in |
| Custom Token Exchange | ❌ Not included | ✅ Built-in |

## Migration Steps

### Step 1: Install the Package

```bash
npm uninstall @auth0/auth0-spa-js
npm install @auth0/auth0-browser-js
```

### Step 2: Update Imports

**Before (spa-js):**
```typescript
import { createAuth0Client } from '@auth0/auth0-spa-js';
```

**After (browser-js):**
```typescript
import { BrowserClient } from '@auth0/auth0-browser-js';
```

### Step 3: Update Initialization

**Before (spa-js):**
```typescript
const auth0 = await createAuth0Client({
  domain: 'tenant.auth0.com',
  clientId: 'YOUR_CLIENT_ID',
  authorizationParams: {
    redirect_uri: window.location.origin,
  },
});
```

**After (browser-js):**
```typescript
const auth0 = new BrowserClient({
  domain: 'tenant.auth0.com',
  clientId: 'YOUR_CLIENT_ID',
  secret: 'your-encryption-secret', // Required for encrypted storage
  authorizationParams: {
    redirect_uri: window.location.origin,
  },
});

// If you want initial session check (like spa-js factory does):
await auth0.checkSession();
```

**Note**: The `secret` is used to encrypt tokens in localStorage. Generate a strong random string for this.

### Step 4: Update Method Calls (No Changes Needed!)

All spa-js methods work identically in browser-js:

```typescript
// These work exactly the same:
await auth0.loginWithRedirect();
await auth0.handleRedirectCallback();
const token = await auth0.getTokenSilently();
const user = await auth0.getUser();
const isAuth = await auth0.isAuthenticated();
await auth0.logout();
```

## Key Differences

### 1. Initialization Pattern

**spa-js** uses an async factory function that automatically checks the session:

```typescript
// spa-js
const auth0 = await createAuth0Client(config);
// Session is already checked at this point
```

**browser-js** uses direct instantiation. Call `checkSession()` if you need initial session check:

```typescript
// browser-js
const auth0 = new BrowserClient(config);

// Optionally check session (equivalent to spa-js factory behavior)
await auth0.checkSession();
```

### 2. Encryption Secret

**spa-js** stores tokens in memory (no encryption needed):

```typescript
// spa-js - no secret required
const auth0 = await createAuth0Client({
  domain: 'tenant.auth0.com',
  clientId: 'YOUR_CLIENT_ID',
});
```

**browser-js** encrypts tokens by default (requires secret):

```typescript
// browser-js - secret required for localStorage/sessionStorage
const auth0 = new BrowserClient({
  domain: 'tenant.auth0.com',
  clientId: 'YOUR_CLIENT_ID',
  secret: 'your-encryption-secret', // Required!
});

// OR use memory storage (no secret required)
const auth0 = new BrowserClient({
  domain: 'tenant.auth0.com',
  clientId: 'YOUR_CLIENT_ID',
  cacheLocation: 'memory', // No encryption, no secret needed
});
```

### 3. Storage Persistence

**spa-js** loses session on page reload (in-memory only):

```typescript
// spa-js
const auth0 = await createAuth0Client(config);
// Refresh page → user logged out
```

**browser-js** persists session across page reloads by default:

```typescript
// browser-js
const auth0 = new BrowserClient({
  ...config,
  secret: 'your-secret',
  cacheLocation: 'localstorage', // Default - persists across reloads
});

// Or use sessionStorage (cleared when tab closes)
const auth0 = new BrowserClient({
  ...config,
  secret: 'your-secret',
  cacheLocation: 'sessionstorage',
});

// Or use memory (spa-js behavior)
const auth0 = new BrowserClient({
  ...config,
  cacheLocation: 'memory', // No persistence, no secret needed
});
```

## Complete Migration Example

### Before (spa-js)

```typescript
import { createAuth0Client } from '@auth0/auth0-spa-js';

// Initialize
const auth0 = await createAuth0Client({
  domain: 'tenant.auth0.com',
  clientId: 'YOUR_CLIENT_ID',
  authorizationParams: {
    redirect_uri: window.location.origin,
    audience: 'https://api.example.com',
    scope: 'openid profile email',
  },
});

// Login
await auth0.loginWithRedirect();

// Handle callback
await auth0.handleRedirectCallback();

// Get token
const token = await auth0.getTokenSilently();

// Get user
const user = await auth0.getUser();

// Check auth
const isAuthenticated = await auth0.isAuthenticated();

// Logout
await auth0.logout({
  logoutParams: {
    returnTo: window.location.origin,
  },
});
```

### After (browser-js)

```typescript
import { BrowserClient } from '@auth0/auth0-browser-js';

// Initialize (synchronous!)
const auth0 = new BrowserClient({
  domain: 'tenant.auth0.com',
  clientId: 'YOUR_CLIENT_ID',
  secret: 'your-encryption-secret', // NEW: Required for encrypted storage
  authorizationParams: {
    redirect_uri: window.location.origin,
    audience: 'https://api.example.com',
    scope: 'openid profile email',
  },
});

// NEW: Optional initial session check (replicates spa-js factory behavior)
await auth0.checkSession();

// Login (identical to spa-js)
await auth0.loginWithRedirect();

// Handle callback (identical to spa-js)
await auth0.handleRedirectCallback();

// Get token (identical to spa-js)
const token = await auth0.getTokenSilently();

// Get user (identical to spa-js)
const user = await auth0.getUser();

// Check auth (identical to spa-js)
const isAuthenticated = await auth0.isAuthenticated();

// Logout (identical to spa-js)
await auth0.logout({
  logoutParams: {
    returnTo: window.location.origin,
  },
});
```

## Storage Options Comparison

### spa-js (In-Memory Only)

```typescript
const auth0 = await createAuth0Client(config);
// Always in-memory, cleared on page refresh
```

### browser-js (Multiple Options)

```typescript
// Option 1: localStorage (default, encrypted, persists across sessions)
const auth0 = new BrowserClient({
  ...config,
  secret: 'your-secret',
  cacheLocation: 'localstorage', // Can be omitted (default)
});

// Option 2: sessionStorage (encrypted, cleared when tab closes)
const auth0 = new BrowserClient({
  ...config,
  secret: 'your-secret',
  cacheLocation: 'sessionstorage',
});

// Option 3: memory (spa-js behavior, no encryption, cleared on refresh)
const auth0 = new BrowserClient({
  ...config,
  cacheLocation: 'memory', // No secret needed
});
```

## Handling Initialization in React

### Before (spa-js)

```typescript
import { createAuth0Client } from '@auth0/auth0-spa-js';
import { useState, useEffect } from 'react';

function App() {
  const [auth0, setAuth0] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const initAuth = async () => {
      const client = await createAuth0Client({
        domain: 'tenant.auth0.com',
        clientId: 'YOUR_CLIENT_ID',
      });
      setAuth0(client);
      setLoading(false);
    };
    initAuth();
  }, []);

  if (loading) return <div>Loading...</div>;

  return <div>{/* Your app */}</div>;
}
```

### After (browser-js)

```typescript
import { BrowserClient } from '@auth0/auth0-browser-js';
import { useState, useEffect } from 'react';

// Create client outside component (synchronous!)
const auth0 = new BrowserClient({
  domain: 'tenant.auth0.com',
  clientId: 'YOUR_CLIENT_ID',
  secret: 'your-encryption-secret',
});

function App() {
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const checkSession = async () => {
      // Optional: Check if user has existing session
      await auth0.checkSession();
      setLoading(false);
    };
    checkSession();
  }, []);

  if (loading) return <div>Loading...</div>;

  return <div>{/* Your app */}</div>;
}
```

## New Features Available in browser-js

### 1. MFA Management

```typescript
// List enrolled authenticators
const authenticators = await auth0.mfa.listAuthenticators({ mfaToken });

// Enroll new authenticator
const enrollment = await auth0.mfa.enrollAuthenticator({
  authenticatorTypes: ['otp'],
  mfaToken,
});

// Challenge authenticator
const challenge = await auth0.mfa.challengeAuthenticator({
  challengeType: 'otp',
  mfaToken,
});

// Delete authenticator
await auth0.mfa.deleteAuthenticator({
  authenticatorId: 'totp|dev_abc123',
  mfaToken,
});
```

### 2. Authenticated Fetcher

```typescript
// Create fetcher with automatic token injection
const fetcher = auth0.createFetcher({
  baseUrl: 'https://api.example.com',
});

// Make authenticated requests
const posts = await fetcher.fetchWithAuth('/posts');
const newPost = await fetcher.fetchWithAuth('/posts', {
  method: 'POST',
  body: JSON.stringify({ title: 'My Post' }),
});
```

### 3. DPoP Support

```typescript
// Enable DPoP for enhanced security
const auth0 = new BrowserClient({
  domain: 'tenant.auth0.com',
  clientId: 'YOUR_CLIENT_ID',
  secret: 'your-encryption-secret',
  useDpop: true, // Enable DPoP
});

// DPoP is handled automatically by the fetcher
const fetcher = auth0.createFetcher({
  baseUrl: 'https://api.example.com',
});

const data = await fetcher.fetchWithAuth('/protected');
```

### 4. Custom Token Exchange

```typescript
// Exchange external tokens for Auth0 tokens
const tokenResponse = await auth0.loginWithCustomTokenExchange({
  subjectTokenType: 'urn:acme:legacy-token',
  subjectToken: legacyToken,
  audience: 'https://api.example.com',
  scope: 'openid offline_access',
});
```

### 5. Cache Management

```typescript
// Get cache keys
const keys = auth0.getCacheKeys();

// Clear all cached data
await auth0.clearCache();

// Clear but keep refresh token
await auth0.clearCache({ keepRefreshToken: true });
```

## Troubleshooting

### Error: "Either provide a secret or set cacheLocation to 'memory'"

**Cause**: You're using localStorage or sessionStorage without providing an encryption secret.

**Solution**: Add a `secret` to your config:

```typescript
const auth0 = new BrowserClient({
  domain: 'tenant.auth0.com',
  clientId: 'YOUR_CLIENT_ID',
  secret: 'your-encryption-secret', // Add this
  authorizationParams: {
    redirect_uri: window.location.origin,
  },
});
```

Or use memory storage (no secret required):

```typescript
const auth0 = new BrowserClient({
  domain: 'tenant.auth0.com',
  clientId: 'YOUR_CLIENT_ID',
  cacheLocation: 'memory', // No secret needed
  authorizationParams: {
    redirect_uri: window.location.origin,
  },
});
```

### User Session Not Persisting After Page Refresh

**Cause**: Using memory storage (spa-js default behavior).

**Solution**: Use localStorage or sessionStorage:

```typescript
const auth0 = new BrowserClient({
  domain: 'tenant.auth0.com',
  clientId: 'YOUR_CLIENT_ID',
  secret: 'your-encryption-secret',
  cacheLocation: 'localstorage', // Persists across reloads
});
```

### TypeScript Errors with Method Signatures

**Cause**: Some method signatures differ slightly between spa-js and browser-js.

**Solution**: All spa-js compatible methods are supported. If you see TypeScript errors, check:

1. You're importing from the correct package (`@auth0/auth0-browser-js`)
2. Your `secret` is provided (required for localStorage/sessionStorage)
3. You're using `new BrowserClient()` instead of `createAuth0Client()`

## Migration Checklist

- [ ] Install `@auth0/auth0-browser-js` and uninstall `@auth0/auth0-spa-js`
- [ ] Update imports: `import { BrowserClient } from '@auth0/auth0-browser-js'`
- [ ] Change from factory function to direct instantiation: `new BrowserClient(config)`
- [ ] Add `secret` to config (or use `cacheLocation: 'memory'`)
- [ ] Optionally call `await auth0.checkSession()` for initial session check
- [ ] Test login flow (should work identically)
- [ ] Test callback handling (should work identically)
- [ ] Test token acquisition (should work identically)
- [ ] Test logout (should work identically)
- [ ] Verify session persistence works as expected
- [ ] Consider using new features (MFA, fetcher, DPoP, etc.)

## Getting Help

- **Documentation**: See [EXAMPLES.md](./EXAMPLES.md) for comprehensive examples
- **Issues**: Report issues at [github.com/auth0/auth0-auth-js/issues](https://github.com/auth0/auth0-auth-js/issues)

## Summary

Migrating from `@auth0/auth0-spa-js` to `@auth0/auth0-browser-js` is straightforward:

1. Change from `createAuth0Client()` to `new BrowserClient()`
2. Add `secret` for encrypted storage (or use `cacheLocation: 'memory'`)
3. Optionally call `checkSession()` for initial session validation
4. All spa-js methods work identically!

You gain enhanced security, better storage options, and powerful new features while maintaining full compatibility with your existing spa-js code.
