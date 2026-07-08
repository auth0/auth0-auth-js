# Database Connections POC Example

This is a manual harness for live-tenant testing of `signUp` and `changePassword` database connection operations with Auth0.

## Prerequisites

- An Auth0 tenant with a database connection enabled on the app
- Signup enabled on the connection (or expect documented signup-disabled behavior)
- The client configured as either a confidential app (with client secret) or public app as configured
- Node.js and npm installed

## Setup

1. Copy `.env.example` to `.env` and fill in your Auth0 tenant credentials:
   ```bash
   cp .env.example .env
   ```

2. Install workspace dependencies at the repo root:
   ```bash
   npm install
   ```

3. Build the auth0-auth-js and auth0-server-js packages first to ensure the example resolves the new database connection surface from dist:
   ```bash
   npm run build --workspace=packages/auth0-auth-js
   npm run build --workspace=packages/auth0-server-js
   ```

4. Install the example dependencies:
   ```bash
   npm install --workspace=examples/database-conns
   ```

## Running

```bash
npm start --workspace=examples/database-conns
```

The app will start on the port specified in your `.env` (default: `http://localhost:3000`).

## Testing

### Sign Up

Test user registration:

```bash
curl -X POST localhost:3000/signup \
  -H 'content-type: application/json' \
  -d '{"email":"new@example.com","password":"Str0ng-pw!"}'
```

Expected success response:
```json
{
  "ok": true,
  "user": {
    "id": "...",
    "email": "new@example.com",
    "emailVerified": false
  }
}
```

Expected error when re-running with the same email:
```json
{
  "ok": false,
  "code": "signup_error",
  "message": "...",
  "cause": { "error": "..." }
}
```

### Change Password

Test password reset request:

```bash
curl -X POST localhost:3000/change-password \
  -H 'content-type: application/json' \
  -d '{"email":"new@example.com"}'
```

Expected success response:
```json
{
  "ok": true,
  "message": "We've just sent you an email to reset your password."
}
```

A password reset email will be sent to the specified email address from your Auth0 tenant.

## Investigation Notes

This POC is the live-tenant check that closes the signup success-rate investigation. When running the tests above, capture observed status codes and response codes for:

- Existing user signup attempt (expect 4xx validation error)
- Weak password signup attempt (expect 4xx validation error)
- Signup with disabled connection (expect 4xx validation error)

These should all be expected validation 4xx responses, not a defect. Any 5xx or unexpected behavior indicates a platform issue.

## Implementation Details

The example:
- Uses a simple no-op state store for the `ServerClient` (database operations never read or write session state)
- Catches `SignUpError` and `ChangePasswordError` and surfaces them with appropriate HTTP status codes
- Reads plain text responses from the change-password endpoint

See the source files for implementation details.
