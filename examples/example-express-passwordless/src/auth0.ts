import type { Request, Response, NextFunction } from 'express';
import express from 'express';
import {
  CookieTransactionStore,
  ServerClient,
  StatelessStateStore,
} from '@auth0/auth0-server-js';
import { StoreOptions } from './types.js';
import { ExpressCookieHandler } from './store/express-cookie-handler.js';

export interface Auth0ExpressOptions {
  domain: string;
  clientId: string;
  clientSecret: string;
  appBaseUrl: string;
  sessionSecret: string;
}

declare module 'express' {
  interface Request {
    auth0Client: ServerClient<StoreOptions>;
  }
}

/**
 * Best-effort extraction of an SDK error `code` for branching on error type.
 *
 * The passwordless errors live in `@auth0/auth0-auth-js` and are NOT re-exported
 * by `@auth0/auth0-server-js`. To keep this example's dependencies to the
 * server SDK only, we branch on the stable `code` string instead of `instanceof`:
 *   - `passwordless_start_error`  (PasswordlessStartError)
 *   - `passwordless_verify_error` (PasswordlessVerifyError)
 *   - `mfa_required_error`        (MfaRequiredError)
 */
function errorCode(error: unknown): string | undefined {
  if (error && typeof error === 'object' && 'code' in error) {
    const { code } = error as { code?: unknown };
    return typeof code === 'string' ? code : undefined;
  }
  return undefined;
}

function errorMessage(error: unknown): string {
  if (error instanceof Error && error.message) {
    return error.message;
  }
  return 'Something went wrong. Please try again.';
}

/** Log the full error (incl. nested cause from openid-client / oauth4webapi) to the server console. */
function logError(where: string, error: unknown): void {
  const code = errorCode(error);
  // eslint-disable-next-line no-console
  console.error(`[passwordless] ${where} failed`, {
    name: error instanceof Error ? error.name : typeof error,
    code,
    message: error instanceof Error ? error.message : String(error),
    cause: (error as { cause?: unknown })?.cause,
  });
}

export function auth0(options: Auth0ExpressOptions) {
  const auth0Client = new ServerClient<StoreOptions>({
    domain: options.domain,
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    // Passwordless OTP is a non-redirect flow, but ServerClient still requires a
    // transaction store (used by other, redirect-based flows). Kept for parity.
    transactionStore: new CookieTransactionStore(
      {
        secret: options.sessionSecret,
      },
      new ExpressCookieHandler()
    ),
    stateStore: new StatelessStateStore(
      {
        secret: options.sessionSecret,
      },
      new ExpressCookieHandler()
    ),
  });

  //@ts-expect-error TypeScript doesnt like this
  const router = new express.Router();

  // Parse url-encoded form bodies for the start/verify POSTs.
  router.use(express.urlencoded({ extended: true }));

  router.use(async (req: Request, _res: Response, next: NextFunction) => {
    req.auth0Client = auth0Client;
    next();
  });

  // Step 0: render the login form (choose channel + identifier).
  router.get('/auth/login', (_request: Request, response: Response) => {
    response.render('login', { error: null, values: {} });
  });

  // Step 1: send a one-time code via email or SMS. No session is created yet.
  router.post('/auth/start', async (request: Request, response: Response) => {
    const channel = request.body.channel === 'sms' ? 'sms' : 'email';
    const email = (request.body.email ?? '').trim();
    const phoneNumber = (request.body.phoneNumber ?? '').trim();

    try {
      if (channel === 'sms') {
        await request.auth0Client.startPasswordlessSms(
          { phoneNumber },
          { request, response }
        );
      } else {
        await request.auth0Client.startPasswordlessEmail(
          { email, send: 'code' },
          { request, response }
        );
      }

      // Carry channel + identifier into the verify step (hidden fields).
      response.render('verify', {
        error: null,
        channel,
        identifier: channel === 'sms' ? phoneNumber : email,
      });
    } catch (error) {
      // passwordless_start_error: bad email/phone, SMS provider, rate limit, etc.
      logError('start', error);
      response.status(400).render('login', {
        error: errorMessage(error),
        values: { channel, email, phoneNumber },
      });
    }
  });

  // Step 2: exchange the OTP for tokens and persist the session, then redirect home.
  router.post('/auth/verify', async (request: Request, response: Response) => {
    const channel = request.body.channel === 'sms' ? 'sms' : 'email';
    const identifier = (request.body.identifier ?? '').trim();
    const code = (request.body.code ?? '').trim();

    try {
      if (channel === 'sms') {
        await request.auth0Client.loginWithPasswordlessSms(
          { phoneNumber: identifier, code },
          { request, response }
        );
      } else {
        await request.auth0Client.loginWithPasswordlessEmail(
          { email: identifier, code },
          { request, response }
        );
      }

      response.redirect(options.appBaseUrl);
    } catch (error) {
      logError('verify', error);
      const code = errorCode(error);

      // MFA is out of scope for this example; surface a clear message.
      if (code === 'mfa_required_error') {
        response.status(403).render('verify', {
          error:
            'This connection requires multi-factor authentication, which this example does not handle.',
          channel,
          identifier,
        });
        return;
      }

      // passwordless_verify_error: wrong/expired code, too many attempts, etc.
      response.status(400).render('verify', {
        error: errorMessage(error),
        channel,
        identifier,
      });
    }
  });

  // Magic link, step 1: email a link. The SDK owns the anti-forgery `state` and persists a
  // transaction; no session is created yet. The link lands the browser on /auth/callback.
  router.post('/auth/start-link', async (request: Request, response: Response) => {
    const email = (request.body.email ?? '').trim();

    try {
      await request.auth0Client.startPasswordlessMagicLink(
        {
          email,
          redirectUri: `${options.appBaseUrl}/auth/callback`,
          scope: 'openid profile email',
        },
        { request, response }
      );

      response.render('check-email', { email });
    } catch (error) {
      logError('start-link', error);
      response.status(400).render('login', {
        error: errorMessage(error),
        values: { channel: 'email', email, phoneNumber: '' },
      });
    }
  });

  // Magic link, step 2: the link lands here with ?code&state. Validate state, exchange the
  // code (no PKCE), persist the session, and redirect home.
  router.get('/auth/callback', async (request: Request, response: Response) => {
    // If the user is already signed in (e.g. they re-click the link in the email),
    // the one-time transaction is already consumed. Don't surface a scary error —
    // just send them home.
    const existingSession = await request.auth0Client.getSession({ request, response });
    if (existingSession) {
      response.redirect(options.appBaseUrl);
      return;
    }

    try {
      const callbackUrl = new URL(request.originalUrl, options.appBaseUrl);
      await request.auth0Client.completePasswordlessMagicLink(callbackUrl, {
        request,
        response,
      });

      response.redirect(options.appBaseUrl);
    } catch (error) {
      // missing_transaction_error (link opened in a different browser, or already used),
      // passwordless_verify_error (state mismatch / tampered link), or
      // token_by_code_error (expired/used link). Give the user a clear retry path.
      logError('callback', error);
      const code = errorCode(error);
      const hint =
        code === 'missing_transaction_error'
          ? 'This magic link must be opened in the same browser that requested it, and can only be used once. Please request a new link.'
          : 'This magic link is invalid or has expired. Please request a new one.';
      response.status(400).render('login', {
        error: hint,
        values: {},
      });
    }
  });

  router.get('/auth/logout', async (request: Request, response: Response) => {
    const returnTo = options.appBaseUrl;
    const logoutUrl = await request.auth0Client.logout(
      { returnTo: returnTo.toString() },
      { request, response }
    );

    response.redirect(logoutUrl.href);
  });

  return router;
}
