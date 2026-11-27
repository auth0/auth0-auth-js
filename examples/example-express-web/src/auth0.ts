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

export function auth0(options: Auth0ExpressOptions) {
  const callbackPath = '/auth/callback';
  const redirectUri = new URL(callbackPath, options.appBaseUrl);

  const auth0Client = new ServerClient<StoreOptions>({
    domain: options.domain,
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    authorizationParams: {
      redirect_uri: redirectUri.toString(),
      scope: 'openid profile email offline_access',
    },
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

  router.use(async (req: Request, res: Response, next: NextFunction) => {
    req.auth0Client = auth0Client;
    next();
  });

  router.get('/auth/login', async (request: Request, response: Response) => {
    const authorizationUrl = await request.auth0Client.startInteractiveLogin(
      {
        appState: { returnTo: options.appBaseUrl },
      },
      { request, response }
    );

    response.redirect(authorizationUrl.href);
  });

  router.get('/auth/callback', async (request: Request, response: Response) => {
    const { appState } = await request.auth0Client.completeInteractiveLogin<
      { returnTo: string } | undefined
    >(new URL(request.url, options.appBaseUrl), { request, response });

    response.redirect(appState?.returnTo ?? options.appBaseUrl);
  });

  // With a hint, Auth0 ends the session without asking the user, and any site can make the browser call this GET
  // route. logout() sends no hint by default; this route only asks for one on a top-level navigation by the user (a
  // link click or a typed URL), not for an <img> or <iframe>, even from this site. Every other request gets the
  // confirmation page, where Auth0 shows one (RP-Initiated Logout enabled, not /v2/logout). A POST route with CSRF
  // protection doesn't need this. See `Skipping the logout confirmation prompt` in the auth0-server-js EXAMPLES.md.
  router.get('/auth/logout', async (request: Request, response: Response) => {
    const fetchSite = request.headers['sec-fetch-site'];
    const userNavigation =
      (fetchSite === 'same-origin' || fetchSite === 'none') &&
      request.headers['sec-fetch-mode'] === 'navigate' &&
      request.headers['sec-fetch-dest'] === 'document';
    const hint = userNavigation ? 'id_token_hint' : 'none';
    const returnTo = options.appBaseUrl;
    const logoutUrl = await request.auth0Client.logout(
      { returnTo: returnTo.toString(), hint },
      { request, response }
    );

    response.redirect(logoutUrl.href);
  });

  router.post('/auth/revoke', async (request: Request, response: Response) => {
    await request.auth0Client.revokeRefreshToken({}, { request, response });
    response.redirect('/private');
  });

  return router;
}
