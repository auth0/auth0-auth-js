import type { Request, Response, NextFunction } from 'express';

export async function hasSession(
  request: Request,
  response: Response,
  next: NextFunction
) {
  const session = await request.auth0Client.getSession({
    request,
    response,
  });

  if (!session) {
    // NOTE: this example always returns the user to "/" after login for simplicity.
    // A real app would persist `returnTo` (e.g. in the transaction/session) and
    // redirect back to it after the session is established.
    response.redirect('/auth/login');
  } else {
    next();
  }
}
