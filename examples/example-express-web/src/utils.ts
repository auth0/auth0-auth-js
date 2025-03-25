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
    response.redirect(`/auth/login?returnTo=${request.url}`);
  } else {
    next();
  }
}