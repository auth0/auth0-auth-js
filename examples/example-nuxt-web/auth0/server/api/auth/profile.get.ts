import { defineEventHandler } from 'h3';

export default defineEventHandler(async (event) => {
  // TODO: See if there are alternative / better ways to access auth0Client
  const auth0Client = event.context.auth0Client ;
  const session = await auth0Client.getSession({ event });

  return session?.user;
});