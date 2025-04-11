import { defineEventHandler, sendRedirect } from 'h3';

export default defineEventHandler(async (event) => {
 // TODO: See if there are alternative / better ways to access auth0Client and auth0ClientOptions
 const auth0Client = event.context.auth0Client;
 const auth0ClientOptions = event.context.auth0ClientOptions;

  const returnTo = auth0ClientOptions.appBaseUrl;
  const logoutUrl = await auth0Client.logout(
    { returnTo: returnTo.toString() },
    { event }
  );

  sendRedirect(event, logoutUrl.href);
});