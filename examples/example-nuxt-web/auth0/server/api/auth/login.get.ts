import { defineEventHandler, sendRedirect } from 'h3';

export default defineEventHandler(async (event) => {
  // TODO: See if there are alternative / better ways to access auth0Client and auth0ClientOptions
  const auth0Client = event.context.auth0Client;
  const auth0ClientOptions = event.context.auth0ClientOptions;
  const query = getQuery(event);
  const returnTo = query.returnTo ?? auth0ClientOptions.appBaseUrl;

  const authorizationUrl = await auth0Client.startInteractiveLogin(
    {
      appState: { returnTo },
    },
    { event }
  );

  sendRedirect(event, authorizationUrl.href);
});
