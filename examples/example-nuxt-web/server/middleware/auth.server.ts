export default defineEventHandler(async (event) => {
  const url = getRequestURL(event);
  
  if (url.pathname === '/private') {
    // TODO: See if there are alternative / better ways to access auth0Client
    const auth0Client = event.context.auth0Client;
    const session = await auth0Client.getSession({ event });

    if (!session) {
      return sendRedirect(event, '/auth/login?returnTo=' + url.pathname);
    }
  }
})