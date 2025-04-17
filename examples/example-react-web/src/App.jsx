import { useEffect, useState } from "react";
import { WebClient } from "@auth0/auth0-web-js";

import auth0Logo from "/auth0.png";
import "./App.css";
import { MemorySessionStore } from "./store/memory-session-store";
import { CookieTransactionStore } from "./store/cookie-transaction-store";

const auth0 = new WebClient({
  domain: import.meta.env.VITE_AUTH0_DOMAIN,
  clientId: import.meta.env.VITE_AUTH0_CLIENT_ID,
  transactionStore: new CookieTransactionStore(),
  stateStore: new MemorySessionStore(),
  authorizationParams: {
    redirect_uri: window.location.origin,
  },
});

function App() {
  const [accessToken, setAccessToken] = useState(null);

  useEffect(() => {
    const searchParams = new URLSearchParams(window.location.search);
    const code = searchParams.get("code");

    if (code) {
      async function handleAuth() {
        const url = new URL(window.location);

        await auth0.handleRedirectCallback(url);

        const token = await auth0.getAccessToken();

        setAccessToken(token);

        url.searchParams.delete("code");
        window.history.replaceState({}, "", url);
      }

      handleAuth();
    }
  }, []);

  return (
    <>
      <div>
        <a href="https://auth0.com/" target="_blank">
          <img src={auth0Logo} className="logo" alt="Auth0 logo" />
        </a>
      </div>
      {!accessToken && (
        <button onClick={() => auth0.loginWithRedirect()}>Login</button>
      )}
      {accessToken && (
        <>
          <pre>
            <code>{JSON.stringify(accessToken, null, 2)}</code>
          </pre>
          <button
            onClick={() =>
              auth0.logout({
                returnTo: window.location.origin,
              })
            }
          >
            Logout
          </button>
        </>
      )}
    </>
  );
}

export default App;
