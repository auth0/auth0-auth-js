import { Auth0Client } from '@auth0/auth0-server-js';

console.log(
  new Auth0Client({
    domain: 'auth0.local',
    clientId: 'abc',
    clientSecret: '123',
  })
);
