import { ServerClient } from '@auth0/auth0-server-js';

console.log(
  new ServerClient({
    domain: 'auth0.local',
    clientId: 'abc',
    clientSecret: '123',
    secret: 'abc',
  })
);
