import {Hono} from 'hono';
import {JwtEnv, jwt, requireScope} from './auth0';
import { logger } from 'hono/logger'

const app = new Hono<JwtEnv>();
app.use(logger())

app.get('/api/public', (c) => {
    return c.text(`Hello world!`);
})

app.use('/api/private/*', jwt());

app.get('/api/private/', (c) => {
    return c.text(`hello ${c.get('jwtPayload').sub}`);
})

app.get('/api/private/scope', requireScope('read:data'), (c) => {
    return c.text(`hello ${c.get('jwtPayload').sub}`);
})

export default app;

