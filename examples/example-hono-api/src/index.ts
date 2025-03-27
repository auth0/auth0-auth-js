import {Hono} from 'hono'
import {Auth0JwtEnv, jwt, requireScope} from './auth0'

const app = new Hono<Auth0JwtEnv>()

app.get('/api/public', (c) => {
    return c.text(`Hello world!`)
})

app.use('/api/private/*', jwt())

app.get('/api/private/', (c) => {
    return c.text(`hello ${c.get('jwtPayload').sub}`)
})

app.get('/api/private/scope', requireScope('read:data'), (c) => {
    return c.text(`hello ${c.get('jwtPayload').sub}`)
})

// noinspection JSUnusedGlobalSymbols
export default app

