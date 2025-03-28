import {serve} from '@hono/node-server'
import app from './index'
import 'dotenv/config';

console.log('server starting on port 3000');
serve({port: 3000, fetch: app.fetch});
