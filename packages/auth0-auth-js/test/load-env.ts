import { config } from 'dotenv';
import { resolve } from 'path';

// Load .env.validation from repo root (or from AUTH0_ENV_FILE if set) into process.env
const envPath = process.env.AUTH0_ENV_FILE || resolve(__dirname, '../../../.env.validation');
config({ path: envPath });
