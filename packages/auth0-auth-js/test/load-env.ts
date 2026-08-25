import { config } from 'dotenv';
import { resolve } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

// Load .env.validation from repo root (or from AUTH0_ENV_FILE if set) into process.env
const __dirname = dirname(fileURLToPath(import.meta.url));
const envPath = process.env.AUTH0_ENV_FILE || resolve(__dirname, '../../../.env.validation');
config({ path: envPath });
