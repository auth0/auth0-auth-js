import express from 'express';
import { auth0, connection } from './auth0.js';
import { SignUpError, ChangePasswordError } from '@auth0/auth0-server-js';

const app = express();
app.use(express.json());

/** Guard: the SDK expects non-empty strings; `{"email": null}` or missing fields must not reach it. */
function nonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

// POST /signup { email, password }
app.post('/signup', async (req, res) => {
  const { email, password } = req.body ?? {};
  if (!nonEmptyString(email) || !nonEmptyString(password)) {
    return res.status(400).json({ ok: false, message: 'email and password are required non-empty strings' });
  }
  try {
    const result = await auth0.database.signUp({ email, password, connection });
    res.json({ ok: true, user: result }); // result.id normalized
  } catch (err) {
    if (err instanceof SignUpError) {
      // POC ONLY: `err.cause` carries the raw Authentication API error body. Echoing it back to the
      // caller exposes internal API details — do NOT copy this to production. See README warning.
      res.status(400).json({ ok: false, code: err.code, message: err.message, cause: err.cause });
    } else {
      res.status(500).json({ ok: false, message: 'unexpected' });
    }
  }
});

// POST /change-password { email }
app.post('/change-password', async (req, res) => {
  const { email } = req.body ?? {};
  if (!nonEmptyString(email)) {
    return res.status(400).json({ ok: false, message: 'email is a required non-empty string' });
  }
  try {
    const message = await auth0.database.changePassword({ email, connection });
    res.json({ ok: true, message }); // plain-text confirmation
  } catch (err) {
    if (err instanceof ChangePasswordError) {
      res.status(400).json({ ok: false, code: err.code, message: err.message });
    } else {
      res.status(500).json({ ok: false, message: 'unexpected' });
    }
  }
});

const port = Number(process.env.PORT ?? 3000);
app.listen(port, () => console.log(`database-conns POC on http://localhost:${port}`));
