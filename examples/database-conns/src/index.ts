import express from 'express';
import { auth0, connection } from './auth0.js';
import { SignUpError, ChangePasswordError } from '@auth0/auth0-server-js';

const app = express();
app.use(express.json());

// POST /signup { email, password }
app.post('/signup', async (req, res) => {
  try {
    const result = await auth0.database.signUp({
      email: req.body.email,
      password: req.body.password,
      connection,
    });
    res.json({ ok: true, user: result }); // result.id normalized
  } catch (err) {
    if (err instanceof SignUpError) {
      res.status(400).json({ ok: false, code: err.code, message: err.message, cause: err.cause });
    } else {
      res.status(500).json({ ok: false, message: 'unexpected' });
    }
  }
});

// POST /change-password { email }
app.post('/change-password', async (req, res) => {
  try {
    const message = await auth0.database.changePassword({ email: req.body.email, connection });
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
