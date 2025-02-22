import { hkdf } from '@panva/hkdf';
import * as jose from 'jose';

const ENC = 'A256CBC-HS512';
const ALG = 'dir';
const DIGEST = 'sha256';
const BYTE_LENGTH = 64;
const ENCRYPTION_INFO = 'Auth0 Generated ryption';

export async function encrypt(payload: jose.JWTPayload, secret: string, salt: string) {
  const encryptionSecret = await hkdf(DIGEST, secret, salt, ENCRYPTION_INFO, BYTE_LENGTH);

  return await new jose.EncryptJWT(payload).setProtectedHeader({ enc: ENC, alg: ALG }).encrypt(encryptionSecret);
}

export async function decrypt<T>(value: string, secret: string, salt: string) {
  const encryptionSecret = await hkdf(DIGEST, secret, salt, ENCRYPTION_INFO, BYTE_LENGTH);

  const res = await jose.jwtDecrypt<T>(value, encryptionSecret, {});
  return res.payload;
}

// Above code only exists in auth0-fastify for tests, we want to consider removing this
