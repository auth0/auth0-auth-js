import type { SignUpOptions, ChangePasswordOptions, SignUpResult } from './types.js';
import type { DatabaseApiErrorResponse } from './errors.js';

type ErrorCtor = new (message: string, cause?: DatabaseApiErrorResponse) => Error;

export function requireFields<T>(
  options: T, keys: Array<keyof T>, ErrorClass: ErrorCtor
): void {
  for (const key of keys) {
    if (options[key] === null || options[key] === undefined) {
      throw new ErrorClass(`Required parameter "${String(key)}" was null or undefined.`);
    }
  }
}

export function transformSignUpRequest(options: SignUpOptions): Record<string, unknown> {
  const wire: Record<string, unknown> = {
    email: options.email,
    password: options.password,
    connection: options.connection,
  };
  if (options.username !== undefined) wire.username = options.username;
  if (options.givenName !== undefined) wire.given_name = options.givenName;
  if (options.familyName !== undefined) wire.family_name = options.familyName;
  if (options.name !== undefined) wire.name = options.name;
  if (options.nickname !== undefined) wire.nickname = options.nickname;
  if (options.picture !== undefined) wire.picture = options.picture;
  if (options.userMetadata !== undefined) wire.user_metadata = options.userMetadata;
  return wire;
}

export function transformChangePasswordRequest(options: ChangePasswordOptions): Record<string, unknown> {
  const wire: Record<string, unknown> = {
    email: options.email,
    connection: options.connection,
  };
  if (options.organization !== undefined) wire.organization = options.organization;
  return wire;
}

export function normalizeSignUpResult(raw: Record<string, unknown>): SignUpResult {
  const id = (raw.id ?? raw._id ?? raw.user_id) as string | undefined;
  return {
    id,
    email: raw.email as string,
    emailVerified: Boolean(raw.email_verified),
    username: raw.username as string | undefined,
    givenName: raw.given_name as string | undefined,
    familyName: raw.family_name as string | undefined,
    name: raw.name as string | undefined,
    nickname: raw.nickname as string | undefined,
    picture: raw.picture as string | undefined,
    userMetadata: raw.user_metadata as Record<string, unknown> | undefined,
  };
}

export async function parseErrorBody(response: Response): Promise<DatabaseApiErrorResponse | undefined> {
  let raw: Record<string, unknown> | undefined;
  try {
    raw = (await response.json()) as Record<string, unknown>;
  } catch {
    return undefined;
  }
  if (typeof raw.error === 'string') {
    return raw as unknown as DatabaseApiErrorResponse;
  }
  if (typeof raw.code === 'string') {
    return { error: raw.code, error_description: (raw.description as string) ?? '' };
  }
  return undefined;
}
