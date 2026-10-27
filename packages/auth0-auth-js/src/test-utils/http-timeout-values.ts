// Values `AbortSignal.timeout` handles correctly, and values it does not (or that make no sense as a limit).
export const VALID_HTTP_TIMEOUTS = [1, 150, 5000, 30000, 60000, 2147483647];
export const INVALID_HTTP_TIMEOUTS: unknown[] = [
  0,
  -1,
  NaN,
  Infinity,
  -Infinity,
  1500.5,
  0.5,
  2147483648,
  4294967295,
  4294967296,
  1e10,
  Number.MAX_SAFE_INTEGER,
  '1000',
  null,
  undefined,
  true,
  {},
];
