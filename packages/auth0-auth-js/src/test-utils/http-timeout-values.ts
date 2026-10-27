// Values that are a usable `httpTimeout`: positive integers. Large ones are capped to the largest timer when used.
export const VALID_HTTP_TIMEOUTS = [
  1,
  150,
  5000,
  30000,
  60000,
  2147483647,
  2592000000,
  4294967296,
  Number.MAX_SAFE_INTEGER,
];
// Values that make no sense as a limit.
export const INVALID_HTTP_TIMEOUTS: unknown[] = [
  0,
  -1,
  NaN,
  Infinity,
  -Infinity,
  1500.5,
  0.5,
  '1000',
  null,
  undefined,
  true,
  {},
];
