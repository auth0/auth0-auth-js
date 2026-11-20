import { POPPY_VERSION_PATTERN } from './constants.js';

// Spec: https://personalagentprotocol.org/docs/1.0/spec, section 3.4 ("Declaring versions", "Checking the version").

/** The two numbers of a version, or `undefined` for text that is not `major.minor`. */
function parseVersion(version: string): { major: number; minor: number } | undefined {
  if (!POPPY_VERSION_PATTERN.test(version)) {
    return undefined;
  }
  const [major = 0, minor = 0] = version.split('.').map(Number);
  return { major, minor };
}

/**
 * Whether a version that an agent sent in `Poppy-Version` is compatible with a version that the API serves. Two
 * versions are compatible when they have the same major version and, before 1.0, the same minor version (section 3.4).
 * So an API that serves `1.0` accepts `1.1`: from 1.0 a side sends only what the other side's version defines. The
 * `versions` option takes `1.x` versions only, so the rule for 0.x is kept for this function and not used by the SDK.
 */
export function isCompatibleVersion(requested: string, served: string): boolean {
  const a = parseVersion(requested);
  const b = parseVersion(served);
  if (a === undefined || b === undefined || a.major !== b.major) {
    return false;
  }
  return a.major >= 1 || a.minor === b.minor;
}

/** Whether the version of a request is compatible with at least one of the versions that the API serves. */
export function isServedVersion(requested: string, served: readonly string[]): boolean {
  return served.some((version) => isCompatibleVersion(requested, version));
}
