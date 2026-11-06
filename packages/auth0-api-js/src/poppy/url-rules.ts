import { MAX_URL_LENGTH } from './constants.js';

// The rules for the URLs an agent chooses, and for the addresses behind them. They guard the requests the SDK makes
// for an agent's client metadata and keys, so a Personal Agent cannot aim them at a server of your own network.
// Spec: https://personalagentprotocol.org/docs/0.3/spec, section 3 (HTTPS, redirects and addresses) and section 4.1
// (agent identity).

/**
 * Parses an absolute URL.
 *
 * @param value - The text to parse.
 * @returns The URL, or `undefined` when `value` is not an absolute URL.
 */
export function parseUrl(value: string): URL | undefined {
  try {
    return new URL(value);
  } catch {
    return undefined;
  }
}

/**
 * Why a value is not an agent URL. {@link agentUrlProblem} reports the first of these that applies, in this order.
 */
export type AgentUrlProblem =
  | 'not_a_string'
  | 'too_long'
  | 'not_a_url'
  | 'not_https'
  | 'has_credentials'
  | 'has_fragment'
  | 'not_canonical';

/**
 * Finds what is wrong with a value that should be an agent URL, the `client_id` of a Personal Agent (spec section 4.1).
 *
 * This checks the shape only: a string of at most {@link MAX_URL_LENGTH} characters that parses, uses `https:`, has no
 * user name or password, has no `#` anywhere, and is in canonical form, which means `new URL(value).href` is
 * `value`. A `client_id` is compared character by character, so a URL that can be written two ways must be written
 * the one way the URL parser writes it. The address is not checked here, because `allowPrivateAddresses` can turn
 * that check off (see {@link isPublicHostname}).
 *
 * @param value - The value to check.
 * @returns The first problem found, or `undefined` when `value` is an agent URL.
 */
export function agentUrlProblem(value: unknown): AgentUrlProblem | undefined {
  if (typeof value !== 'string') {
    return 'not_a_string';
  }
  if (value.length > MAX_URL_LENGTH) {
    return 'too_long';
  }
  const url = parseUrl(value);
  if (url === undefined) {
    return 'not_a_url';
  }
  if (url.protocol !== 'https:') {
    return 'not_https';
  }
  if (url.username !== '' || url.password !== '') {
    return 'has_credentials';
  }
  // An empty fragment (`https://agent.example/x#`) stays in `href` and is missing from `url.hash`, so the canonical
  // form check below would accept it and a check of `url.hash` would not see it. The text is checked instead.
  if (value.includes('#')) {
    return 'has_fragment';
  }
  if (url.href !== value) {
    return 'not_canonical';
  }
  return undefined;
}

/**
 * Whether a value is an agent URL, the `client_id` of a Personal Agent (spec section 4.1): an `https:` URL in canonical
 * form, without user name, password or fragment, of at most {@link MAX_URL_LENGTH} characters.
 *
 * This checks the shape only, so `https://localhost:8443/agent.json` is an agent URL. Check the address with
 * {@link isPublicHostname}, unless private addresses are allowed on purpose.
 *
 * @param value - The value to check.
 * @returns Whether `value` is an agent URL.
 */
export function isAgentUrl(value: unknown): value is string {
  return agentUrlProblem(value) === undefined;
}

// `https://`, a host, an optional port and at most one slash. The host is a name or an IPv4 address, or an IPv6 address
// in brackets, and the port is digits, so `https://host:` is not an origin. User info, a path, a query and a fragment
// cannot match. An empty query or fragment leaves no trace on a parsed URL, so the text is checked and not the parsed
// URL. The URL parser still has to accept it, which checks the host and the size of the port.
const HTTPS_ORIGIN_PATTERN = /^https:\/\/(?:\[[^\]/?#@\\\s]+\]|[^/?#@\\\s:[\]]+)(?::\d+)?\/?$/;

/**
 * Whether a value is an `https:` origin: `https://host`, or `https://host:port` with digits for the port, with an
 * optional trailing slash. It has no user name, password, path, query or fragment. An empty port, as in `https://host:`,
 * is not an origin.
 *
 * The address is not checked. The origin of your own API and the issuer of your Auth0 domain are compared with
 * values in a request and never fetched, and either can be on `localhost` in development.
 *
 * @param value - The value to check.
 * @returns Whether `value` is an `https:` origin.
 */
export function isHttpsOrigin(value: unknown): value is string {
  return typeof value === 'string' && HTTPS_ORIGIN_PATTERN.test(value) && parseUrl(value) !== undefined;
}

// The IPv4 ranges that are not public, as [first address, prefix length]. The special-purpose ranges of RFC 6890 that
// can reach the machines of your own network, or no machine at all.
const NON_PUBLIC_IPV4_RANGES: ReadonlyArray<readonly [first: number, prefixLength: number]> = [
  [ipv4(0, 0, 0, 0), 8], // "this network" (RFC 1122)
  [ipv4(10, 0, 0, 0), 8], // private (RFC 1918)
  [ipv4(100, 64, 0, 0), 10], // shared address space of carrier-grade NAT (RFC 6598)
  [ipv4(127, 0, 0, 0), 8], // loopback (RFC 1122)
  [ipv4(169, 254, 0, 0), 16], // link-local, which includes the address of cloud metadata services (RFC 3927)
  [ipv4(172, 16, 0, 0), 12], // private (RFC 1918)
  [ipv4(192, 0, 0, 0), 24], // IETF protocol assignments (RFC 6890)
  [ipv4(192, 168, 0, 0), 16], // private (RFC 1918)
  [ipv4(198, 18, 0, 0), 15], // benchmarking (RFC 2544)
  [ipv4(224, 0, 0, 0), 4], // multicast (RFC 5771)
  [ipv4(240, 0, 0, 0), 4], // reserved (RFC 1112), and the limited broadcast address 255.255.255.255 (RFC 919)
];

/** The IPv4 address `a.b.c.d` as an unsigned 32-bit number. */
function ipv4(a: number, b: number, c: number, d: number): number {
  return ((a * 256 + b) * 256 + c) * 256 + d;
}

// What the URL parser writes for an IPv4 address: four decimal parts without leading zeros. It turns `2130706433`,
// `0177.0.0.1` and `0x7f.1` into `127.0.0.1` before this code sees the hostname.
const IPV4_PATTERN = /^(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})$/;

/** Reads an IPv4 address in the form the URL parser writes, as an unsigned 32-bit number. */
function parseIpv4(text: string): number | undefined {
  const match = IPV4_PATTERN.exec(text);
  if (match === null) {
    return undefined;
  }
  const [, a, b, c, d] = match.map(Number);
  // This cannot run: the pattern has four groups, and a match has all of them. The check is here to narrow the types.
  if (a === undefined || b === undefined || c === undefined || d === undefined) {
    return undefined;
  }
  return [a, b, c, d].every((part) => part <= 255) ? ipv4(a, b, c, d) : undefined;
}

function isPublicIpv4(address: number): boolean {
  return !NON_PUBLIC_IPV4_RANGES.some(([first, prefixLength]) => {
    const shift = 2 ** (32 - prefixLength);
    return Math.floor(address / shift) === Math.floor(first / shift);
  });
}

/** Reads one side of an IPv6 address: hex groups separated by `:`, the last one optionally an IPv4 address. */
function readGroups(text: string, allowIpv4Tail: boolean): number[] | undefined {
  if (text === '') {
    return [];
  }
  const pieces = text.split(':');
  const groups: number[] = [];
  for (const [index, piece] of pieces.entries()) {
    if (allowIpv4Tail && index === pieces.length - 1 && piece.includes('.')) {
      const address = parseIpv4(piece);
      if (address === undefined) {
        return undefined;
      }
      groups.push(Math.floor(address / 65536), address % 65536);
    } else if (/^[\da-f]{1,4}$/.test(piece)) {
      groups.push(Number.parseInt(piece, 16));
    } else {
      return undefined;
    }
  }
  return groups;
}

/** Reads an IPv6 address, without brackets, as its eight 16-bit groups. */
function parseIpv6(text: string): number[] | undefined {
  const halves = text.split('::');
  if (halves.length > 2) {
    return undefined;
  }
  const [head = '', tail] = halves;
  if (tail === undefined) {
    const groups = readGroups(head, true);
    return groups?.length === 8 ? groups : undefined;
  }
  // With `::`, only the part after it can end in an IPv4 address.
  const before = readGroups(head, false);
  const after = readGroups(tail, true);
  if (before === undefined || after === undefined) {
    return undefined;
  }
  // `::` stands for at least one group of zeros.
  const missing = 8 - before.length - after.length;
  return missing >= 1 ? [...before, ...new Array<number>(missing).fill(0), ...after] : undefined;
}

function isPublicIpv6(groups: readonly number[]): boolean {
  const group = (index: number): number => groups[index] ?? 0;
  const allZero = (from: number, to: number): boolean => groups.slice(from, to).every((value) => value === 0);
  const embedded = (high: number, low: number): number => high * 65536 + low;

  // ::/96 holds the IPv4-compatible addresses, which RFC 4291 deprecates. It holds `::` and `::1` too, as
  // 0.0.0.0 and 0.0.0.1 are in 0.0.0.0/8.
  if (allZero(0, 6)) {
    return isPublicIpv4(embedded(group(6), group(7)));
  }
  // ::ffff:0:0/96 holds the IPv4-mapped addresses (RFC 4291).
  if (allZero(0, 5) && group(5) === 0xffff) {
    return isPublicIpv4(embedded(group(6), group(7)));
  }
  // ::ffff:0:0:0/96 holds the IPv4-translated addresses, which put an IPv4 address in the last 32 bits (RFC 2765). Do
  // not mix it up with the IPv4-mapped range above, which has the group of ones one group later.
  if (allZero(0, 4) && group(4) === 0xffff && group(5) === 0) {
    return isPublicIpv4(embedded(group(6), group(7)));
  }
  // 64:ff9b::/96 is the prefix of NAT64, which puts an IPv4 address in the last 32 bits (RFC 6052).
  if (group(0) === 0x64 && group(1) === 0xff9b && allZero(2, 6)) {
    return isPublicIpv4(embedded(group(6), group(7)));
  }
  // 64:ff9b:1::/48 is the prefix that a network may use for NAT64 of its own (RFC 8215). Only the layout of a /96 prefix
  // is read: the IPv4 address is in the last 32 bits. A network can choose another layout of RFC 6052, section 2.2.
  if (group(0) === 0x64 && group(1) === 0xff9b && group(2) === 1) {
    return isPublicIpv4(embedded(group(6), group(7)));
  }
  // 2002::/16 is 6to4, which puts an IPv4 address in bits 16 to 47 (RFC 3056).
  if (group(0) === 0x2002) {
    return isPublicIpv4(embedded(group(1), group(2)));
  }
  const first = group(0);
  const isUniqueLocal = (first & 0xfe00) === 0xfc00; // fc00::/7 (RFC 4193)
  const isLinkLocal = (first & 0xffc0) === 0xfe80; // fe80::/10 (RFC 4291)
  const isSiteLocal = (first & 0xffc0) === 0xfec0; // fec0::/10, which RFC 3879 deprecates
  const isMulticast = (first & 0xff00) === 0xff00; // ff00::/8 (RFC 4291)
  return !isUniqueLocal && !isLinkLocal && !isSiteLocal && !isMulticast;
}

/**
 * `host` without its trailing dots, in one pass. A pattern such as `/\.+$/` is not an option: it starts again from
 * every dot of a long run that is not at the end, so its time grows with the square of the length.
 */
function withoutTrailingDots(host: string): string {
  let end = host.length;
  while (end > 0 && host.charCodeAt(end - 1) === 0x2e) {
    end -= 1;
  }
  return host.slice(0, end);
}

// The URL parser reads a host as an IPv4 address when its last label is a number, in decimal or in hex (`0x7f`).
function endsInNumber(host: string): boolean {
  const lastLabel = host.slice(host.lastIndexOf('.') + 1);
  return /^(?:\d+|0x[\da-f]*)$/.test(lastLabel);
}

// The domains that only a local network resolves, or that no network does: `localhost` (RFC 6761), `local` for mDNS
// (RFC 6762), `internal` for private networks, `localdomain` for the alias of /etc/hosts, and `home.arpa` for home
// networks (RFC 8375). A name is under one of them when it is the domain or ends with a dot and the domain. `example`
// and `test` are not here: the tests and the docs name their agents under them.
const LOCAL_ONLY_DOMAINS: readonly string[] = ['localhost', 'local', 'internal', 'localdomain', 'home.arpa'];

function isUnderLocalOnlyDomain(host: string): boolean {
  return LOCAL_ONLY_DOMAINS.some((domain) => host === domain || host.endsWith(`.${domain}`));
}

/**
 * Whether a hostname is one the SDK may connect to for an agent: not `localhost`, not a name that only a local network
 * can resolve, and not an IP address in a range that is loopback, private, link-local or otherwise not public. Spec
 * section 3 says a Company MUST NOT connect to such an address for a URL the other party gave it, unless it was
 * configured to on purpose.
 *
 * Pass `URL.hostname`. This function expects a hostname as the URL parser writes it, and it does not normalize a
 * hostname itself. The parser turns `2130706433`, `0177.0.0.1` and an address in full-width digits into `127.0.0.1`,
 * and it writes an IPv6 address in brackets. Text that did not go through the parser is read as it is, so a name in
 * full-width digits is read as a name. As a safeguard, these are refused: a hostname that ends in a number but is not
 * an IPv4 address in four decimal parts, an IPv6 address that cannot be read, and an empty hostname. Letter case and
 * trailing dots are ignored.
 *
 * The names that are refused:
 * - `localhost` and every name under it.
 * - A name with no dot, such as `vault`. A resolver completes it from the search list of its own network, so it can
 *   only be a host of that network.
 * - Every name under `.local`, `.internal`, `.localdomain` and `.home.arpa`, which are for local networks.
 *
 * The ranges:
 * - IPv4: 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24,
 *   192.168.0.0/16, 198.18.0.0/15, 224.0.0.0/4 and 240.0.0.0/4.
 * - IPv6: `::`, `::1`, fc00::/7, fe80::/10, fec0::/10 and ff00::/8.
 * - The IPv6 ranges that hold an IPv4 address are checked with the IPv4 ranges: the IPv4-mapped addresses
 *   (::ffff:0:0/96), the IPv4-translated addresses (::ffff:0:0:0/96), the IPv4-compatible addresses (::/96), NAT64
 *   (64:ff9b::/96), the local-use NAT64 prefix (64:ff9b:1::/48) and 6to4 (2002::/16).
 *
 * This looks at the text of the hostname. It cannot see where a name resolves to, so any other name passes, even one
 * that points to an internal address. Guard against that with the `fetch` you give the SDK, or with an egress proxy.
 *
 * @param hostname - The hostname, without a port.
 * @returns Whether `hostname` may be connected to.
 */
export function isPublicHostname(hostname: string): boolean {
  // The URL parser keeps trailing dots: `localhost.` and `localhost..` are different strings from `localhost`, but a
  // resolver can read them as it. It keeps them after an address too (`127.0.0.1..` is a name to the parser, not an
  // address), so every one of them goes before the address is read.
  const host = withoutTrailingDots(hostname.toLowerCase());
  if (host === '' || isUnderLocalOnlyDomain(host)) {
    return false;
  }
  if (host.includes(':') || host.startsWith('[') || host.endsWith(']')) {
    const literal = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
    const groups = parseIpv6(literal);
    return groups !== undefined && isPublicIpv6(groups);
  }
  if (endsInNumber(host)) {
    const address = parseIpv4(host);
    return address !== undefined && isPublicIpv4(address);
  }
  // A name with no dot is one label, which a resolver completes from the search list of its own network.
  return host.includes('.');
}

/**
 * Whether two URLs have the same hostname. Ports and paths are ignored.
 *
 * Spec section 4.1 says the `jwks_uri` of an agent is "on the same domain as `client_id`". Deciding whether two hosts
 * share a registrable domain needs the Public Suffix List, so the SDK takes the strict reading: the hostnames must be
 * equal.
 *
 * @param a - The first URL.
 * @param b - The second URL.
 * @returns Whether both parse and have the same hostname. `false` when either does not parse.
 */
export function sameHostname(a: string, b: string): boolean {
  const first = parseUrl(a);
  const second = parseUrl(b);
  return first !== undefined && second !== undefined && first.hostname === second.hostname;
}
