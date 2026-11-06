import { describe, expect, test } from 'vitest';

import { MAX_URL_LENGTH } from './constants.js';
import {
  agentUrlProblem,
  isAgentUrl,
  isHttpsOrigin,
  isPublicHostname,
  parseUrl,
  sameHostname,
  type AgentUrlProblem,
} from './url-rules.js';

/** A canonical agent URL that is exactly `length` characters long. */
function agentUrlOfLength(length: number): string {
  const prefix = 'https://agent.example/';
  return prefix + 'a'.repeat(length - prefix.length);
}

/** What the verifier passes to `isPublicHostname`: the hostname after the URL parser has normalized the address. */
function hostnameOf(url: string): string {
  return new URL(url).hostname;
}

describe('isAgentUrl', () => {
  test.each<[string, unknown]>([
    ['a plain agent URL', 'https://agent.example/agent.json'],
    ['a query', 'https://agent.example/a?b=c'],
    ['localhost, because this checks the shape only', 'https://localhost:8443/agent.json'],
    ['an IP address, because this checks the shape only', 'https://127.0.0.1/agent.json'],
    ['a port that is not the default one', 'https://agent.example:8443/agent.json'],
    ['the root path', 'https://agent.example/'],
    ['the longest URL', agentUrlOfLength(MAX_URL_LENGTH)],
  ])('accepts %s', (_label, value) => {
    expect(isAgentUrl(value)).toBe(true);
  });

  test.each<[string, unknown]>([
    ['http', 'http://agent.example/agent.json'],
    ['another scheme', 'ftp://agent.example/agent.json'],
    ['a script URL', 'javascript:alert(1)'],
    ['a user name and a password', 'https://u:p@agent.example/x'],
    ['a user name only', 'https://u@agent.example/x'],
    ['an empty user info, which the canonical form drops', 'https://@agent.example/x'],
    ['a fragment', 'https://agent.example/x#f'],
    ['an empty fragment', 'https://agent.example/x#'],
    ['an upper-case host, which is not canonical', 'https://Agent.example/x'],
    ['no path, which is not canonical', 'https://agent.example'],
    ['the default port, which is not canonical', 'https://agent.example:443/x'],
    ['a dot segment, which is not canonical', 'https://agent.example/a/../x'],
    ['a space, which is not canonical', 'https://agent.example/a b'],
    ['a leading space', ' https://agent.example/x'],
    ['a trailing new line', 'https://agent.example/x\n'],
    ['a tab inside the host', 'https://agent.exa\tmple/x'],
    ['a backslash', 'https://agent.example\\x'],
    ['a Unicode host, which is not canonical', 'https://bücher.example/x'],
    ['text that is not a URL', 'not a url'],
    ['an empty string', ''],
    ['a URL one character over the limit', agentUrlOfLength(MAX_URL_LENGTH + 1)],
    ['a number', 42],
    ['null', null],
    ['undefined', undefined],
    ['an object', { href: 'https://agent.example/x' }],
    ['a URL object', new URL('https://agent.example/x')],
  ])('rejects %s', (_label, value) => {
    expect(isAgentUrl(value)).toBe(false);
  });
});

describe('agentUrlProblem', () => {
  test.each<[string, unknown, AgentUrlProblem | undefined]>([
    ['a valid agent URL', 'https://agent.example/agent.json', undefined],
    ['a number', 42, 'not_a_string'],
    ['a URL over the limit', agentUrlOfLength(MAX_URL_LENGTH + 1), 'too_long'],
    ['text that is not a URL', 'not a url', 'not_a_url'],
    ['http', 'http://agent.example/agent.json', 'not_https'],
    ['credentials', 'https://u:p@agent.example/x', 'has_credentials'],
    [
      'credentials and a fragment, which names the credentials first',
      'https://u:p@agent.example/x#f',
      'has_credentials',
    ],
    ['a fragment', 'https://agent.example/x#f', 'has_fragment'],
    ['an empty fragment', 'https://agent.example/x#', 'has_fragment'],
    ['an upper-case host', 'https://Agent.example/x', 'not_canonical'],
    ['no path', 'https://agent.example', 'not_canonical'],
    ['an empty user info', 'https://@agent.example/x', 'not_canonical'],
  ])('names the problem with %s', (_label, value, problem) => {
    expect(agentUrlProblem(value)).toBe(problem);
  });

  test('agrees with isAgentUrl', () => {
    for (const value of ['https://agent.example/agent.json', 'https://Agent.example/x', 42, '', 'http://a.example/']) {
      expect(isAgentUrl(value)).toBe(agentUrlProblem(value) === undefined);
    }
  });
});

describe('isHttpsOrigin', () => {
  test.each<[string, unknown]>([
    ['a host', 'https://api.zepto.example'],
    ['a host and a trailing slash', 'https://api.zepto.example/'],
    ['localhost with a port, because this checks the shape only', 'https://localhost:3000'],
    ['an IPv6 address with a port', 'https://[::1]:3000'],
    ['an IPv4 address with a port', 'https://127.0.0.1:8080'],
    ['a port that is not the default one', 'https://api.zepto.example:8443/'],
    ['an upper-case host, which the stored origin lowers', 'https://API.zepto.example'],
    ['the default port, which the stored origin drops', 'https://api.zepto.example:443'],
  ])('accepts %s', (_label, value) => {
    expect(isHttpsOrigin(value)).toBe(true);
  });

  test.each<[string, unknown]>([
    ['a path', 'https://api.zepto.example/v1'],
    ['http', 'http://api.zepto.example'],
    ['a query', 'https://api.zepto.example?x'],
    ['an empty query', 'https://api.zepto.example?'],
    ['a fragment', 'https://api.zepto.example#f'],
    ['an empty fragment', 'https://api.zepto.example/#'],
    ['a user name and a password', 'https://u:p@api.zepto.example'],
    ['a user name only', 'https://u@api.zepto.example'],
    ['two slashes', 'https://api.zepto.example//'],
    ['a trailing space', 'https://api.zepto.example '],
    ['a space inside the host', 'https://api zepto.example'],
    ['a trailing backslash', 'https://api.zepto.example\\'],
    ['no scheme', 'api.zepto.example'],
    ['a scheme-relative URL', '//api.zepto.example'],
    ['a scheme without slashes', 'https:api.zepto.example'],
    ['an upper-case scheme', 'HTTPS://api.zepto.example'],
    ['no host', 'https://'],
    ['a port that is too large', 'https://api.zepto.example:99999'],
    ['a port that is not a number', 'https://api.zepto.example:abc'],
    ['an empty port', 'https://api.zepto.example:'],
    ['an empty port and a trailing slash', 'https://api.zepto.example:/'],
    ['an empty port after an IPv6 address', 'https://[::1]:'],
    ['a port with a sign', 'https://api.zepto.example:+80'],
    ['two ports', 'https://api.zepto.example:80:90'],
    ['a colon in a host that is not an IPv6 address', 'https://a:b.example'],
    ['an IPv6 address without the closing bracket', 'https://[::1'],
    ['an empty string', ''],
    ['a number', 42],
    ['null', null],
    ['undefined', undefined],
    ['a URL object', new URL('https://api.zepto.example')],
  ])('rejects %s', (_label, value) => {
    expect(isHttpsOrigin(value)).toBe(false);
  });
});

describe('isPublicHostname', () => {
  test('relies on the URL parser to write numeric hosts and IPv6 literals in one canonical form', () => {
    expect(hostnameOf('https://2130706433/x')).toBe('127.0.0.1');
    expect(hostnameOf('https://0177.0.0.1/x')).toBe('127.0.0.1');
    expect(hostnameOf('https://[::ffff:192.168.0.1]/x')).toBe('[::ffff:c0a8:1]');
  });

  describe('names', () => {
    test.each<[string, string]>([
      ['localhost', 'localhost'],
      ['a name under localhost', 'a.localhost'],
      ['a deeper name under localhost', 'a.b.localhost'],
      ['localhost in capitals', 'LOCALHOST'],
      ['a name under localhost in mixed case', 'Sub.LocalHost'],
      ['localhost with a trailing dot', 'localhost.'],
      ['a name under localhost with a trailing dot', 'a.localhost.'],
      ['localhost with two trailing dots, which the URL parser keeps', 'localhost..'],
      ['an empty hostname', ''],
      ['a dot', '.'],
    ])('rejects %s', (_label, hostname) => {
      expect(isPublicHostname(hostname)).toBe(false);
    });

    // A name with no dot is one label, which a resolver completes from the search list of its own network, so it can
    // only be a host of that network.
    test.each<[string, string]>([
      ['a name with no dot', 'vault'],
      ['a name with no dot in capitals', 'VAULT'],
      ['a name with no dot that ends with localhost', 'mylocalhost'],
      ['a name with no dot and a hyphen', 'my-agent'],
      ['a name with no dot and a digit', 'agent1'],
      ['a name with no dot and a trailing dot', 'vault.'],
      ['a name with no dot and two trailing dots, which the URL parser keeps', 'vault..'],
      ['local on its own', 'local'],
      ['internal on its own', 'internal'],
      ['localdomain on its own', 'localdomain'],
      ['a punycode label with no dot', 'xn--bcher-kva'],
    ])('rejects %s', (_label, hostname) => {
      expect(isPublicHostname(hostname)).toBe(false);
    });

    // These suffixes are for networks of their own, or for no network: mDNS names, names of a cloud network or of a
    // cluster, the alias of /etc/hosts, and the names of a home network (RFC 6762, RFC 8375).
    test.each<[string, string]>([
      ['a name under .local', 'printer.local'],
      ['a name under .local in mixed case', 'Printer.LOCAL'],
      ['a name under .local with a trailing dot', 'printer.local.'],
      ['a deeper name under .local', 'a.b.local'],
      ['a name under .internal', 'metadata.google.internal'],
      ['a name under .internal with a trailing dot', 'db.internal.'],
      ['a name under .internal with two trailing dots', 'db.internal..'],
      ['a name under .localdomain', 'host.localdomain'],
      ['localhost.localdomain, the alias of /etc/hosts', 'localhost.localdomain'],
      ['a name under .home.arpa', 'printer.home.arpa'],
      ['a deeper name under .home.arpa', 'a.b.home.arpa'],
      ['home.arpa itself', 'home.arpa'],
      ['home.arpa in capitals', 'HOME.ARPA'],
    ])('rejects %s', (_label, hostname) => {
      expect(isPublicHostname(hostname)).toBe(false);
    });

    test.each<[string, string]>([
      ['a registered-looking name', 'agent.example'],
      ['a name with several labels', 'www.agent.example'],
      ['a name in capitals', 'AGENT.EXAMPLE'],
      ['a name with a trailing dot', 'agent.example.'],
      ['a punycode name', 'xn--bcher-kva.example'],
      ['a name that only starts with localhost', 'localhost.example'],
      ['a name that only ends with localhost', 'a.mylocalhost'],
      ['a name that only ends with localhost.example', 'notlocalhost.example'],
      ['a name that has localhost in the middle', 'a.localhost.example'],
      ['a name that has digits in a label', '1.2.3.4.example'],
      // The tests and the docs use these for agents, and they are not refused.
      ['a name under .test', 'my-agent.test'],
      ['a name under .example', 'my-agent.example'],
      ['a name with a dot and a trailing dot', 'my-agent.test.'],
    ])('accepts %s', (_label, hostname) => {
      expect(isPublicHostname(hostname)).toBe(true);
    });

    test.each<[string, string]>([
      ['a name that has local in the middle', 'a.local.example'],
      ['a name that has internal in the middle', 'a.internal.example'],
      ['a name that has localdomain in the middle', 'a.localdomain.example'],
      ['a name that has home.arpa in the middle', 'home.arpa.example'],
      ['a name whose last label only ends with local', 'a.notlocal'],
      ['a name whose last label only ends with internal', 'a.notinternal'],
      ['a name whose last label only ends with localdomain', 'a.notlocaldomain'],
      ['a name whose last labels only end with home.arpa', 'a.nothome.arpa'],
      ['a name under another arpa zone', 'host.in-addr.arpa'],
      ['a name that starts with local', 'local.example'],
      ['a name that starts with internal', 'internal.example'],
    ])('accepts %s, because the suffix is a whole label', (_label, hostname) => {
      expect(isPublicHostname(hostname)).toBe(true);
    });
  });

  describe('long input', () => {
    // A trailing dot is stripped in one pass. A pattern such as /\.+$/ backtracks from every dot of a long run that is
    // not at the end, so it takes seconds for 65,536 dots (the time grows with the square of the length).
    const DOTS = '.'.repeat(65_536);

    test.each<[string, string]>([
      ['65,536 dots and then a label', `${DOTS}a`],
      ['a label and then 65,536 dots', `a${DOTS}`],
      ['two labels with 65,536 dots between them', `a${DOTS}b`],
      ['localhost and then 65,536 dots', `localhost${DOTS}`],
      ['a loopback address and then 65,536 dots', `127.0.0.1${DOTS}`],
      ['a name with no dot and then 65,536 dots', `vault${DOTS}`],
      ['a name under .local and then 65,536 dots', `printer.local${DOTS}`],
      ['65,536 dots and nothing else', DOTS],
    ])('handles %s in well under 100 ms', (_label, hostname) => {
      const start = performance.now();
      isPublicHostname(hostname);
      const elapsed = performance.now() - start;

      expect(elapsed).toBeLessThan(100);
    });

    test('still sees localhost and an address behind 65,536 trailing dots', () => {
      expect(isPublicHostname(`localhost${DOTS}`)).toBe(false);
      expect(isPublicHostname(`127.0.0.1${DOTS}`)).toBe(false);
      expect(isPublicHostname(`vault${DOTS}`)).toBe(false);
      expect(isPublicHostname(`printer.local${DOTS}`)).toBe(false);
      expect(isPublicHostname(DOTS)).toBe(false);
      expect(isPublicHostname(`agent.example${DOTS}`)).toBe(true);
    });
  });

  describe('IPv4 addresses', () => {
    test.each<[string, string]>([
      ['127.0.0.1', '127.0.0.1'],
      ['10.1.2.3', '10.1.2.3'],
      ['172.31.0.1', '172.31.0.1'],
      ['192.168.0.1', '192.168.0.1'],
      ['169.254.169.254, the address of cloud metadata services', '169.254.169.254'],
      ['100.64.0.1', '100.64.0.1'],
      ['0.0.0.0', '0.0.0.0'],
      ['an address with a trailing dot', '127.0.0.1.'],
      ['a loopback address with two trailing dots', '127.0.0.1..'],
      ['a private address with two trailing dots', '10.0.0.1..'],
      ['a link-local address with several trailing dots', '169.254.169.254....'],
    ])('rejects %s', (_label, hostname) => {
      expect(isPublicHostname(hostname)).toBe(false);
    });

    test('the URL parser keeps more than one trailing dot after an address, so the address check has to look past them', () => {
      expect(hostnameOf('https://127.0.0.1./x')).toBe('127.0.0.1');
      expect(hostnameOf('https://127.0.0.1../x')).toBe('127.0.0.1..');
      expect(isAgentUrl('https://127.0.0.1../x')).toBe(true);
    });

    test.each<[string, string]>([
      ['a 32-bit number', 'https://2130706433/x'],
      ['an octal address', 'https://0177.0.0.1/x'],
      ['a hex address', 'https://0x7f.0.0.1/x'],
      ['a short address', 'https://127.1/x'],
      ['a single 0', 'https://0/x'],
      ['an address with a trailing dot', 'https://127.0.0.1./x'],
      ['a loopback address with two trailing dots', 'https://127.0.0.1../x'],
      ['a private address with two trailing dots', 'https://10.0.0.1../x'],
      ['a percent-encoded address', 'https://%31%32%37.0.0.1/x'],
      ['full-width digits, which the URL parser maps to ASCII', 'https://１２７.0.0.1/x'],
    ])('rejects the hostname of a URL with %s', (_label, url) => {
      expect(isPublicHostname(hostnameOf(url))).toBe(false);
    });

    // The range table of the SDK: [range, first address, last address].
    const NON_PUBLIC_RANGES: Array<[range: string, first: string, last: string]> = [
      ['0.0.0.0/8', '0.0.0.0', '0.255.255.255'],
      ['10.0.0.0/8', '10.0.0.0', '10.255.255.255'],
      ['100.64.0.0/10', '100.64.0.0', '100.127.255.255'],
      ['127.0.0.0/8', '127.0.0.0', '127.255.255.255'],
      ['169.254.0.0/16', '169.254.0.0', '169.254.255.255'],
      ['172.16.0.0/12', '172.16.0.0', '172.31.255.255'],
      ['192.0.0.0/24', '192.0.0.0', '192.0.0.255'],
      ['192.168.0.0/16', '192.168.0.0', '192.168.255.255'],
      ['198.18.0.0/15', '198.18.0.0', '198.19.255.255'],
      ['224.0.0.0/4', '224.0.0.0', '239.255.255.255'],
      ['240.0.0.0/4', '240.0.0.0', '255.255.255.255'],
    ];

    test.each(
      NON_PUBLIC_RANGES.flatMap(
        ([range, first, last]): Array<[string, string]> => [
          [`${first}, the first address of ${range}`, first],
          [`${last}, the last address of ${range}`, last],
        ]
      )
    )('rejects %s', (_label, address) => {
      expect(isPublicHostname(address)).toBe(false);
    });

    test.each(['8.8.8.8', '172.32.0.1'])('accepts %s', (address) => {
      expect(isPublicHostname(address)).toBe(true);
    });

    test.each([
      '1.0.0.0',
      '9.255.255.255',
      '11.0.0.0',
      '100.63.255.255',
      '100.128.0.0',
      '126.255.255.255',
      '128.0.0.0',
      '169.253.255.255',
      '169.255.0.0',
      '172.15.255.255',
      '172.32.0.0',
      '191.255.255.255',
      '192.0.1.0',
      '192.167.255.255',
      '192.169.0.0',
      '198.17.255.255',
      '198.20.0.0',
      '223.255.255.255',
    ])('accepts %s, an address next to a range that is not public', (address) => {
      expect(isPublicHostname(address)).toBe(true);
    });

    test.each([
      ['a 32-bit number', '2130706433'],
      ['an octal address', '0177.0.0.1'],
      ['a hex address', '0x7f.0.0.1'],
      ['a short address', '127.1'],
      ['an address with three parts', '1.2.3'],
      ['an address with five parts', '1.2.3.4.5'],
      ['an address with a part over 255', '1.2.3.256'],
      ['an address with a leading zero', '01.2.3.4'],
      ['a name that ends in a number', 'example.123'],
    ])('refuses %s when it is not in the canonical form the URL parser writes', (_label, hostname) => {
      expect(isPublicHostname(hostname)).toBe(false);
    });
  });

  describe('IPv6 addresses', () => {
    test.each<[string, string]>([
      ['the loopback address', '[::1]'],
      ['the unspecified address', '[::]'],
      ['a link-local address', '[fe80::1]'],
      ['the last link-local prefix', '[febf::1]'],
      ['a unique local address', '[fd00::1]'],
      ['the first unique local prefix', '[fc00::1]'],
      ['the last unique local address', '[fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]'],
      ['a multicast address', '[ff02::1]'],
      ['the first multicast address', '[ff00::]'],
      ['the loopback address written in full', '[0:0:0:0:0:0:0:1]'],
      ['an address without the brackets', '::1'],
    ])('rejects %s', (_label, hostname) => {
      expect(isPublicHostname(hostname)).toBe(false);
    });

    test.each<[string, string]>([
      ['a private IPv4 address mapped in the dotted form', '[::ffff:192.168.0.1]'],
      ['a private IPv4 address mapped in the hex form', '[::ffff:c0a8:1]'],
      ['a loopback IPv4 address mapped in the dotted form', '[::ffff:127.0.0.1]'],
      ['a loopback IPv4 address mapped in the hex form', '[::ffff:7f00:1]'],
      ['the cloud metadata address mapped in the hex form', '[::ffff:a9fe:a9fe]'],
      ['the unspecified IPv4 address mapped', '[::ffff:0:0]'],
      ['a mapped address in upper case', '[::FFFF:7F00:1]'],
      ['a mapped address written in full', '[0:0:0:0:0:ffff:7f00:1]'],
      ['a mapped address written in full with a dotted tail', '[0:0:0:0:0:ffff:127.0.0.1]'],
    ])('rejects an IPv4-mapped address: %s', (_label, hostname) => {
      expect(isPublicHostname(hostname)).toBe(false);
    });

    test.each<[string, string]>([
      ['a loopback IPv4 address', '[::7f00:1]'],
      ['a loopback IPv4 address in the dotted form', '[::127.0.0.1]'],
      ['a 10/8 IPv4 address', '[::a00:1]'],
      ['a 192.168/16 IPv4 address', '[::c0a8:1]'],
      ['the cloud metadata address', '[::a9fe:a9fe]'],
    ])('rejects an IPv4-compatible address (::/96) with %s', (_label, hostname) => {
      expect(isPublicHostname(hostname)).toBe(false);
    });

    test.each<[string, string]>([
      ['a loopback IPv4 address', '[64:ff9b::7f00:1]'],
      ['the cloud metadata address', '[64:ff9b::a9fe:a9fe]'],
      ['a private IPv4 address in the dotted form', '[64:ff9b::192.168.0.1]'],
      ['a 10/8 IPv4 address written in full', '[64:ff9b:0:0:0:0:a00:1]'],
    ])('rejects a NAT64 address (64:ff9b::/96) with %s', (_label, hostname) => {
      expect(isPublicHostname(hostname)).toBe(false);
    });

    test.each<[string, string]>([
      ['a loopback IPv4 address', '[2002:7f00:1::]'],
      ['a 192.168/16 IPv4 address', '[2002:c0a8:1::1]'],
      ['the cloud metadata address', '[2002:a9fe:a9fe::]'],
      ['a 10/8 IPv4 address written in full', '[2002:a00:1:0:0:0:0:1]'],
    ])('rejects a 6to4 address (2002::/16) with %s', (_label, hostname) => {
      expect(isPublicHostname(hostname)).toBe(false);
    });

    test.each<[string, string]>([
      ['the first site-local address', '[fec0::]'],
      ['a site-local address', '[fec0::1]'],
      ['the last site-local prefix', '[feff::1]'],
      ['the last site-local address', '[feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]'],
    ])('rejects a site-local address (fec0::/10): %s', (_label, hostname) => {
      expect(isPublicHostname(hostname)).toBe(false);
    });

    test.each<[string, string]>([
      ['a loopback IPv4 address', '[::ffff:0:7f00:1]'],
      ['a 10/8 IPv4 address', '[::ffff:0:a00:1]'],
      ['the cloud metadata address', '[::ffff:0:a9fe:a9fe]'],
      ['a private IPv4 address in the dotted form', '[::ffff:0:192.168.0.1]'],
      ['a loopback IPv4 address written in full', '[0:0:0:0:ffff:0:7f00:1]'],
      ['the unspecified IPv4 address', '[::ffff:0:0:0]'],
    ])('rejects an IPv4-translated address (::ffff:0:0:0/96) with %s', (_label, hostname) => {
      expect(isPublicHostname(hostname)).toBe(false);
    });

    test.each<[string, string]>([
      ['a loopback IPv4 address', '[64:ff9b:1::7f00:1]'],
      ['the cloud metadata address', '[64:ff9b:1::a9fe:a9fe]'],
      ['a private IPv4 address in the dotted form', '[64:ff9b:1::192.168.0.1]'],
      ['a 10/8 IPv4 address written in full', '[64:ff9b:1:0:0:0:a00:1]'],
    ])('rejects a local-use NAT64 address (64:ff9b:1::/48) with %s', (_label, hostname) => {
      expect(isPublicHostname(hostname)).toBe(false);
    });

    test.each<[string, string]>([
      ['a global unicast address', '[2606:4700::1]'],
      ['a public DNS server', '[2001:4860:4860::8888]'],
      ['an address just below the unique local range', '[fbff::1]'],
      ['an address just above the unique local range', '[fe00::1]'],
      ['an address just below the link-local range', '[fe7f::1]'],
      ['a public IPv4 address mapped in the dotted form', '[::ffff:8.8.8.8]'],
      ['a public IPv4 address mapped in the hex form', '[::ffff:808:808]'],
      ['a public IPv4-compatible address', '[::808:808]'],
      ['a public NAT64 address', '[64:ff9b::808:808]'],
      ['a public 6to4 address', '[2002:808:808::]'],
      ['an address next to the mapped range', '[::fffe:7f00:1]'],
      ['an address next to the NAT64 prefix', '[64:ff9a::7f00:1]'],
      ['an address next to the 6to4 prefix', '[2003:7f00:1::]'],
      ['an address whose first group is not zero', '[1::7f00:1]'],
      ['a public IPv4 address, translated', '[::ffff:0:808:808]'],
      ['an address next to the IPv4-translated range, with a 1 in the group after ffff', '[::ffff:1:7f00:1]'],
      ['an address next to the IPv4-translated range, with a 1 in the fourth group', '[0:0:0:1:ffff:0:7f00:1]'],
      ['a public IPv4 address in a local-use NAT64 address', '[64:ff9b:1::808:808]'],
      ['an address next to the local-use NAT64 prefix', '[64:ff9b:2::7f00:1]'],
      ['an address in the NAT64 space outside the local-use prefix', '[64:ff9b:0:1::7f00:1]'],
      ['an address next to the local-use NAT64 prefix, with another first group', '[65:ff9b:1::7f00:1]'],
    ])('accepts %s', (_label, hostname) => {
      expect(isPublicHostname(hostname)).toBe(true);
    });

    test.each<[string, string]>([
      ['a missing closing bracket', '[::1'],
      ['a missing opening bracket', '::1]'],
      ['three colons', '[:::1]'],
      ['two compressions', '[1::2::3]'],
      ['a group with five digits', '[12345::1]'],
      ['a group that is not hex', '[::g]'],
      ['seven groups and no compression', '[1:2:3:4:5:6:7]'],
      ['nine groups', '[1:2:3:4:5:6:7:8:9]'],
      ['eight groups and a compression', '[1:2:3:4:5:6:7:8::]'],
      ['a zone id', '[fe80::1%eth0]'],
      ['a dotted tail with a leading zero', '[::ffff:01.2.3.4]'],
      ['a dotted tail with three parts', '[::1.2.3]'],
      ['a dotted part in the middle', '[::1.2.3.4:5]'],
      ['an IPv4 address inside brackets', '[1.2.3.4]'],
      ['empty brackets', '[]'],
      ['a host with a port', 'localhost:3000'],
    ])('refuses %s, because it cannot be read', (_label, hostname) => {
      expect(isPublicHostname(hostname)).toBe(false);
    });

    test.each<[string, string]>([
      ['an IPv4-mapped address', 'https://[::ffff:192.168.0.1]/x'],
      ['an IPv4-compatible address', 'https://[::127.0.0.1]/x'],
      ['a NAT64 address', 'https://[64:ff9b::192.168.0.1]/x'],
      ['a loopback address written in full', 'https://[0:0:0:0:0:0:0:1]/x'],
      ['a site-local address', 'https://[fec0::1]/x'],
      ['an IPv4-translated address', 'https://[::ffff:0:127.0.0.1]/x'],
      ['an IPv4-translated address in the hex form', 'https://[::ffff:0:7f00:1]/x'],
      ['a local-use NAT64 address', 'https://[64:ff9b:1::127.0.0.1]/x'],
      ['a local-use NAT64 address in the hex form', 'https://[64:ff9b:1::7f00:1]/x'],
    ])('rejects the hostname of a URL with %s', (_label, url) => {
      expect(isPublicHostname(hostnameOf(url))).toBe(false);
    });
  });
});

describe('sameHostname', () => {
  test.each<[string, string, string, boolean]>([
    ['the same host with a different port and path', 'https://a.example/x', 'https://a.example:8443/y', true],
    ['the same host in a different case', 'https://A.example/x', 'https://a.example/x', true],
    ['a different subdomain', 'https://a.example/x', 'https://b.a.example/x', false],
    ['the parent domain', 'https://b.a.example/x', 'https://a.example/x', false],
    ['a sibling subdomain', 'https://b.example.com/x', 'https://c.example.com/x', false],
    ['another domain', 'https://a.example/x', 'https://evil.example/x', false],
    ['a host that starts with the same name', 'https://a.example/x', 'https://a.example.evil.example/x', false],
    ['a host that ends with the same name', 'https://a.example/x', 'https://xa.example/x', false],
    ['a host with a trailing dot', 'https://a.example/x', 'https://a.example./x', false],
    ['credentials that look like the host', 'https://a.example/x', 'https://a.example@evil.example/x', false],
  ])('compares %s', (_label, a, b, expected) => {
    expect(sameHostname(a, b)).toBe(expected);
    expect(sameHostname(b, a)).toBe(expected);
  });

  test.each<[string, string, string]>([
    ['the first value', 'not a url', 'https://a.example/'],
    ['the second value', 'https://a.example/', ''],
    ['both values', '', ''],
  ])('is false when %s cannot be parsed', (_label, a, b) => {
    expect(sameHostname(a, b)).toBe(false);
  });
});

describe('parseUrl', () => {
  test('returns the URL, or undefined when the text is not one', () => {
    expect(parseUrl('https://a.example/x')?.hostname).toBe('a.example');
    expect(parseUrl('not a url')).toBeUndefined();
    expect(parseUrl('')).toBeUndefined();
  });
});
