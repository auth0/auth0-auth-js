// Writes the HTML reference to docs/ (gitignored) and the Mintlify artifact,
// which is committed for the docs content pipeline to pick up.
//
// The root `npm run docs` also loads this file for the merged monorepo site, so
// don't set `name`: it would rename the package and break the root navigationLinks.
module.exports = {
  entryPoints: ['./src/index.ts'],
  entryPointStrategy: 'resolve',

  out: './docs/',
  json: './mintlify/auth0-auth-js.json',
  readme: './README.md',
  cleanOutputDir: true,

  excludePrivate: true,
  excludeProtected: true,
  excludeInternal: true,
  excludeExternals: true,
  externalPattern: ['**/node_modules/typescript/**', '**/node_modules/@types/**'],

  categorizeByGroup: false,
  // One list for both levels: top-level exports, then the AuthClient member groups.
  categoryOrder: [
    'Getting Started',
    'Configuration',
    'Sub-clients',
    'Utilities',
    'Login & Logout',
    'Session',
    'Access Tokens',
    'Token Exchange',
    'Account Linking',
    'Backchannel Authentication',
    'Backchannel Logout',
    'MFA',
    'Passkeys',
    'Passwordless',
    'Database',
    'Anonymous Sessions',
    'Errors',
    '*',
    'Other',
  ],
  defaultCategory: 'Other',
  navigation: {
    includeCategories: true,
    includeGroups: false,
  },
  sort: ['kind', 'alphabetical'],
  kindSortOrder: ['Function', 'Class', 'Interface', 'TypeAlias', 'Enum', 'Variable'],

  // Keeps source links stable so regenerating only diffs changed symbols.
  gitRevision: 'main',
  hideGenerator: true,
  searchInComments: true,
};
