// Writes the HTML reference to docs/ (gitignored) and the Mintlify artifact,
// which is committed for the docs content pipeline to pick up.
//
// The root `npm run docs` also loads this file for the merged monorepo site, so
// don't set `name`: it would rename the package and break the root navigationLinks.
module.exports = {
  entryPoints: ['./src/index.ts'],
  entryPointStrategy: 'resolve',

  out: './docs/',
  json: './mintlify/auth0-api-js.json',
  readme: './README.md',
  cleanOutputDir: true,

  excludePrivate: true,
  excludeProtected: true,
  excludeInternal: true,
  // Without this, every error class inherits Error's `stack`, `captureStackTrace`
  // and `prepareStackTrace` from TypeScript's own lib types. Re-exported errors
  // from `@auth0/auth0-auth-js` are intentionally excluded by the externalPattern.
  excludeExternals: true,
  externalPattern: [
    '**/node_modules/typescript/**',
    '**/node_modules/@types/**'
  ],
  exclude: [
    '**/__tests__/**/*',
    '**/__mocks__/**/*'
  ],

  categorizeByGroup: false,
  // One list for both levels: top-level exports, with the class member groups
  // around them. Categories not listed here land in the `*` slot.
  categoryOrder: [
    'Constructor',
    'Getting Started',
    'Configuration',
    'Token Verification',
    'Token Exchange',
    'Protected Resource',
    'Utilities',
    'Errors',
    'Builder',
    'Actions',
    '*',
    'Other'
  ],
  defaultCategory: 'Other',
  navigation: {
    includeCategories: true,
    includeGroups: false
  },
  sort: ['kind', 'alphabetical'],
  kindSortOrder: [
    'Function',
    'Class',
    'Interface',
    'TypeAlias',
    'Enum',
    'Variable'
  ],

  // Keeps source links stable so regenerating only diffs changed symbols.
  gitRevision: 'main',
  hideGenerator: true,
  searchInComments: true,

  tsconfig: './tsconfig.docs.json'
};
