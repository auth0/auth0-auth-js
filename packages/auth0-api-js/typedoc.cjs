const {
  CATEGORY_ORDER,
  DEFAULT_CATEGORY
} = require('./scripts/typedoc-plugin.cjs');

module.exports = {
  entryPoints: ['./src/index.ts'],
  entryPointStrategy: 'resolve',

  out: './docs/',
  readme: './README.md',
  name: 'Auth0 API SDK',
  cleanOutputDir: true,

  plugin: ['./scripts/typedoc-plugin.cjs'],

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
  categoryOrder: CATEGORY_ORDER,
  defaultCategory: DEFAULT_CATEGORY,
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

  hideGenerator: true,
  searchInComments: true,

  tsconfig: './tsconfig.json'
};
