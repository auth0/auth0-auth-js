Auth0-Auth-JS Mono Repo, containing SDKs for implementing user authentication in JavaScript applications.

![Release](https://img.shields.io/npm/v/@auth0/auth0-auth-js)
![Downloads](https://img.shields.io/npm/dw/@auth0/auth0-auth-js)
[![License](https://img.shields.io/:license-mit-blue.svg?style=flat)](https://opensource.org/licenses/MIT)
[<img src="https://devin.ai/assets/deepwiki-badge.png" alt="Ask questions about auth0-mcp-server on DeepWiki" height="20"/>](https://deepwiki.com/auth0/auth0-auth-js)

📚 [Packages](#packages) - 💬 [Feedback](#feedback)


## Packages
- [`auth0-auth-js`](./packages/auth0-auth-js/README.md) - Authentication Client for JavaScript runtimes.
- [`auth0-api-js`](./packages/auth0-api-js/README.md) - Authentication SDK for API's on JavaScript runtimes.
- [`auth0-server-js`](./packages/auth0-server-js/README.md) - Authentication SDK for Server-Side Applications on JavaScript runtimes.

## Running Examples

The following examples can be found in the examples directory:

- [Fastify Web App Example](./examples/example-fastify-web/README.md)
- [Fastify API Example](./examples/example-fastify-api/README.md)
- [NestJS API Example](./examples/example-nestjs-api/README.md)
- [Express Web App Example](./examples/example-express-web/README.md)

Before running the examples, you need to install the dependencies for the monorepo and build all the packages.

1. Install depedencies
```bash
$ npm install
```

2. Build all packages
```bash
$ npm run build
```

3. Follow example instructions

## Feedback

### Contributing

We appreciate feedback and contribution to this repo! Before you get started, please read the following:

- [Auth0's general contribution guidelines](https://github.com/auth0/open-source-template/blob/master/GENERAL-CONTRIBUTING.md)
- [Auth0's code of conduct guidelines](https://github.com/auth0/open-source-template/blob/master/CODE-OF-CONDUCT.md)

### Raise an issue

To provide feedback or report a bug, please [raise an issue on our issue tracker](https://github.com/auth0/auth0-auth-js/issues).

## Vulnerability Reporting

Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/responsible-disclosure-policy) details the procedure for disclosing security issues.

## What is Auth0?

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://cdn.auth0.com/website/sdks/logos/auth0_dark_mode.png" width="150">
    <source media="(prefers-color-scheme: light)" srcset="https://cdn.auth0.com/website/sdks/logos/auth0_light_mode.png" width="150">
    <img alt="Auth0 Logo" src="https://cdn.auth0.com/website/sdks/logos/auth0_light_mode.png" width="150">
  </picture>
</p>
<p align="center">
  Auth0 is an easy to implement, adaptable authentication and authorization platform. To learn more checkout <a href="https://auth0.com/why-auth0">Why Auth0?</a>
</p>
