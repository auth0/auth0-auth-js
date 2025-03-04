The Auth0-Auth-JS Mono Repo, containing SDKs for implementing user authentication in JavaScript applications.

![Release](https://img.shields.io/npm/v/@auth0/auth0-auth-js)
![Downloads](https://img.shields.io/npm/dw/@auth0/auth0-auth-js)
[![License](https://img.shields.io/:license-mit-blue.svg?style=flat)](https://opensource.org/licenses/MIT)

📚 [Testing](#testing) - 💬 [Feedback](#feedback)


## Testing

In order to test the SDK in a project outside of this repository, you can use the following steps:

- git clone this repository
- run `npm install` in the root of the repository
- run `npm run build --workspaces` in the root of the repository
- run `npm pack --workspaces` in the root of the repository

This creates the following three files:
- `packages/auth0-auth-js/auth0-auth0-auth-js-<version>.tgz`
- `packages/auth0-server-js/auth0-auth0-server-js-<version>.tgz`
- `packages/auth0-fastify/auth0-auth0-fastify-<version>.tgz`

The above tarballs can be installed in your project using `npm install <path-to-tarball>`.
For example, `npm install ../path/to/repo/packages/auth0-auth-js/auth0-auth-js-<version>.tgz`.

Note that, if you need to use `auth0-server-js`, you also need to install the tarbal for `auth0-auth-js` as `auth0-server-js` depends on `auth0-auth-js`.
Same goes for `auth0-fastify` which depends on `auth0-server-js`, meaning when you need to install `auth0-fastify`, you also need to install `auth0-server-js` and `auth0-auth-js`.
If all you need is `auth0-auth-js`, you can just install that tarball.

> WARNING: The tarballs are not meant for production use. They are meant for testing purposes only.

## Feedback

### Contributing

We appreciate feedback and contribution to this repo! Before you get started, please read the following:

- [Auth0's general contribution guidelines](https://github.com/auth0/open-source-template/blob/master/GENERAL-CONTRIBUTING.md)
- [Auth0's code of conduct guidelines](https://github.com/auth0/auth0-server-js/blob/main/CODE-OF-CONDUCT.md)
- [This repo's contribution guide](./CONTRIBUTING.md)

### Raise an issue

To provide feedback or report a bug, please [raise an issue on our issue tracker](https://github.com/auth0/auth0-server-js/issues).

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
<p align="center">
  This project is licensed under the MIT license. See the <a href="https://github.com/auth0/auth0-server-js/blob/main/packages/auth0-fastify/LICENSE"> LICENSE</a> file for more info.
</p>
