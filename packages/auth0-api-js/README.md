The Auth0-API-JS SDK is a library that allows securing API's.

Using this SDK as-is in your API may not be trivial, as it is designed to be used as a building block for building framework-specific SDKs.

![Release](https://img.shields.io/npm/v/@auth0/auth0-api-js)
![Downloads](https://img.shields.io/npm/dw/@auth0/auth0-api-js)
[![License](https://img.shields.io/:license-mit-blue.svg?style=flat)](https://opensource.org/licenses/MIT)

📚 [Documentation](#documentation) - 🚀 [Getting Started](#getting-started) - 💬 [Feedback](#feedback)

## Documentation

- [Examples](https://github.com/auth0/auth0-server-js/blob/main/packages/auth0-api-js/EXAMPLES.md) - examples for your different use cases.
- [Docs Site](https://auth0.com/docs) - explore our docs site and learn more about Auth0.

## Getting Started

### 1. Install the SDK

```shell
npm i @auth0/auth0-api-js
```

This library requires Node.js 20 LTS and newer LTS versions.

### 2. Create the Auth0 SDK client

Create an instance of the `ApiClient`. This instance will be imported and used anywhere we need access to the methods.


```ts
import { ApiClient } from '@auth0/auth0-api-js';

const apiClient = new apiClient({
  domain: '<AUTH0_DOMAIN>',
  audience: '<AUTH0_AUDIENCE>',
});
```

The `AUTH0_DOMAIN` can be obtained from the [Auth0 Dashboard](https://manage.auth0.com) once you've created an application.
The `AUTH0_AUDIENCE` is the identifier of the API. You can find this in the API section of the Auth0 dashboard.

### 3. Verify the Access Token

The SDK's `verifyAccessToken` method can be used to verify the access token.

```ts
const apiClient = new apiClient({
  domain: '<AUTH0_DOMAIN>',
  audience: '<AUTH0_AUDIENCE>',
});

const accessToken = '...';
const decodedAndVerfiedToken = await apiClient.verifyAccessToken({
  accessToken
});
```

Even thought the SDK automatically validates claims like `iss`, `aud`, `exp`, and `nbf`, you can also pass additional claims to be required:
Additionally, `requiredClaims` can be conf

```ts
const apiClient = new apiClient({
  domain: '<AUTH0_DOMAIN>',
  audience: '<AUTH0_AUDIENCE>',
});

const accessToken = '...';
const decodedAndVerfiedToken = await apiClient.verifyAccessToken({
  accessToken,
  requiredClaims: ['my_custom_claim']
});
```

### 4. More Examples

A full overview of examples can be found in [EXAMPLES.md](./EXAMPLES.md).

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
  This project is licensed under the MIT license. See the <a href="https://github.com/auth0/auth0-server-js/blob/main/packages/auth0-auth-js/LICENSE"> LICENSE</a> file for more info.
</p>
