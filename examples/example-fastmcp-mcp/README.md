# Example FastMCP MCP Server with Auth0 Integration

This is a practical example of securing a [Model Context Protocol (MCP)](https://modelcontextprotocol.io/docs) server
with Auth0 authentication using the [FastMCP](https://github.com/punkpeye/fastmcp) TypeScript framework. It demonstrates
real-world OAuth 2.0 and OIDC integration with JWT token verification and scope enforcement.

## Install dependencies

Install the dependencies using npm:

```bash
npm install
```

## Configuration

Rename `.env.example` to `.env` and configure the domain and audience:

```ts
AUTH0_DOMAIN = YOUR_AUTH0_DOMAIN;
AUTH0_AUDIENCE = YOUR_AUTH0_AUDIENCE;
```

With the configuration in place, the example can be started by running:

```bash
npm run start
```

## Testing

Use an MCP client like [MCP Inspector](https://github.com/modelcontextprotocol/inspector) to test your server interactively:

```bash
npx @modelcontextprotocol/inspector
```

The server will start up and the UI will be accessible at http://localhost:6274.

In the MCP Inspector, select `Streamable HTTP` as the `Transport Type` and enter `http://localhost:3001/mcp` as the URL.
