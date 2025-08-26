# Example FastMCP MCP Server with Auth0 Integration

This is a practical example of securing a [Model Context Protocol (MCP)](https://modelcontextprotocol.io/docs) server
with Auth0 using the [FastMCP](https://github.com/punkpeye/fastmcp) TypeScript framework. It demonstrates
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

## Auth0 Tenant Setup

### Pre-requisites:

This guide uses [Auth0 CLI](https://auth0.github.io/auth0-cli/) to configure an Auth0 tenant for secure MCP tool access. If you don't have it, you can follow the [Auth0 CLI installation instructions](https://auth0.github.io/auth0-cli/) to set it up.

### Step 1: Authenticate with Auth0 CLI

First, you need to log in to the Auth0 CLI with the correct scopes to manage all the necessary resources.

1. Run the login command: This command will open a browser window for you to authenticate. We are requesting a set of
   scopes to configure APIs, roles, clients, and actions.

```
auth0 login --scopes "read:client_grants,create:client_grants,delete:client_grants,read:clients,create:clients,update:clients,read:resource_servers,create:resource_servers,update:resource_servers,read:roles,create:roles,update:roles,update:tenant_settings,read:connections,update:connections,read:actions,create:actions,update:actions,delete:actions,update:triggers"
```

2. Verify your tenant: After logging in, confirm you are operating on the tenant you want to configure.

```
auth0 tenants list
```

### Step 2: Configure Tenant Settings

Next, enable tenant-level flags required for Dynamic Client Registration (DCR) and an improved user consent experience.

- `enable_dynamic_client_registration`: Allows MCP tools to register themselves as applications automatically.
  [Learn more](https://auth0.com/docs/get-started/applications/dynamic-client-registration#enable-dynamic-client-registration)
- `use_scope_descriptions_for_consent`: Shows user-friendly descriptions for scopes on the consent screen.
  [Learn more](https://auth0.com/docs/customize/login-pages/customize-consent-prompts).

Execute the following command to enable the above mentioned flags through the tenant settings:

```
auth0 tenant-settings update set flags.enable_dynamic_client_registration flags.use_scope_descriptions_for_consent
```

### Step 3: Promote Connections to Domain Level

[Learn more](https://auth0.com/docs/authenticate/identity-providers/promote-connections-to-domain-level) about promoting
connections to domain level.

1. List your connections to get their IDs: `auth0 api get connections`
2. From the list, identify only the connections that should be available to be used with third party applications. For each of those specific connection IDs, run the following command to mark it as a domain-level connection. Replace `YOUR_CONNECTION_ID` with the actual ID (e.g., `con_XXXXXXXXXXXXXXXX`)

```
auth0 api patch connections/YOUR_CONNECTION_ID --data '{"is_domain_connection": true}'
```

### Step 4: Configure the API and Default Audience

This step creates the API (also known as a Resource Server) that represents your protected MCP Server and sets it as the
default for your tenant.

1. Create the API: This command registers the API with Auth0, defines its signing algorithm, enables Role-Based Access
   Control (RBAC), and specifies the available scopes. Replace `http://localhost:3001` and `MCP Tools API`
   with your desired identifier and name. Add your tool-specific scopes to the scopes array.

   Note that `rfc9068_profile_authz` is used instead of `rfc9068_profile` as the token dialect to enable RBAC. [Learn more](https://auth0.com/docs/get-started/apis/enable-role-based-access-control-for-apis#token-dialect-options)

```
auth0 api post resource-servers --data '{
  "identifier": "http://localhost:3001",
  "name": "MCP Tools API",
  "signing_alg": "RS256",
  "token_dialect": "rfc9068_profile_authz",
  "enforce_policies": true,
  "scopes": [
    {"value": "tool:whoami", "description": "Access the WhoAmI tool"},
    {"value": "tool:greet", "description": "Access the Greeting tool"}
  ]
}'

```

2. Set the Default Audience: This ensures that users logging in interactively get access tokens that are valid for your
   newly created MCP Server. Replace `http://localhost:3001` with the same API identifier you used above.

   **Note:** This step is currently required but temporary. Without setting a default audience, the issued access tokens will not be scoped specifically to your MCP resource server. Support for RFC 8707 (Resource Indicators for OAuth 2.0) is coming soon, which will provide proper resource targeting. Once available, these instructions will be updated to use `resource_parameter_profile: "compatibility"` instead of the default audience approach.

```
auth0 api patch "tenants/settings" --data '{"default_audience": "http://localhost:3001"}'
```

### Step 5: Configure RBAC Roles and Permissions

Now, set up roles and assign permissions to them. This allows you to control which users can access which tools.

1. Create Roles: For each role you need (e.g., "Tool Administrator", "Tool User"), run the create command.

```
# Example for an admin role
auth0 roles create --name "Tool Administrator" --description "Grants access to all MCP tools"

# Example for a basic user role
auth0 roles create --name "Tool User" --description "Grants access to basic MCP tools"
```

2. Assign Permissions to Roles: After creating roles, note the ID from the output (e.g. `rol_`) and and assign the API
   permissions to it. Replace `YOUR_ROLE_ID`, `http://localhost:3001`, and the list of scopes.

```
# Example for admin role (all scopes)
auth0 roles permissions add YOUR_ADMIN_ROLE_ID --api-id "http://localhost:3001" --permissions "tool:whoami,tool:greet"

# Example for user role (one scope)
auth0 roles permissions add YOUR_USER_ROLE_ID --api-id "http://localhost:3001" --permissions "tool:whoami"
```

3. Assign Roles to Users: Find users and assign them to the roles.

```
# Find a user's ID
auth0 users search --query "email:\"example@google.com\""

# Assign the role using the user's ID and the role's ID
auth0 users roles assign "auth0|USER_ID_HERE" --roles "YOUR_ROLE_ID_HERE"
```

### Step 6: Configure and Deploy the Scope-Injection Action

This Auth0 Action will automatically add the correct scope claim to a user's access token based on the permissions
granted by their assigned roles.

1. Create the Action Code: Save the following JavaScript code to a file named `mcp-action.js`. Replace
   `http://localhost:3001` with your API identifier and update the `ROLE_SCOPES_MAPPING` with your specific roles and
   their associated scopes.

```
/**
 * Auth0 Action: Inject MCP Scopes
 *
 * This Action injects MCP tool scopes into access tokens based on user roles.
 * Only runs for tokens issued to the MCP API audience.
 *
 * This Action bridges Auth0's RBAC system with OAuth 2.0 scopes for
 * interactive authentication flows. It ensures that users with MCP
 * roles receive tokens with appropriate tool access permissions.
 *
 */
exports.onExecutePostLogin = async (event, api) => {
  // IMPORTANT: Verify the configuration values below match your setup from the previous steps
  const targetAudience = 'http://localhost:3001';
  const roleToScopesMapping = {"Tool User":["tool:whoami"],"Tool Administrator":["tool:whoami","tool:greet"]};

  // Debug configuration - enabled only when the secret is set to 'true'
  const DEBUG_ENABLED = event.secrets?.DEBUG_ENABLED === 'true';

  // Safe debug logger that avoids logging secrets
  const debug = (message) => {
    if (DEBUG_ENABLED) {
      console.log(message);
    }
  };

  const actualAudience = event.resource_server?.identifier;

  // Debug: Log initial state - carefully avoiding sensitive data
  debug(' --------- MCP SCOPES ACTION START ---------');
  debug(` Target audience: ${targetAudience}`);
  debug(` Actual audience: ${actualAudience || 'undefined'}`);
  debug(` Available roles in mapping: ${Object.keys(roleToScopesMapping).join(', ')}`);

  const roles = event.authorization?.roles || [];
  debug(` User has ${roles.length} roles`);

  // Only process tokens intended for the MCP API
  if (actualAudience === targetAudience) {
    debug(' AUDIENCE MATCHED! Processing scopes...');

    if (roles.length === 0) {
      debug('  WARNING: User has no roles assigned');
    }

    let addedScopesCount = 0;

    // Iterate through user roles and add corresponding scopes
    for (const roleName of roles) {
      debug(` Processing role #${roles.indexOf(roleName) + 1}/${roles.length}`);

      if (roleToScopesMapping[roleName]) {
        const scopes = roleToScopesMapping[roleName];
        debug(`    Found ${scopes.length} scopes for this role`);

        for (const scope of scopes) {
          debug(`    Adding scope #${scopes.indexOf(scope) + 1}`);
          api.accessToken.addScope(scope);
          addedScopesCount++;
        }
      } else {
        debug(`    No scopes defined for this role`);
      }
    }

    debug(`SUCCESS: Added ${addedScopesCount} scopes to the token`);
  } else {
    debug('AUDIENCE MISMATCH! Skipping scope injection.');
    debug(`Expected "${targetAudience}" but got "${actualAudience || 'undefined'}"`);
  }

  debug('--------- MCP SCOPES ACTION COMPLETE ---------');
};
```

2. Create and Deploy the Action: Use the CLI to create the action from your file and deploy it.

```
# Create the action (this will output the action's ID)
auth0 actions create --name "Inject MCP Scopes" --trigger post-login --code "$(cat mcp-actions.js)" --no-input --json

# Deploy the action using its ID
auth0 actions deploy YOUR_ACTION_ID_HERE
```

3. Bind the Action: Attach the deployed action to the "Post Login" trigger so it runs every time a user logs in.

```
auth0 api patch "actions/triggers/post-login/bindings" --data '{"bindings": [{"ref": {"type": "action_id", "value": "YOUR_ACTION_ID_HERE"}, "display_name": "Inject MCP Scopes"}]}'
```
