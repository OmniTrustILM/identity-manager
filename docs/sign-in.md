# Signing in

Identity Manager learns how to sign in from your ILM. The person gives only the address of the ILM (or your
organization sets it with the `IlmUrl` policy key, see [policy.md](policy.md)). No identity provider, client ID or
scope is built into the application or set by policy. This guide is for the administrator of the ILM and of the
identity provider.

Identity Manager works with any OAuth 2 or OpenID Connect provider that follows the standards below. No provider is
treated specially.

## What ILM publishes

ILM publishes its OAuth Protected Resource Metadata ([RFC 9728](https://www.rfc-editor.org/rfc/rfc9728)) without
authentication at:

```text
{ilm}/.well-known/oauth-protected-resource/api
```

where `{ilm}` is the address of the ILM, for example `https://ilm.example.com`. ILM also answers a request to its API
without a token with status 401 and the header `WWW-Authenticate: Bearer resource_metadata="<that address>"`.

The document lists the identity providers that are switched on for applications in ILM's OAuth provider settings.
Providers meant for workloads are not listed. An example (also in
[oauth/resource-metadata.example.json](oauth/resource-metadata.example.json)):

```json
{
  "resource": "https://ilm.example.com/api",
  "resource_name": "OmniTrust ILM",
  "authorization_servers": ["https://login.example.com/realms/main"],
  "bearer_methods_supported": ["header"],
  "otilm_authorization_servers": [
    {
      "issuer": "https://login.example.com/realms/main",
      "name": "Company sign-in",
      "client_id": "identity-manager",
      "scopes": ["openid", "profile", "email", "offline_access"],
      "resource": "https://ilm.example.com/api"
    }
  ]
}
```

| Field                         | Meaning                                                                          |
|-------------------------------|----------------------------------------------------------------------------------|
| `resource`                    | The ILM API, `{ilm}/api`. Identity Manager refuses the document if it differs.   |
| `authorization_servers`       | The issuers of the providers switched on for applications.                       |
| `bearer_methods_supported`    | `["header"]`: the access token goes in the `Authorization` header.               |
| `otilm_authorization_servers` | One entry per provider; every `issuer` must also be in `authorization_servers`.  |
| `issuer`                      | The issuer of the provider.                                                      |
| `name`                        | The name shown to people when they choose a provider.                            |
| `client_id`                   | Optional. The client ID of the public client registered at the provider.         |
| `scopes`                      | The scopes Identity Manager asks for, as given.                                  |
| `resource`                    | Optional. Sent as the `resource` parameter ([RFC 8707](https://www.rfc-editor.org/rfc/rfc8707)). |

### Check it

```bash
curl -i https://ilm.example.com/.well-known/oauth-protected-resource/api
```

The answer must be status 200 with a JSON document like the one above. Check the header of the 401 answer too:

```bash
curl -i https://ilm.example.com/api/v1/auth/profile
```

It must be status 401 with a `WWW-Authenticate: Bearer resource_metadata="https://ilm.example.com/.well-known/oauth-protected-resource/api"`
header. If your ILM does not send the header, Identity Manager tries the address above on its own. If it publishes
neither, Identity Manager says that this ILM does not publish how to sign in and names the address it tried.

## What the identity provider needs

Identity Manager is a public client: it keeps no client secret. The provider needs:

- A public client (no client secret) with the authorization code flow and PKCE with the `S256` method.
- The redirect URI `http://127.0.0.1/callback`, accepted on any port. Identity Manager listens on `127.0.0.1` on a
  free port for one answer during sign-in. A provider that compares the port exactly cannot be used.
- Refresh tokens, with rotation if the provider offers it. Without a refresh token the person signs in again when the
  access token expires. Many providers hand out refresh tokens only for a scope such as `offline_access`; add it to
  the scopes published by ILM.
- An access token that ILM accepts: an audience or scope that ILM checks, and the same value in the `audiences` of
  ILM's provider settings.
- A discovery document at `{issuer}/.well-known/openid-configuration` or
  `{issuer}/.well-known/oauth-authorization-server` ([RFC 8414](https://www.rfc-editor.org/rfc/rfc8414)). Its
  `issuer` must equal the issuer ILM publishes, and it must have `authorization_endpoint` and `token_endpoint`. If it
  lists `code_challenge_methods_supported`, that list must include `S256`.

## Set it up

1. In the identity provider, register a public client as described above, or skip this step if the provider supports
   Client ID Metadata Documents (see below).
2. In ILM, open the OAuth provider settings, add or edit the provider and switch it on for applications. Enter the
   client ID, the scopes, and the audience. The exact field names depend on your ILM version, see its documentation.
3. Check the document with `curl` as shown above.
4. Start Identity Manager, enter the ILM address and sign in.

### Without registering a client

If the provider's discovery document has `client_id_metadata_document_supported` set to `true`, you do not have to
register a client. Leave the client ID empty in ILM; Identity Manager then uses the address of its own Client ID
Metadata Document as the client ID:

```text
https://omnitrustilm.github.io/identity-manager/oauth/client-metadata.json
```

The provider fetches that document to learn the redirect URI and the client type. Its content is in
[oauth/client-metadata.json](oauth/client-metadata.json). A provider that supports this must also accept the
loopback redirect on any port; check that with your provider. If the provider does not support the feature and ILM
publishes no client ID, Identity Manager cannot use that provider.

## Examples

The examples below show the idea only. The names of settings change between versions of the providers; check their
documentation. They are not tested against every version.

### Example: Keycloak

1. In the realm, create a client with client type OpenID Connect and the client ID `identity-manager`.
2. Turn client authentication off, so that the client is public. Keep the standard flow on, and turn the other flows
   off.
3. Under advanced settings, set Proof Key for Code Exchange Code Challenge Method to `S256`.
4. Set the valid redirect URIs to `http://127.0.0.1/*`. Keycloak allows a wildcard only at the end of a redirect URI,
   so this covers `/callback` on any port. Check how your version treats the port of a loopback address.
5. Make the access token carry an audience that ILM accepts, for example with an audience mapper on a client scope,
   and use that value as the audience in ILM.
6. For refresh token rotation, turn on Revoke Refresh Token in the realm's token settings. The scope
   `offline_access` makes Keycloak issue an offline refresh token.
7. In ILM enter the issuer (`https://login.example.com/realms/main`), the client ID `identity-manager` and the scopes
   `openid profile email offline_access`.

### Example: Microsoft Entra ID

1. Register an application. Under authentication, add the platform "Mobile and desktop applications" with the
   redirect URI `http://127.0.0.1`, and allow public client flows. Entra ID compares the port of a loopback address
   loosely, but check whether it also wants the path `/callback`.
2. Expose an API on the ILM application registration and add a scope that ILM accepts. Use that scope in the scopes
   given to Identity Manager, in the form `api://<application-id>/<scope-name>`, together with `offline_access`.
3. Use the v2.0 issuer of your tenant, `https://login.microsoftonline.com/<tenant-id>/v2.0`, as the issuer in ILM.
   Check that the `issuer` in the discovery document matches it exactly.
4. In ILM enter the client ID (the application ID of the registration), the scopes and the audience that the access
   token carries.

## What the application stores

After sign-in Identity Manager keeps the refresh token in the protected storage of the system, in one item together
with the ILM address, the issuer and the client ID it belongs to:

| System  | Protected storage                                  |
|---------|----------------------------------------------------|
| macOS   | Keychain                                           |
| Windows | Credential Manager                                 |
| Linux   | Secret Service (for example GNOME Keyring or KWallet) |

The service is `com.omnitrust.identity-manager` and the account is the ILM address. The access token stays in memory
only. Signing out deletes the item and revokes the refresh token when the provider publishes a revocation endpoint.
Changing the ILM address signs out first.

## Policy

The policy keys `IlmUrl` (the address of the ILM) and `SignInProvider` (the name of the provider to use when ILM
publishes several) concern sign-in. See [policy.md](policy.md) for their types, sources and rules.
