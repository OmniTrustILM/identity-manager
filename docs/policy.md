# Policy

An organization can fix settings of Identity Manager from the system. A setting fixed this way is called managed:
the person sees its value but cannot change it.

## Settings

| Name           | Type                         | Default | Meaning                                                           |
|----------------|------------------------------|---------|-------------------------------------------------------------------|
| `StartAtLogin` | boolean                      | `true`  | Start Identity Manager when the person signs in.                  |
| `LogLevel`     | string: `error`, `warn`, `info`, `debug` | `info`  | How much the application writes to its log.                       |
| `IlmUrl`       | string                       | none    | The address of your ILM, for example `https://ilm.example.com`. HTTPS only; a path is allowed, a trailing slash, query, fragment or user name is not. |
| `SignInProvider` | string                     | none    | The name of the identity provider to sign in with, as your ILM publishes it. When your ILM does not publish that name, the person chooses. Not shown in Settings. |

How each source stores the types:

| Type    | macOS (property list) | Windows (registry)      | Linux (JSON)      |
|---------|-----------------------|-------------------------|-------------------|
| boolean | `<true/>`, `<false/>` | `REG_DWORD` `1` or `0`  | `true`, `false`   |
| string  | `<string>`            | `REG_SZ`                | string            |

## Sources

| System  | Source                                                                  |
|---------|-------------------------------------------------------------------------|
| macOS   | `/Library/Managed Preferences/com.omnitrust.identity-manager.plist` (device), then `/Library/Managed Preferences/<user>/com.omnitrust.identity-manager.plist` (the signed-in user) |
| Windows | `HKLM\SOFTWARE\Policies\OmniTrustILM\IdentityManager`, then `HKCU\SOFTWARE\Policies\OmniTrustILM\IdentityManager` |
| Linux   | `/etc/identity-manager/policy.json`                                     |

Each key is decided on its own. The machine source wins over the user source, policy wins over the person's choice,
and the person's choice wins over the default. A key that policy does not set stays with the person.

Policy is read whenever settings are read, so a change shows the next time Settings opens.

### Trust

On macOS and Linux a policy file counts only if it is a regular file, owned by root, and neither it nor any folder
above it is writable by group or others or is a symbolic link. Otherwise the whole file is ignored and the application
logs a warning. This keeps a file an ordinary user can write from acting as policy.

### Invalid values

A value of the wrong type, an unknown name, an invalid `LogLevel`, an invalid `IlmUrl` or an empty `SignInProvider` is ignored with a warning in the log. The key stays
unlocked, and the other keys of the same source still apply.

## What the person sees

A managed setting shows its control disabled, a lock icon and the note "Managed by your organization". The core also
refuses a change to a managed setting.

## The person's file

The person's own choices are stored in `settings.json` in the application's configuration folder:

| System  | Path                                                                      |
|---------|---------------------------------------------------------------------------|
| macOS   | `~/Library/Application Support/com.omnitrust.identity-manager/settings.json` |
| Windows | `%APPDATA%\com.omnitrust.identity-manager\settings.json`                  |
| Linux   | `~/.config/com.omnitrust.identity-manager/settings.json`                  |

Its keys are `startAtLogin` (boolean), `logLevel` (string) and `ilmUrl` (string). `SignInProvider` has no key here: only policy sets it.

## Examples

- macOS: [policy/identity-manager.mobileconfig](policy/identity-manager.mobileconfig), a device-scope configuration
  profile whose payload type is the application's preference domain; macOS writes it to the device file above.
- Windows: [policy/identity-manager.reg](policy/identity-manager.reg).
- Linux: [policy/policy.json](policy/policy.json); install it as root:
  `sudo install -d -m 0755 /etc/identity-manager && sudo install -m 0644 policy.json /etc/identity-manager/policy.json`.

All three set `StartAtLogin` to false, `LogLevel` to `debug`, `IlmUrl` to `https://ilm.example.com` and `SignInProvider` to `Corporate`.
