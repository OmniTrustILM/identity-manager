# Policy

An organization can fix settings of Identity Manager from the system. A setting fixed this way is called managed:
the person sees its value but cannot change it.

## Settings

| Name           | Type                         | Default | Meaning                                                           |
|----------------|------------------------------|---------|-------------------------------------------------------------------|
| `StartAtLogin` | boolean                      | `true`  | Start Identity Manager when the person signs in.                  |
| `LogLevel`     | string: `error`, `warn`, `info`, `debug` | `info`  | How much the application writes to its log.                       |
| `IlmUrl`       | string                       | none    | The address of your ILM, for example `https://ilm.example.com`. HTTPS only; a path is allowed, a trailing slash, query, fragment or user name is not. |
| `RequireUnlock` | boolean                    | `true`  | Ask the system to confirm the person after a start with a saved sign-in and after the computer locks. Ignored where the system cannot confirm the person. |
| `LockAfterIdle` | integer, 1 to 1440         | none    | Also lock after this many minutes without input. Without it there is no idle lock. Has an effect only while `RequireUnlock` is on. |
| `CheckInterval` | integer, 5 to 1440         | `15`    | How often, in minutes, Identity Manager checks ILM for changes to the certificates on the computer. In Settings the person chooses 5, 15, 30 or 60 minutes ("Check ILM every"); a managed value shows as it is. |
| `ExpiryWarningDays` | integer, 1 to 365    | `30`    | How many days before a certificate expires Identity Manager marks it as expiring soon and asks for attention. In Settings the person chooses 7, 14, 30, 60 or 90 days ("Warn before expiry"); a managed value shows as it is. |
| `AutomaticRenewal` | string: `off`, `newKey`, `sameKey` | `newKey` | Whether Identity Manager renews the certificates that ILM manages before they expire: not at all, with a new private key each time, or with the key the certificate already has. `off` also turns off the switch of every certificate. In Settings the person chooses Off, New key or Same key ("Automatic renewal"); a managed value shows as it is, and with `newKey` or `sameKey` the person can still switch a single certificate off. See [certificates.md](certificates.md). |
| `SignInProvider` | string                     | none    | The name of the identity provider to sign in with, as your ILM publishes it. When your ILM does not publish that name, the person chooses. Not shown in Settings. |
| `SignInMethod` | string: `oauth`, `certificate` | none    | The way of signing in that your organization allows. `oauth` offers only the identity providers; `certificate` offers only a certificate on the computer. Without it both are offered. Not shown in Settings. |
| `KeyStorages` | string: a comma-separated list of `keychain`, `software`, `tpm` | none    | The places on the computer where a new certificate request may create its private key. Without it every place the computer offers is offered. Unknown names are ignored; a value that names no known place allows none, and the person cannot create a key. Not shown in Settings. |
| `DefaultKeyStorage` | string: `keychain`, `software`, `tpm` | none    | The place preselected for a new key. When it is missing or not offered, the first offered place is preselected. Also the place for every key enrolment creates, see "Enrolment". Not shown in Settings. |
| `CompletePrepared` | boolean | `false` | Complete by itself every certificate an administrator prepared for the person in ILM, except one whose registration asks for a challenge. See "Enrolment". Not shown in Settings. |
| `RequestProfiles` | string: RA Profile names separated by commas | none | The RA Profiles to request a certificate from, once for each person and computer. A name must match exactly the name ILM lists for the person; spaces around a name and empty items are ignored. See "Enrolment". Not shown in Settings. |
| `SignInCertificateProfile` | string: one RA Profile name | none | The certificate that enrolment installs from this RA Profile becomes the person's sign-in certificate. See [sign-in.md](sign-in.md). Not shown in Settings. |

How each source stores the types:

| Type    | macOS (property list) | Windows (registry)      | Linux (JSON)      |
|---------|-----------------------|-------------------------|-------------------|
| boolean | `<true/>`, `<false/>` | `REG_DWORD` `1` or `0`  | `true`, `false`   |
| integer | `<integer>`           | `REG_DWORD`             | number            |
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

A value of the wrong type, an unknown name, an invalid `LogLevel`, an invalid `IlmUrl`, an invalid `SignInMethod`, an invalid `DefaultKeyStorage`, an invalid `AutomaticRenewal`, a `CompletePrepared` that is not a boolean, a `RequestProfiles` or `SignInCertificateProfile` that is not a string, a `LockAfterIdle` outside 1 to 1440, a `CheckInterval` outside 5 to 1440, an `ExpiryWarningDays` outside 1 to 365 or an empty `SignInProvider` is ignored with a warning in the log. The key stays
unlocked, and the other keys of the same source still apply.

## Enrolment

`CompletePrepared`, `RequestProfiles` and `SignInCertificateProfile` let your organization have certificates made
for the person without their asking. They are read only from policy: Settings does not show them and the person cannot
change them. They are used after the person has signed in, on macOS and Windows, never on Linux.

- `CompletePrepared` completes every open certificate that an administrator prepared for the person in ILM, unless its
  registration asks for a challenge. The challenge always stays with the person.
- `RequestProfiles` names the RA Profiles to request from, for example `Workstation, Email`. Each is requested once
  for each person and computer. A name that ILM does not list for the person is skipped and logged.
- `SignInCertificateProfile` names the RA Profile whose certificate becomes the sign-in certificate.

`KeyStorages` and `DefaultKeyStorage` choose where the key of everything enrolment creates is made: the default
storage when it is allowed, otherwise the first allowed one. When the policy leaves no storage, nothing is enrolled.
The key type is EC P-256 when that storage offers it, otherwise the first type it offers.

What enrolment does and what stays with the person is in [certificates.md](certificates.md), and the sign-in
certificate in [sign-in.md](sign-in.md).

## A managed first run

A contractor receives a Mac that the organization manages. The configuration profile below sets the ILM address and
the identity provider, completes the certificates prepared for the contractor, makes the certificate from the RA
Profile `Contractor sign-in` the sign-in certificate, and keeps the keys in the keychain. `RequestProfiles` is not
needed here; add it, for example `"Workstation"`, to request from more RA Profiles.

```xml
<key>IlmUrl</key>
<string>https://ilm.example.com</string>
<key>SignInProvider</key>
<string>Corporate</string>
<key>CompletePrepared</key>
<true/>
<key>SignInCertificateProfile</key>
<string>Contractor sign-in</string>
<key>DefaultKeyStorage</key>
<string>keychain</string>
```

These keys go in the same payload as in [policy/identity-manager.mobileconfig](policy/identity-manager.mobileconfig).
Do not set `SignInMethod` to `oauth`: the sign-in certificate is not set then. On Windows the same keys and values
go in the registry, with `DefaultKeyStorage` set to `software` or `tpm`; enrolment does nothing on Linux.

Then the contractor opens Identity Manager and sees the ILM address already set, chooses Sign in and signs in with
`Corporate`. At the first check after signing in:

1. The certificates prepared for the contractor without a challenge are completed and installed, and "Your
   certificate is ready" is shown for each.
2. When the certificate from `Contractor sign-in` is installed, it becomes the sign-in certificate.
3. Anything that needs the contractor, such as a form with a value to choose or a challenge, waits in Requests.

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

Its keys are `startAtLogin` (boolean), `logLevel` (string), `ilmUrl` (string), `requireUnlock` (boolean), `lockAfterIdle` (number of minutes), `checkEvery` (number of minutes) and `warnDays` (number of days) and `automaticRenewal` (string). `SignInProvider`, `SignInMethod`, `KeyStorages`, `DefaultKeyStorage`, `CompletePrepared`, `RequestProfiles` and `SignInCertificateProfile` have no key here: only policy sets them. The file also keeps `signInCertificate`, the ILM address and the fingerprint of the certificate last used to sign in there; it is used only while that address is the ILM address.

## Examples

- macOS: [policy/identity-manager.mobileconfig](policy/identity-manager.mobileconfig), a device-scope configuration
  profile whose payload type is the application's preference domain; macOS writes it to the device file above.
- Windows: [policy/identity-manager.reg](policy/identity-manager.reg).
- Linux: [policy/policy.json](policy/policy.json); install it as root:
  `sudo install -d -m 0755 /etc/identity-manager && sudo install -m 0644 policy.json /etc/identity-manager/policy.json`.

All three set `StartAtLogin` to false, `LogLevel` to `debug`, `IlmUrl` to `https://ilm.example.com`, `RequireUnlock` to true, `LockAfterIdle` to 15, `CheckInterval` to 30, `ExpiryWarningDays` to 30, `AutomaticRenewal` to `newKey`, `SignInProvider` to `Corporate`, `SignInMethod` to `oauth`, `KeyStorages` to `software,tpm`, `DefaultKeyStorage` to `software`, `CompletePrepared` to true, `RequestProfiles` to `Workstation, Email` and `SignInCertificateProfile` to `Workstation`, except the macOS profile, which sets both storages to `keychain`, the only storage macOS offers. The example keeps `SignInMethod` at `oauth`, so it sets no sign-in certificate; remove that key to use `SignInCertificateProfile`.
