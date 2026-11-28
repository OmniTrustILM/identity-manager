# Deployment

This guide is for the administrator who installs Identity Manager on many computers and sets it up for the people who
use them. A person who installs it on their own computer reads [install.md](install.md).

## What you deploy

| System  | Package                                    | Installed by                      | Settings by                    |
|---------|--------------------------------------------|-----------------------------------|--------------------------------|
| Windows | `Identity-Manager_<version>_x64_en-US.msi` | `msiexec`, Intune or another tool | MSI properties or Group Policy |
| macOS   | `Identity-Manager_<version>_aarch64.dmg`   | By hand                           | Configuration profile          |

Releases are on [GitHub](https://github.com/OmniTrustILM/identity-manager/releases). Apple silicon is the only Mac
supported. No Linux package is released yet; the policy file for Linux is in [policy.md](policy.md).

The MSI installs per machine and is not code-signed yet, so SmartScreen may warn a person who opens it by hand. The
Mac app is not notarised, so a person allows its first start once, see [install.md](install.md). Pushing the app to
Macs waits for a signed package.

Check what you download before you deploy it; see "Verify a download".

## What the person needs in ILM

Each person needs an account in ILM that can sign in through the identity provider you set up, see
[sign-in.md](sign-in.md). Give them a role with only the permissions of what Identity Manager does for them:

| Permission            | Needed for                                                  |
|-----------------------|-------------------------------------------------------------|
| `certificates:list`   | Finding the person's certificates in ILM to renew or revoke |
| `certificates:create` | Requesting a certificate, also by policy, and renewing      |
| `certificates:renew`  | Renewing a certificate, also automatically                  |
| `certificates:revoke` | Revoking a certificate                                      |

ILM decides every action. Without a permission the app shows no control for the action or reports that ILM does not
allow it. Completing a certificate that an administrator prepared for the person is decided by ILM too. See
[certificates.md](certificates.md).

## Windows

### Silent install with the MSI

```bat
msiexec /i Identity-Manager_0.1.0_x64_en-US.msi ILMURL=https://ilm.example.com SIGNINPROVIDER=Corporate SIGNINMETHOD=oauth STARTATLOGIN=1 AUTOMATICUPDATES=0 /qn /l*v im-install.log
```

Run it from an elevated prompt. `/qn` shows no window and `/l*v` writes a log. A property you leave out writes
nothing.

| Property           | Policy key         | Type and values                              |
|--------------------|--------------------|----------------------------------------------|
| `ILMURL`           | `IlmUrl`           | Text: the address of your ILM, HTTPS         |
| `SIGNINPROVIDER`   | `SignInProvider`   | Text: the name of the identity provider      |
| `SIGNINMETHOD`     | `SignInMethod`     | Text: `oauth` or `certificate`               |
| `STARTATLOGIN`     | `StartAtLogin`     | Number: `1` starts at sign-in, `0` does not  |
| `AUTOMATICUPDATES` | `AutomaticUpdates` | Number: `1` checks for updates, `0` does not |

The MSI writes each value you give to `HKLM\SOFTWARE\Policies\OmniTrustILM\IdentityManager`, where the application
reads policy; [policy.md](policy.md) explains each key. The other policy keys have no property: set them with Group
Policy or the registry.

- **An upgrade keeps them.** Run the newer MSI without properties and the values you gave before stay. The MSI keeps
  its own record of them under `...\IdentityManager\Installer`. Give a property again to change its value.
- **An uninstall removes them.** `msiexec /x Identity-Manager_0.1.0_x64_en-US.msi /qn` removes the values the MSI wrote
  and its record. A value someone else wrote in the key stays.
- **Set each key one way only.** Use the MSI property or Group Policy for a key, not both. A property overwrites a
  Group Policy value under the same key and records its own. A later upgrade without properties then puts the MSI
  value back, and an uninstall deletes the value, until Group Policy writes its own again at its next refresh.

### Group Policy

1. Copy `packaging/windows/IdentityManager.admx` from the source repository to
   `\\<domain>\SYSVOL\<domain>\Policies\PolicyDefinitions`, and `packaging/windows/en-US/IdentityManager.adml` to the
   `en-US` folder inside it. This is the central store. On a single computer use `C:\Windows\PolicyDefinitions`.
2. In the Group Policy Management Editor, open the category "OmniTrust ILM" › "Identity Manager". Its subcategories
   General, Connection, Security and Certificates hold the policies, under both Computer Configuration and User
   Configuration.
3. Set the policies you want and link the object to the computers or people.

A policy under Computer Configuration wins over the same policy under User Configuration, and a policy that is "Not
configured" stays with the person. Group Policy sets the settings, not the application: install the MSI without the
properties for the keys Group Policy sets.

### Intune

- **The application.** Add the MSI as a line-of-business app and put the properties in its command line, or package it
  as a Win32 app with the `msiexec /i … /qn` line above as the install command and
  `msiexec /x Identity-Manager_<version>_x64_en-US.msi /qn` as the uninstall command. Assign it to the computers.
- **The settings, with the template.** Import `IdentityManager.admx` and `IdentityManager.adml` under Devices,
  Configuration, Import ADMX. Then create a profile of the kind "Imported Administrative templates" and set the
  policies. Menu names change between portal versions; use the ones your portal shows.
- **The settings, with properties only.** The five properties need no template. Use them when you set no other key.

As with Group Policy, set each key one way only.

## macOS

Send a configuration profile through your device management. Its payload type is the preference domain
`com.omnitrust.identity-manager` and its keys are the policy keys in [policy.md](policy.md). A complete profile is
[policy/identity-manager.mobileconfig](policy/identity-manager.mobileconfig). Use a device-scope profile: macOS writes
it to `/Library/Managed Preferences/com.omnitrust.identity-manager.plist`.

**Use one profile per preference domain.** A second profile for `com.omnitrust.identity-manager` replaces the first;
it does not merge with it. Put every key in one profile, and when you replace a profile, remove the old one.

Until a signed package exists, a person installs the disk image by hand, see [install.md](install.md).

## Updates

Each installation checks for updates itself and installs one only when the person chooses. Where your device
management deploys new versions, turn this off so that only it changes the version:

- Windows: `AUTOMATICUPDATES=0` on the MSI line, or the Group Policy "Automatic updates" set to Disabled.
- macOS: `AutomaticUpdates` set to false in the profile.

With it off the application makes no request to GitHub, and Settings shows the row locked. To deploy a new version on
Windows, run the newer MSI over the old one; the properties you gave stay.

## Verify a download

Releases are signed: `checksums.txt` has a cosign signature, and the installer and disk image have build provenance
attestations. The steps are in "Check a download" in [install.md](install.md). Do them once on the files you put in
your deployment tool.
