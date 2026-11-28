# Install Identity Manager

This guide shows you how to install, update, check and remove Identity Manager on Windows and on a Mac. An
administrator who installs it for many computers reads [deployment.md](deployment.md) instead.

## What you need

- Windows 10 or 11 on 64-bit Intel or AMD, or a Mac with Apple silicon. Intel Macs are not supported.
- Administrator rights on Windows: the installer installs for every person on the computer.
- No Linux package is released yet.

## Download

Download the file for your system from the
[releases page](https://github.com/OmniTrustILM/identity-manager/releases). Take the newest release. `<version>` is
the number of the release, for example `0.1.0`.

| System  | File                                    |
|---------|-----------------------------------------|
| Windows | `Identity-Manager_<version>_x64_en-US.msi` |
| macOS   | `Identity-Manager_<version>_aarch64.dmg`   |

The other files of a release are for checking a download and for updates; see "Check a download".

## Install on Windows

1. Open the `.msi` file.
2. Windows may show a blue "Windows protected your PC" window. The installer is not code-signed yet, so Windows does
   not know the publisher. If you downloaded the file from the releases page above, choose "More info", then "Run
   anyway". If you are not sure of the source, check the download first.
3. Allow the change when Windows asks for administrator rights and follow the steps.
4. Start Identity Manager from the Start menu. Its icon appears in the notification area of the taskbar.

## Install on a Mac

1. Open the `.dmg` file.
2. Drag Identity Manager to the Applications folder.
3. Open Identity Manager from Applications. The app is not notarised by Apple, so macOS blocks the first start.
4. Open System Settings, then Privacy & Security. Scroll to the message about Identity Manager and choose "Open
   Anyway". Confirm, and sign in to the Mac if it asks.

You do this once. Its icon appears in the menu bar.

## Start with your ILM

Open Identity Manager and enter the address of your ILM, then choose Sign in. Your organization may have set the
address already. See [sign-in.md](sign-in.md) for what happens next.

## Updates

Identity Manager checks GitHub for a new version about a minute after it starts and then once a day. When it finds
one, it shows the notification "Identity Manager <version> is available" and adds "Install update <version>…" to the
menu of its tray icon. Nothing installs until you choose that entry. Only updates signed with the project's update key
are installed; the app refuses any other.

- On Windows the update installs the newer installer, and Windows asks for administrator rights.
- On a Mac the app replaces itself and restarts. Until the app is notarised, macOS asks once after each update to let
  Identity Manager use the keychain. Choose "Always Allow".
- To stop the checks, switch off "Check for updates" in Settings, General. With it off, Identity Manager makes no
  request to GitHub, and you install new versions by hand from the releases page.
- Your organization can switch updates off with the `AutomaticUpdates` policy key. The row is then locked and says
  "Managed by your organization". See [policy.md](policy.md).

## Check a download

Each release lists `checksums.txt`, which holds the SHA-256 sum of every file, and `checksums.txt.sig`, a signature
of that list made with the OmniTrust ILM signing key. Check the list first, then the file.

1. Put the file, `checksums.txt` and `checksums.txt.sig` in one folder.
2. Download the public key `cosign.pub` from the
   [OmniTrustILM `.github` repository](https://raw.githubusercontent.com/OmniTrustILM/.github/main/cosign.pub).
3. Check the signature with [cosign](https://docs.sigstore.dev/cosign/system_config/installation/):

   ```bash
   cosign verify-blob --key cosign.pub --signature checksums.txt.sig checksums.txt
   ```

   It prints `Verified OK` when the list is genuine.
4. Check that your file matches the list.

   On Linux and in Git Bash on Windows:

   ```bash
   sha256sum -c checksums.txt --ignore-missing
   ```

   On macOS:

   ```bash
   shasum -a 256 -c checksums.txt --ignore-missing
   ```

   In PowerShell, compare the output of `Get-FileHash <file>` with the line for the file in `checksums.txt`.

The line for your file must end in `OK`. If a check fails, do not install the file.

You can also check where the installer and the disk image were built. With the [GitHub CLI](https://cli.github.com):

```bash
gh attestation verify Identity-Manager_<version>_x64_en-US.msi --repo OmniTrustILM/identity-manager
```

Use the `.dmg` file name for the disk image. The command checks the build provenance attestation that the release
workflow made.

`Identity-Manager_<version>_sbom.cdx.json` is the list of the components in the release, in CycloneDX format, for
those who need it.

## Remove

- Windows: open Settings, Apps, Installed apps, choose Identity Manager and Uninstall.
- macOS: quit Identity Manager from its menu, then drag it from Applications to the Bin.

Your own settings stay in `settings.json`; the folder is named in [policy.md](policy.md). Delete it if you want
them gone too.
