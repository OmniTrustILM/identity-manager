# Identity Manager

Identity Manager is a desktop application that brings certificates managed by ILM (OmniTrust ILM) to a person's
computer.

The application is minimal so far. It puts an icon in the system tray (menu bar on macOS) with the
entries "Open Identity Manager" and "Quit", and opens one window. Closing the window hides it to the tray; "Quit"
ends the application. Only one copy runs: starting a second brings the window of the first forward. `--self-check`
starts the application, checks that the interface loaded and agrees with the core on name and version, prints the
outcome and exits with status 0 on success, non-zero on failure or after 60 seconds without a report.

The code is a Rust core crate, `im-core`, the Tauri application in `crates/app`, and the React interface in `app/`,
together with the checks and workflows that verify them.

## Requirements

- Rust through [rustup](https://rustup.rs). The toolchain version is pinned in `rust-toolchain.toml` and installed
  automatically.
- `cargo-llvm-cov` 0.9.1 and `cargo-deny` 0.20.2:

  ```bash
  cargo install --locked cargo-llvm-cov@0.9.1 cargo-deny@0.20.2
  ```

- Node.js 22.22 or newer with npm.
- Linux: the Tauri build packages, plus `xvfb` and `dbus-x11` for the self-check without a display:

  ```bash
  sudo apt-get install -y libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev libxdo-dev libssl-dev \
    patchelf xvfb dbus-x11
  ```

- Windows: the WebView2 runtime, which Windows 10 and 11 include.
- For local SonarQube analysis also Docker, `sonar-scanner`, Python 3 and OpenSSL.

## Development

Install the interface dependencies first:

```bash
cd app && npm ci
```

### Build

```bash
cd app && npm run build
```

The Rust crate builds with `cargo build --workspace --locked`.

### Run

Start the interface server in one terminal and the application in another:

```bash
npm --prefix app run dev
```

```bash
cd crates/app && ../../app/node_modules/.bin/tauri dev
```

The application loads the interface from the server and reloads it on change.

Debug builds store the refresh token too. Each build changes the code signature, so macOS asks once per build to
allow keychain access.

Signing in with a certificate asks for the same: each debug rebuild changes the signature, so macOS asks again for
permission to use the certificate's key.

### Bundle

```bash
bash scripts/verify.sh bundle
```

Builds the installer for the current system (`.app` and `.dmg` on macOS, `.msi` on Windows, `.deb` on Linux) into
`target/release/bundle/`.

### Self-check

```bash
bash scripts/verify.sh self-check
```

Runs the bundled application with `--self-check`. Run `bundle` first; on Linux this installs the `.deb` with `sudo`.

### Tests

```bash
bash scripts/verify.sh test
```

### Component tests

```bash
bash scripts/verify.sh ct
```

Runs the component tests (`*.ct.tsx`, next to the components) in Chromium and WebKit. Install the browsers once:

```bash
cd app && npx playwright install chromium webkit
```

On Linux add `--with-deps` to install the system libraries too.

### Coverage

```bash
bash scripts/verify.sh coverage
```

Reports are written to `reports/`. The command fails below 80 % line coverage.

### Formatting

Check formatting and lint rules with:

```bash
bash scripts/verify.sh lint
```

It runs the rustfmt check, Clippy, cargo-deny, Biome, the TypeScript check and `npm audit`.
To fix formatting:

```bash
cargo fmt --all
cd app && npm run format
```

`bash scripts/verify.sh all` runs lint and then coverage, as the workflows do.

### Local SonarQube analysis

```bash
env -u SONAR_TOKEN scripts/sonar-local.sh
```

The script starts an ephemeral `sonarqube:community` container, runs the coverage build, analyses the project and
fails unless the quality gate passes and no open issue touches a line changed since `BASE_BRANCH` (default
`origin/main`).

## Design tokens

All sizes, radii, fonts and colours live as CSS variables in `app/src/design-system/tokens.css`, one set per
system. The values come from the design files (`*.pen`), which are the drawings; change a value in both.

- The interface sets `data-os` on `<html>` from the platform the core reports (`macos`, `windows` or `linux`), and the
  matching set applies.
- Light and dark follow the system only, through `prefers-color-scheme`. On Linux the web view does not follow the
  desktop, so the application reads the colour scheme from the Settings portal and sets `data-theme` on `<html>`.
- `@theme inline` in `app/src/styles.css` maps the variables to Tailwind utilities. Components use those utilities and
  contain no colour or size literals.

## Window settings

The native material is set in `crates/app/tauri.conf.json` and the platform files next to it:

- macOS: the main window is `transparent` with the `sidebar` window effect and an overlay title bar with a hidden
  title. `transparent` needs `macOSPrivateApi`, which in turn needs the `macos-private-api` feature of `tauri`.
- Windows: the main window is `transparent` with the `mica` effect. Mica needs Windows 11; Windows 10 shows no
  material.
- Linux: the window is opaque.

`tauri.macos.conf.json` and `tauri.windows.conf.json` replace the whole `windows` array of `tauri.conf.json`, they do
not merge into it.

## Signing in

The person enters the address of the ILM and signs in through their identity provider in the system browser; see
[docs/sign-in.md](docs/sign-in.md) for what the ILM and the provider need. The refresh token is kept in the system's
protected storage: the Keychain on macOS, the Credential Manager on Windows and the Secret Service on Linux.

## Certificates

The overview counts the certificates on the computer, warns before they expire and can add them to the ILM; see
[docs/certificates.md](docs/certificates.md).

## Settings and policy

An organization can fix settings from the system, and the person's own choices are stored in `settings.json`; see
[docs/policy.md](docs/policy.md).

## License

Apache License 2.0, see [LICENSE.md](LICENSE.md).
