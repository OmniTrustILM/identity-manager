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

## License

Apache License 2.0, see [LICENSE.md](LICENSE.md).
