# Identity Manager

Identity Manager is a desktop application that brings certificates managed by ILM (OmniTrust ILM) to a person's
computer.

This repository holds the foundation only so far: a Rust core crate, `im-core`, and the React interface in `app/`,
together with the checks and workflows that verify them. There is no application yet.

## Requirements

- Rust through [rustup](https://rustup.rs). The toolchain version is pinned in `rust-toolchain.toml` and installed
  automatically.
- `cargo-llvm-cov` 0.9.1 and `cargo-deny` 0.20.2:

  ```bash
  cargo install --locked cargo-llvm-cov@0.9.1 cargo-deny@0.20.2
  ```

- Node.js 22.22 or newer with npm.
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
