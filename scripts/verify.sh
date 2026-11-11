#!/usr/bin/env bash
# Run `npm ci` in app/ first.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

usage() {
    echo "usage: scripts/verify.sh <lint|test|coverage|all|bundle|self-check>" >&2
    exit 2
}

build_interface() {
    (cd app && npm run build)
}

lint() {
    build_interface
    cargo fmt --all --check
    cargo clippy --workspace --all-targets --locked -- -D warnings
    cargo deny check
    (cd app && npm run lint)
    (cd app && npm run typecheck)
    (cd app && npm audit --audit-level=moderate)
}

check_generated_types() {
    local dir=app/src/bridge/generated
    if ! git diff --quiet -- "$dir" || [ -n "$(git ls-files --others --exclude-standard -- "$dir")" ]; then
        echo "$dir differs from the Rust types; regenerate with cargo test and commit the result" >&2
        exit 1
    fi
}

run_tests() {
    build_interface
    cargo test --workspace --locked
    check_generated_types
    (cd app && npm test)
}

with_display() {
    if [ "$(uname -s)" = Linux ]; then
        xvfb-run -a dbus-run-session -- "$@"
    else
        "$@"
    fi
}

coverage() {
    build_interface
    mkdir -p reports
    cargo llvm-cov clean --workspace
    cargo llvm-cov --no-report --workspace --locked --features tauri/custom-protocol
    check_generated_types
    with_display cargo llvm-cov run --no-report -p identity-manager --locked \
        --features tauri/custom-protocol -- --self-check
    cargo llvm-cov report --summary-only
    cargo llvm-cov report --fail-under-lines 80 --lcov --output-path reports/rust.lcov
    cargo clippy --workspace --all-targets --locked --message-format=json > reports/clippy.json
    (cd app && npm run test:cov)
    cp app/coverage-vitest/lcov.info reports/ui.lcov
}

bundle() {
    local bundles
    case "$(uname -s)" in
        Darwin) bundles=app,dmg ;;
        MINGW* | MSYS* | CYGWIN*) bundles=msi ;;
        Linux) bundles=deb ;;
        *) echo "no bundle targets for $(uname -s)" >&2; exit 1 ;;
    esac
    build_interface
    (cd crates/app && ../../app/node_modules/.bin/tauri build --bundles "$bundles")
}

self_check() {
    local deb msi extracted binary
    case "$(uname -s)" in
        Darwin)
            binary="target/release/bundle/macos/Identity Manager.app/Contents/MacOS/identity-manager"
            ;;
        MINGW* | MSYS* | CYGWIN*)
            msi=$(ls target/release/bundle/msi/*.msi)
            extracted=target/release/bundle/msi-extracted
            rm -rf "$extracted"
            MSYS2_ARG_CONV_EXCL='*' msiexec /a "$(cygpath -w "$msi")" /qn "TARGETDIR=$(cygpath -wa "$extracted")"
            binary=$(find "$extracted" -name identity-manager.exe | head -n 1)
            [ -n "$binary" ] || { echo "identity-manager.exe not found in $msi" >&2; exit 1; }
            ;;
        Linux)
            deb=$(ls target/release/bundle/deb/*.deb)
            sudo apt-get install -y "./$deb"
            binary=$(dpkg-deb -c "$deb" | awk '$NF ~ /^\.\/usr\/bin\/[^\/]+$/ { print substr($NF, 2); exit }')
            ;;
        *) echo "no self-check for $(uname -s)" >&2; exit 1 ;;
    esac
    with_display "$binary" --self-check
}

case "${1:-}" in
    lint) lint ;;
    test) run_tests ;;
    coverage) coverage ;;
    all) lint; coverage ;;
    bundle) bundle ;;
    self-check) self_check ;;
    *) usage ;;
esac
