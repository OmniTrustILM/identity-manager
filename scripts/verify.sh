#!/usr/bin/env bash
# Run `npm ci` in app/ first.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

usage() {
    echo "usage: scripts/verify.sh <lint|test|coverage|ct|all|bundle|self-check|policy-system|keyring-system>" >&2
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
    if ! git diff --quiet -- "$dir" || [[ -n "$(git ls-files --others --exclude-standard -- "$dir")" ]]; then
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
    if [[ "$(uname -s)" == Linux ]]; then
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

component_tests() {
    (cd app && npm run test:ct)
}

# The browsers are installed in CI on Linux only; elsewhere they are a local choice.
browsers_available() {
    [[ "$(uname -s)" == Linux || ( "$(uname -s)" == Darwin && -z "${CI:-}" ) ]]
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
            ;;
        Linux)
            deb=$(ls target/release/bundle/deb/*.deb)
            sudo apt-get install -y "./$deb"
            binary=$(dpkg -L "$(dpkg-deb -f "$deb" Package)" | grep '^/usr/bin/')
            ;;
        *) echo "no self-check for $(uname -s)" >&2; exit 1 ;;
    esac
    [[ -n "$binary" ]] || { echo "no app binary found in the bundle" >&2; exit 1; }
    with_display "$binary" --self-check
}

refuse_existing() {
    echo "policy-system will not replace the existing policy $1" >&2
    exit 1
}

as_root() {
    if [[ "$(id -u)" == 0 ]]; then "$@"; else sudo "$@"; fi
}

# Installs a policy on the runner, reads it back through the real readers and removes it. The sources
# are system files and keys, so this runs on CI runners only. Besides the policy the unix systems get a
# root-owned file that group members may write; it must not be trusted.
policy_system() {
    [[ -n "${CI:-}" ]] || { echo "policy-system changes system policy and runs on CI runners only (CI is not set)" >&2; exit 1; }
    local policy_xml='<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>StartAtLogin</key><false/><key>LogLevel</key><string>debug</string></dict></plist>'
    local policy_json='{"StartAtLogin": false, "LogLevel": "debug"}'
    scratch=$(mktemp -d)
    case "$(uname -s)" in
        Darwin)
            folder="/Library/Managed Preferences"
            device="$folder/com.omnitrust.identity-manager.plist"
            export IM_POLICY_UNTRUSTED="$folder/untrusted-test.plist"
            for target in "$device" "$IM_POLICY_UNTRUSTED"; do
                [[ ! -e "$target" && ! -L "$target" ]] || refuse_existing "$target"
            done
            printf '%s\n' "$policy_xml" > "$scratch/policy"
            trap 'as_root rm -f "$device" "$IM_POLICY_UNTRUSTED"; rm -rf "$scratch"' EXIT
            as_root mkdir -p "$folder"
            as_root install -o root -g wheel -m 0644 "$scratch/policy" "$device"
            as_root install -o root -g wheel -m 0664 "$scratch/policy" "$IM_POLICY_UNTRUSTED"
            ;;
        Linux)
            folder=/etc/identity-manager
            export IM_POLICY_UNTRUSTED="$folder/untrusted.json"
            [[ ! -e "$folder" && ! -L "$folder" ]] || refuse_existing "$folder"
            printf '%s\n' "$policy_json" > "$scratch/policy"
            trap 'as_root rm -rf "$folder"; rm -rf "$scratch"' EXIT
            as_root install -d -o root -g root -m 0755 "$folder"
            as_root install -o root -g root -m 0644 "$scratch/policy" "$folder/policy.json"
            as_root install -o root -g root -m 0664 "$scratch/policy" "$IM_POLICY_UNTRUSTED"
            ;;
        MINGW* | MSYS* | CYGWIN*)
            key='HKLM\SOFTWARE\Policies\OmniTrustILM\IdentityManager'
            if MSYS2_ARG_CONV_EXCL='*' reg query "$key" > /dev/null 2>&1; then refuse_existing "$key"; fi
            trap 'MSYS2_ARG_CONV_EXCL="*" reg delete "$key" /f || true; rm -rf "$scratch"' EXIT
            MSYS2_ARG_CONV_EXCL='*' reg add "$key" /v StartAtLogin /t REG_DWORD /d 0 /f
            MSYS2_ARG_CONV_EXCL='*' reg add "$key" /v LogLevel /t REG_SZ /d debug /f
            ;;
        *) echo "no policy sources for $(uname -s)" >&2; exit 1 ;;
    esac
    cargo test -p im-core --locked --test policy_system -- --ignored
}

# Saves, reads and deletes an item in the protected storage of the runner, so it runs on CI runners only.
# Linux has no storage without a session: the secret service of an unlocked gnome-keyring runs on a private bus.
keyring_system() {
    [[ -n "${CI:-}" ]] || { echo "keyring-system writes to the protected storage of the system and runs on CI runners only (CI is not set)" >&2; exit 1; }
    local run=(cargo test -p im-core --locked --test keyring_system -- --ignored)
    if [[ "$(uname -s)" == Linux ]]; then
        as_root apt-get install -y --no-install-recommends gnome-keyring dbus
        dbus-run-session -- bash -c 'echo "" | gnome-keyring-daemon --unlock --components=secrets > /dev/null && "$@"' _ "${run[@]}"
    else
        "${run[@]}"
    fi
}

case "${1:-}" in
    lint) lint ;;
    test) run_tests ;;
    coverage) coverage ;;
    ct) component_tests ;;
    all)
        lint
        coverage
        if browsers_available; then component_tests; fi
        ;;
    bundle) bundle ;;
    self-check) self_check ;;
    policy-system) policy_system ;;
    keyring-system) keyring_system ;;
    *) usage ;;
esac
