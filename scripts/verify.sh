#!/usr/bin/env bash
# Run `npm ci` in app/ first.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

usage() {
    echo "usage: scripts/verify.sh <lint|test|coverage|ct|all|bundle|release-check <tag>|self-check|policy-system|keyring-system|identity-system|msi-system>" >&2
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

# Extra arguments go to `tauri build`.
bundle() {
    local bundles
    case "$(uname -s)" in
        Darwin) bundles=app,dmg ;;
        MINGW* | MSYS* | CYGWIN*) bundles=msi ;;
        Linux) bundles=deb ;;
        *) echo "no bundle targets for $(uname -s)" >&2; exit 1 ;;
    esac
    build_interface
    (cd crates/app && ../../app/node_modules/.bin/tauri build --bundles "$bundles" "$@")
}

# Fails unless the tag matches the version of the workspace and of the interface, and the updater key is set.
release_check() {
    local tag=${1:-} version cargo_version package_version pubkey
    version=${tag#v}
    cargo_version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)
    package_version=$(sed -n 's/^ *"version": *"\(.*\)",*$/\1/p' app/package.json | head -n 1)
    if [[ "$tag" != v* || "$version" != "$cargo_version" || "$version" != "$package_version" ]]; then
        echo "tag '$tag' does not match version $cargo_version in Cargo.toml and $package_version in app/package.json" >&2
        exit 1
    fi
    pubkey=$(sed -n 's/^ *"pubkey": *"\(.*\)",*$/\1/p' crates/app/tauri.conf.json)
    [[ -n "$pubkey" ]] || { echo "the updater pubkey in crates/app/tauri.conf.json is empty; set it before releasing" >&2; exit 1; }
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
<plist version="1.0"><dict><key>StartAtLogin</key><false/><key>AutomaticUpdates</key><false/><key>LogLevel</key><string>debug</string><key>CompletePrepared</key><true/><key>RequestProfiles</key><string>Web, Mail</string><key>SignInCertificateProfile</key><string>Sign-in</string></dict></plist>'
    local policy_json='{"StartAtLogin": false, "AutomaticUpdates": false, "LogLevel": "debug", "CompletePrepared": true, "RequestProfiles": "Web, Mail", "SignInCertificateProfile": "Sign-in"}'
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
            MSYS2_ARG_CONV_EXCL='*' reg add "$key" /v AutomaticUpdates /t REG_DWORD /d 0 /f
            MSYS2_ARG_CONV_EXCL='*' reg add "$key" /v LogLevel /t REG_SZ /d debug /f
            MSYS2_ARG_CONV_EXCL='*' reg add "$key" /v CompletePrepared /t REG_DWORD /d 1 /f
            MSYS2_ARG_CONV_EXCL='*' reg add "$key" /v RequestProfiles /t REG_SZ /d "Web, Mail" /f
            MSYS2_ARG_CONV_EXCL='*' reg add "$key" /v SignInCertificateProfile /t REG_SZ /d Sign-in /f
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

# Writes ca.pem, leaf.pem and identity.p12 (password in $2) for a throwaway CA and a client certificate with an
# ECDSA P-256 key and the clientAuth extended key usage, into the directory $1.
make_test_identity() {
    local dir=$1 password=$2
    (
        cd "$dir"
        export MSYS2_ARG_CONV_EXCL='*'
        printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n' > ca.ext
        printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n' > leaf.ext
        openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ca.key
        openssl req -new -key ca.key -subj "/CN=Identity Manager Test CA" -out ca.csr
        openssl x509 -req -in ca.csr -signkey ca.key -days 2 -extfile ca.ext -out ca.pem
        openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out leaf.key
        openssl req -new -key leaf.key -subj "/CN=Identity Manager Test Client" -out leaf.csr
        openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile leaf.ext -out leaf.pem
        # OpenSSL 3 writes a format the macOS importer rejects unless -legacy is given; LibreSSL has no such flag.
        openssl pkcs12 -export -legacy -inkey leaf.key -in leaf.pem -name "Identity Manager Test Client" \
            -passout "pass:$password" -out identity.p12 2> /dev/null \
            || openssl pkcs12 -export -inkey leaf.key -in leaf.pem -name "Identity Manager Test Client" \
                -passout "pass:$password" -out identity.p12
    )
}

# Prints the hash of the certificate $2 (leaf or ca) in the directory $3 as the DER bytes: SHA-256 for the test,
# SHA-1 for the Windows thumbprint.
certificate_digest() {
    local digest=$1 name=$2 dir=$3
    openssl x509 -in "$dir/$name.pem" -outform DER | openssl dgst "-$digest" -r | cut -d' ' -f1
}

# The cleanups run from an EXIT trap, so they read globals.
remove_test_keychain() {
    if [[ -n "$saved_default" ]]; then
        security default-keychain -d user -s "$saved_default" || true
    fi
    if [[ ${#saved_keychains[@]} -gt 0 ]]; then
        security list-keychains -d user -s "${saved_keychains[@]}" || true
    fi
    security delete-keychain "$keychain" || true
    security delete-keychain "$other_keychain" || true
    rm -rf "$dir"
}

remove_test_certificate() {
    # shellcheck disable=SC2016 # PowerShell expands the variable
    IM_THUMBPRINT="$thumbprint" IM_CA_THUMBPRINT="$ca_thumbprint" pwsh -NoProfile -Command \
        'Remove-Item "Cert:\CurrentUser\My\$env:IM_THUMBPRINT" -DeleteKey -ErrorAction SilentlyContinue;
         Remove-Item "Cert:\CurrentUser\My\$env:IM_CA_THUMBPRINT" -ErrorAction SilentlyContinue' || true
    rm -rf "$dir"
}

# Puts a throwaway client certificate, and its CA as a certificate without a key, into the user store of the runner,
# lists and signs with the client certificate through the real readers, checks that the CA is not listed, and removes
# both. The store is the real one, so this runs on CI runners only. Linux has no store.
identity_system() {
    [[ -n "${CI:-}" ]] || { echo "identity-system writes to the certificate store of the system and runs on CI runners only (CI is not set)" >&2; exit 1; }
    local password test_name ca_pem request request_out
    dir=$(mktemp -d)
    password=$(openssl rand -hex 16)
    make_test_identity "$dir" "$password"
    case "$(uname -s)" in
        Darwin)
            keychain="$dir/identity-test.keychain-db"
            other_keychain="$dir/identity-other.keychain-db"
            test_name=identity::macos::tests::system_store_lists_and_signs
            saved_keychains=()
            saved_default=$(security default-keychain -d user)
            saved_default=${saved_default#*\"}
            saved_default=${saved_default%\"*}
            while IFS= read -r line; do
                line=${line#*\"}
                saved_keychains+=("${line%\"*}")
            done < <(security list-keychains -d user)
            trap remove_test_keychain EXIT
            security create-keychain -p "$password" "$keychain"
            security set-keychain-settings -lut 3600 "$keychain"
            security unlock-keychain -p "$password" "$keychain"
            # A second identity in a keychain that is on the search list but not the default must not be read.
            mkdir "$dir/other"
            make_test_identity "$dir/other" "$password"
            security create-keychain -p "$password" "$other_keychain"
            security set-keychain-settings -lut 3600 "$other_keychain"
            security unlock-keychain -p "$password" "$other_keychain"
            security list-keychains -d user -s "$keychain" "$other_keychain" "${saved_keychains[@]}"
            security default-keychain -d user -s "$keychain"
            security import "$dir/identity.p12" -k "$keychain" -P "$password" -A -f pkcs12
            security import "$dir/ca.pem" -k "$keychain" -f openssl
            security import "$dir/other/identity.p12" -k "$other_keychain" -P "$password" -A -f pkcs12
            security set-key-partition-list -S apple-tool:,apple: -s -k "$password" "$keychain" > /dev/null
            security set-key-partition-list -S apple-tool:,apple: -s -k "$password" "$other_keychain" > /dev/null
            elsewhere=$(certificate_digest sha256 leaf "$dir/other")
            ;;
        MINGW* | MSYS* | CYGWIN*)
            thumbprint=$(certificate_digest sha1 leaf "$dir")
            ca_thumbprint=$(certificate_digest sha1 ca "$dir")
            test_name=identity::windows::tests::system_store_lists_and_signs
            trap remove_test_certificate EXIT
            # The software key storage provider is the one the key provider test expects.
            MSYS2_ARG_CONV_EXCL='*' certutil -user -csp "Microsoft Software Key Storage Provider" \
                -p "$password" -importpfx "$(cygpath -w "$dir/identity.p12")" NoExport
            # shellcheck disable=SC2016 # PowerShell expands the variable
            IM_CA=$(cygpath -w "$dir/ca.pem") pwsh -NoProfile -Command \
                'Import-Certificate -FilePath $env:IM_CA -CertStoreLocation Cert:\CurrentUser\My | Out-Null'
            ;;
        *) echo "identity-system has no certificate store to test on $(uname -s)" >&2; exit 1 ;;
    esac
    ca_pem=$dir/ca.pem
    [[ "$(uname -s)" == Darwin ]] || ca_pem=$(cygpath -w "$ca_pem")
    IM_IDENTITY_FINGERPRINT=$(certificate_digest sha256 leaf "$dir") \
        IM_IDENTITY_KEYLESS_FINGERPRINT=$(certificate_digest sha256 ca "$dir") IM_IDENTITY_CA=$ca_pem \
        IM_IDENTITY_ELSEWHERE_FINGERPRINT=${elsewhere:-} \
        cargo test -p im-core --locked -- --ignored "$test_name"
    build_interface
    if [[ "$(uname -s)" != Darwin ]]; then
        IM_IDENTITY_FINGERPRINT=$(certificate_digest sha256 leaf "$dir") \
            cargo test -p identity-manager --locked key_provider -- --ignored
    fi
    # Creates keys in the key storage of the runner: the default keychain (the temporary one) on macOS, the software
    # provider and the platform provider when the runner has one on Windows. The test prints what is offered.
    request="$dir/request.der"
    request_out=$request
    [[ "$(uname -s)" == Darwin ]] || request_out=$(cygpath -w "$request")
    IM_KEY_REQUEST_OUT=$request_out \
        cargo test -p identity-manager --locked key_storage -- --ignored --nocapture
    [[ -s "$request" ]] || { echo "the key storage test wrote no request" >&2; exit 1; }
    openssl req -inform DER -in "$request" -verify -noout
    # Installs a certificate and its intermediate for a new key in each offered storage, finds the identity through
    # the reader, and removes the certificates and the key again. Then installs a second certificate beside the first
    # for the same key and removes both through the installer, the key with the last one.
    cargo test -p identity-manager --locked install::tests::installer_ -- --ignored --nocapture
}

# Runs msiexec with the arguments, logging to $1; prints the end of the log and fails when msiexec does.
run_msiexec() {
    local log=$1
    shift
    if ! MSYS2_ARG_CONV_EXCL='*' msiexec "$@" /qn /l*v "$(cygpath -w "$log")"; then
        echo "msiexec $1 failed; the end of its log:" >&2
        tr -d '\0' < "$log" | tail -n 60 >&2
        exit 1
    fi
}

# Prints "<type> <data>" of value $1 of the 64-bit key $2, or nothing when it is not there.
policy_value() {
    local name=$1 key=$2
    MSYS2_ARG_CONV_EXCL='*' reg query "$key" /v "$name" /reg:64 2> /dev/null | tr -d '\r' \
        | awk -v name="$name" '$1 == name {
            type = $2
            sub(/^[[:space:]]*[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+/, "")
            print type, $0
        }' || true
}

# $1 is a registry key and the other arguments are "<name> <type> <data>"; fails with a line for every value of the
# key that differs.
expect_policy_values() {
    local key=$1 entry actual failed=0
    shift
    for entry in "$@"; do
        actual=$(policy_value "${entry%% *}" "$key")
        if [[ "${entry%% *} $actual" != "$entry" ]]; then
            echo "$key value ${entry%% *}: expected '${entry#* }', found '${actual:-nothing}'" >&2
            failed=1
        fi
    done
    [[ "$failed" == 0 ]] || exit 1
}

# Starts the installed application in self-check mode and expects the policy line to name exactly $1.
expect_installed_policy() {
    local names=$1 binary output
    binary=$(find "$(cygpath -u "$PROGRAMFILES")" -maxdepth 3 -name identity-manager.exe | head -n 1)
    [[ -n "$binary" ]] || { echo "the installed application was not found" >&2; exit 1; }
    output=$("$binary" --self-check)
    echo "$output"
    grep -Fxq "self-check policy managed: $names" <<< "$output" || { echo "the policy line does not name: $names" >&2; exit 1; }
}

# Expects the policy key to hold the MSI's values and the value it does not own, the installer's record to hold the
# MSI's values only, and the application to report them all as managed.
expect_installed_state() {
    expect_policy_values "$policy_key" "${expected[@]}" "$foreign"
    expect_policy_values "$record_key" "${expected[@]}"
    [[ -z "$(policy_value "${foreign%% *}" "$record_key")" ]] || { echo "the installer recorded ${foreign%% *}" >&2; exit 1; }
    expect_installed_policy "AutomaticUpdates, IlmUrl, SignInMethod, SignInProvider, StartAtLogin"
}

remove_installed_product() {
    MSYS2_ARG_CONV_EXCL='*' reg delete "$policy_key" /f /reg:64 > /dev/null 2>&1 || true
    for msi in "$first_msi" "$second_msi"; do
        [[ ! -f "$msi" ]] || MSYS2_ARG_CONV_EXCL='*' msiexec /x "$(cygpath -w "$msi")" /qn > /dev/null 2>&1 || true
    done
    rm -rf "$scratch"
}

# Installs the bundled MSI with policy properties, upgrades it without properties and uninstalls it, checking the
# policy values in the registry and the application's own view of them at each step. It installs software and
# writes HKLM, so it runs on CI runners only. It expects `bundle` to have built the MSI.
msi_system() {
    [[ -n "${CI:-}" ]] || { echo "msi-system installs software and runs on CI runners only (CI is not set)" >&2; exit 1; }
    case "$(uname -s)" in
        MINGW* | MSYS* | CYGWIN*) ;;
        *) echo "msi-system tests the Windows installer and runs on Windows only" >&2; exit 1 ;;
    esac
    local version next
    # The key holds a value the installer does not own, which it must leave alone; the subkey is the installer's record.
    policy_key='HKLM\SOFTWARE\Policies\OmniTrustILM\IdentityManager'
    record_key="$policy_key\\Installer"
    foreign="SignInProvider REG_SZ Corporate"
    if MSYS2_ARG_CONV_EXCL='*' reg query "$policy_key" /reg:64 > /dev/null 2>&1; then refuse_existing "$policy_key"; fi
    scratch=$(mktemp -d)
    first_msi=$scratch/first.msi
    second_msi=$scratch/second.msi
    cp "$(ls target/release/bundle/msi/*.msi)" "$first_msi"
    trap remove_installed_product EXIT
    MSYS2_ARG_CONV_EXCL='*' reg add "$policy_key" /v SignInProvider /t REG_SZ /d Corporate /f /reg:64 > /dev/null

    run_msiexec "$scratch/install.log" /i "$(cygpath -w "$first_msi")" \
        ILMURL=https://ilm.example.com SIGNINMETHOD=oauth STARTATLOGIN=0 AUTOMATICUPDATES=0
    expected=(
        "IlmUrl REG_SZ https://ilm.example.com" "SignInMethod REG_SZ oauth"
        "StartAtLogin REG_DWORD 0x0" "AutomaticUpdates REG_DWORD 0x0"
    )
    expect_installed_state

    version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)
    next="${version%.*}.$(( ${version##*.} + 1 ))"
    bundle --config "{\"version\":\"$next\"}"
    cp "$(ls target/release/bundle/msi/*_"${next}"_*.msi)" "$second_msi"
    run_msiexec "$scratch/upgrade.log" /i "$(cygpath -w "$second_msi")"
    expect_installed_state

    run_msiexec "$scratch/uninstall.log" /x "$(cygpath -w "$second_msi")"
    expect_policy_values "$policy_key" "$foreign"
    local name
    for name in IlmUrl SignInMethod StartAtLogin AutomaticUpdates; do
        [[ -z "$(policy_value "$name" "$policy_key")" ]] || { echo "the uninstall left $name in $policy_key" >&2; exit 1; }
    done
    if MSYS2_ARG_CONV_EXCL='*' reg query "$record_key" /reg:64 > /dev/null 2>&1; then
        echo "the uninstall left $record_key" >&2
        exit 1
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
    bundle) shift; bundle "$@" ;;
    release-check) release_check "${2:-}" ;;
    self-check) self_check ;;
    policy-system) policy_system ;;
    keyring-system) keyring_system ;;
    identity-system) identity_system ;;
    msi-system) msi_system ;;
    *) usage ;;
esac
