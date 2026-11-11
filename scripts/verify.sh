#!/usr/bin/env bash
# Run `npm ci` in app/ first.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

usage() {
    echo "usage: scripts/verify.sh <lint|test|coverage|all>" >&2
    exit 2
}

lint() {
    cargo fmt --all --check
    cargo clippy --workspace --all-targets --locked -- -D warnings
    cargo deny check
    (cd app && npm run lint)
    (cd app && npm run typecheck)
    (cd app && npm audit --audit-level=moderate)
}

run_tests() {
    cargo test --workspace --locked
    (cd app && npm test)
}

coverage() {
    mkdir -p reports
    cargo llvm-cov --workspace --locked --fail-under-lines 80 --lcov --output-path reports/rust.lcov
    cargo clippy --workspace --all-targets --locked --message-format=json > reports/clippy.json
    (cd app && npm run test:cov)
    cp app/coverage-vitest/lcov.info reports/ui.lcov
}

case "${1:-}" in
    lint) lint ;;
    test) run_tests ;;
    coverage) coverage ;;
    all) lint; coverage ;;
    *) usage ;;
esac
