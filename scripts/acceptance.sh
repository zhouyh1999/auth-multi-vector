#!/usr/bin/env bash
# Inside the isolated environment. Use a new copy for a clean-build assertion.
set -eu -o pipefail
mkdir -p docs/evidence
case "${1:-all}" in
build)
    rustc -Vv
    cargo -V
    cc --version
    c++ --version
    "$PYTHON" -V
    pwd
    ip -brief address
    cargo metadata --format-version 1 --offline --locked >docs/evidence/metadata.json
    cargo tree --workspace --locked --offline -e features >docs/evidence/features.txt
    cargo build --workspace --release --locked --offline -j 8
    "$PYTHON" -m venv artifacts/acceptance/venv
    artifacts/acceptance/venv/bin/python -m pip install --no-index --find-links third_party/python --require-hashes -r third_party/python/requirements.lock
    openssl version
    ldd "$CARGO_TARGET_DIR/release/first-visit"
    artifacts/acceptance/venv/bin/python -c 'import ssl; print(ssl.OPENSSL_VERSION,ssl.HAS_TLSv1_3); assert ssl.HAS_TLSv1_3'
    ;;
tests)
    cargo build --workspace --all-targets --locked --offline -j 8
    cargo test --workspace --locked --offline
    artifacts/acceptance/venv/bin/python -m unittest discover -v -s scripts/tests
    ;;
sample)
    py=artifacts/acceptance/venv/bin/python
    for action in validate-data prepare reference test-e2e audit; do
        "$py" scripts/artifact.py "$action" --dataset sample
    done
    (sha256sum --check tests/fixtures/sample/wire.sha256)
    "$CARGO_TARGET_DIR/release/first-visit" check-fixture tests/fixtures/sample/public tests/fixtures/sample/wire
    "$CARGO_TARGET_DIR/release/check-historical" tests/fixtures/lotte/2857
    ;;
all)
    for step in build tests sample; do bash "$0" "$step"; done
    ;;
*) exit 2 ;;
esac

