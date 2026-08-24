set positional-arguments := true

default:
    @just --list

fmt-check:
    cargo fmt --all -- --check

check:
    cargo check --all-targets --all-features

test:
    cargo test --all-features

clippy:
    cargo clippy --all-targets --all-features -- -D warnings

audit:
    cargo audit --deny warnings \
      --ignore RUSTSEC-2025-0141 \
      --ignore RUSTSEC-2024-0436 \
      --ignore RUSTSEC-2026-0206 \
      --ignore RUSTSEC-2026-0192

ffi-generate:
    mkdir -p include
    cbindgen --config cbindgen.toml --crate hhm-desktop-app --output include/hhm_desktop.h

ffi-check:
    mkdir -p target/generated
    cbindgen --config cbindgen.toml --crate hhm-desktop-app --output target/generated/hhm_desktop.h
    cmp include/hhm_desktop.h target/generated/hhm_desktop.h
    cc -std=c11 -Wall -Wextra -Werror -fsyntax-only -x c include/hhm_desktop.h

ffi-smoke:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build --lib --all-features
    cc -std=c11 -Wall -Wextra -Werror tests/ffi_smoke.c -Iinclude -Ltarget/debug \
      -lhhm_desktop_app -o target/ffi-smoke
    case $(uname -s) in
      Darwin) DYLD_LIBRARY_PATH=target/debug target/ffi-smoke ;;
      Linux) LD_LIBRARY_PATH=target/debug target/ffi-smoke ;;
      *) echo "dynamic FFI smoke execution is not configured for this host" ;;
    esac

verify: fmt-check check test clippy audit ffi-check ffi-smoke env-check

env-edit profile:
    sops edit --input-type dotenv --output-type dotenv env/enc/{{ profile }}.env.enc

env-rekey:
    #!/usr/bin/env bash
    set -euo pipefail
    shopt -s nullglob
    files=(env/enc/*.env.enc)
    [[ ${#files[@]} -gt 0 ]] || { echo "no encrypted environments" >&2; exit 1; }
    for file in "${files[@]}"; do
      sops updatekeys --yes --input-type dotenv "$file"
    done

env-check:
    #!/usr/bin/env bash
    set -euo pipefail
    bad=$(git ls-files | grep -E '(^|/)\.env$|(^|/)\.env\.[^/]+$|(^|/)env/dec/' \
      | grep -vE '\.(example|sample|template)$' || true)
    [[ -z $bad ]] || { echo "plaintext environment files are tracked" >&2; exit 1; }
    shopt -s nullglob
    files=(env/enc/*.env.enc)
    [[ ${#files[@]} -gt 0 ]] || { echo "no encrypted environments" >&2; exit 1; }
    for file in "${files[@]}"; do
      grep -q 'ENC\[AES256_GCM' "$file" || { echo "$file is not encrypted" >&2; exit 1; }
      grep -q '^sops_mac=' "$file" || { echo "$file has no SOPS MAC" >&2; exit 1; }
      recipients=$(grep -c 'map_recipient' "$file" || true)
      [[ $recipients -ge 2 ]] || { echo "$file needs at least two age recipients" >&2; exit 1; }
    done
    echo "encrypted environment audit passed"
