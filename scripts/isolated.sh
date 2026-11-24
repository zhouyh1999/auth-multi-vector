#!/usr/bin/env bash
# Run from the workspace root on Linux. Only the toolchains and this copy are mounted.
set -euo pipefail
root=$(pwd -P)
test -f "$root/config.toml"
rust=${RUST_TOOLCHAIN_DIR:-$(rustc --print sysroot)}
py=${PYTHON_BIN:-$(command -v python3.10)}
py=$(readlink -f "$py")
pyroot=$("$py" -c 'import sys; print(sys.base_prefix)')
# Check existing path components before creating any directories on the host.
"$py" -I -S - "$root" <<'PY'
from pathlib import Path
import re, sys
root = Path(sys.argv[1])
for line in Path('/proc/self/mountinfo').read_text().splitlines():
    mount = Path(re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), line.split()[4]))
    if mount != root and mount.is_relative_to(root):
        sys.exit(f'nested mount in project: {mount}')
for name in ('artifacts/acceptance/home', 'artifacts/acceptance/tmp', 'artifacts/acceptance/cargo-home',
             'artifacts/acceptance/target', 'artifacts/acceptance/venv', 'docs/evidence'):
    dest = root / name
    if dest.resolve() != dest:
        sys.exit(f'linked work directory: {dest}')
PY
mkdir -p "$root/artifacts/acceptance"/{home,tmp,cargo-home}
args=(--unshare-net --unshare-pid --new-session --die-with-parent
      --ro-bind /usr /usr --ro-bind /etc /etc --ro-bind /sys /sys
      --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64
      --dev /dev --proc /proc --tmpfs /tmp)
if [[ "$rust" != /usr/* ]]; then args+=(--ro-bind "$rust" "$rust"); fi
if [[ "$pyroot" != /usr && "$pyroot" != /usr/* ]]; then args+=(--ro-bind "$pyroot" "$pyroot"); fi
exec env -i PATH=/usr/bin:/bin bwrap "${args[@]}" --bind "$root" "$root" --chdir "$root" \
    --setenv PATH "$root/third_party/native/bin:$rust/bin:$pyroot/bin:/usr/bin:/usr/sbin:/bin" \
    --setenv LD_LIBRARY_PATH "$root/third_party/native/lib" \
    --setenv HOME "$root/artifacts/acceptance/home" --setenv TMPDIR "$root/artifacts/acceptance/tmp" \
    --setenv CARGO_HOME "$root/artifacts/acceptance/cargo-home" --setenv CARGO_TARGET_DIR "$root/artifacts/acceptance/target" \
    --setenv CARGO_NET_OFFLINE true --setenv PYTHON "$py" --setenv PYTHONDONTWRITEBYTECODE 1 \
    --setenv PYTHONNOUSERSITE 1 --setenv LANG C.UTF-8 "$@"

