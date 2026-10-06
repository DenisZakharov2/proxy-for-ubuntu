#!/usr/bin/env bash
#
# Сборка .deb для proxy-for-ubuntu.
#
# Использует dpkg-deb напрямую, а не debhelper: на машине сборки не нужны
# fakeroot, dh и прочее. Скрипт полностью воспроизводим и запускается в CI
# на чистом ubuntu-latest.
#
#   ./scripts/build-deb.sh --output dist --version 0.1.0
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

OUTPUT="$ROOT/dist"
VERSION=""
ARCH="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
SKIP_BUILD=0
SKIP_TESTS=0

die() { echo "ошибка: $*" >&2; exit 1; }
info() { echo "  $*"; }

usage() {
    cat <<'EOF'
Использование: scripts/build-deb.sh [опции]

  --output DIR      куда положить .deb (по умолчанию ./dist)
  --version VER     версия пакета (по умолчанию из app/src-tauri/Cargo.toml)
  --arch ARCH       архитектура (по умолчанию из dpkg)
  --skip-build      не пересобирать бинарники, взять готовые из target/release
  --skip-tests      не запускать cargo test
  -h, --help        эта справка
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output) OUTPUT="$2"; shift 2 ;;
        --version) VERSION="$2"; shift 2 ;;
        --arch) ARCH="$2"; shift 2 ;;
        --skip-build) SKIP_BUILD=1; shift ;;
        --skip-tests) SKIP_TESTS=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "неизвестный аргумент: $1" ;;
    esac
done

export PATH="${HOME}/.cargo/bin:${PATH}"

# ── версия ──────────────────────────────────────────────────────────────────
if [[ -z "$VERSION" ]]; then
    VERSION="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$ROOT/app/src-tauri/Cargo.toml" | head -1)"
fi
[[ -n "$VERSION" ]] || die "не удалось определить версию"
PKG_VERSION="${VERSION}-1"
PKG="proxy-for-ubuntu_${VERSION}_${ARCH}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

echo "==> proxy-for-ubuntu $VERSION ($ARCH)"

# ── сборка фронтенда и бинарников ───────────────────────────────────────────
TARGET_DIR="$ROOT/app/src-tauri/target/release"
BINARIES=(proxy-for-ubuntu proxy-for-ubuntud pfu-cli)

if [[ $SKIP_BUILD -eq 0 ]]; then
    if [[ $SKIP_TESTS -eq 0 ]]; then
        echo "==> cargo test"
        (cd "$ROOT/app/src-tauri" && cargo test --lib --quiet) || die "тесты не прошли — сборка прервана"
    fi

    echo "==> frontend build"
    (cd "$ROOT/app" && npm ci --no-audit --no-fund && npm run build) \
        || die "сборка фронтенда не удалась"

    echo "==> cargo build --release"
    (cd "$ROOT/app/src-tauri" && cargo build --release --bins) || die "сборка Rust не удалась"
else
    info "сборка пропущена (--skip-build)"
fi

for b in "${BINARIES[@]}"; do
    [[ -x "$TARGET_DIR/$b" ]] || die "не найден бинарник $TARGET_DIR/$b"
done

# ── дерево пакета ───────────────────────────────────────────────────────────
echo "==> сборка дерева пакета"
install -d "$STAGE/DEBIAN"
install -d "$STAGE/usr/bin"
install -d "$STAGE/usr/lib/systemd/system"
install -d "$STAGE/usr/lib/polkit-1/actions"
install -d "$STAGE/usr/share/applications"
install -d "$STAGE/usr/share/icons/hicolor/scalable/apps"
install -d "$STAGE/usr/share/icons/hicolor/256x256/apps"
install -d "$STAGE/usr/share/proxy-for-ubuntu/profiles"
install -d "$STAGE/usr/share/proxy-for-ubuntu/geo/geoip"
install -d "$STAGE/usr/share/proxy-for-ubuntu/geo/geosite"
install -d "$STAGE/usr/share/doc/proxy-for-ubuntu"

for b in "${BINARIES[@]}"; do
    install -m 0755 "$TARGET_DIR/$b" "$STAGE/usr/bin/$b"
done

# systemd
install -m 0644 "$ROOT/packaging/systemd/proxy-for-ubuntud.service" \
    "$STAGE/usr/lib/systemd/system/proxy-for-ubuntud.service"
install -m 0644 "$ROOT/packaging/systemd/proxy-for-ubuntu-gui.service" \
    "$STAGE/usr/lib/systemd/system/proxy-for-ubuntu-gui.service"

# polkit
install -m 0644 "$ROOT/packaging/polkit/com.deniszakharov.proxyforubuntu.policy" \
    "$STAGE/usr/lib/polkit-1/actions/com.deniszakharov.proxyforubuntu.policy"

# desktop
install -m 0644 "$ROOT/packaging/desktop/proxy-for-ubuntu.desktop" \
    "$STAGE/usr/share/applications/proxy-for-ubuntu.desktop"

# иконки
install -m 0644 "$ROOT/packaging/icons/proxy-for-ubuntu.svg" \
    "$STAGE/usr/share/icons/hicolor/scalable/apps/proxy-for-ubuntu.svg"
install -m 0644 "$ROOT/packaging/icons/proxy-for-ubuntu-256.png" \
    "$STAGE/usr/share/icons/hicolor/256x256/apps/proxy-for-ubuntu.png" 2>/dev/null || \
    info "иконка 256x256 не найдена, пропускаю"

# профили и geo по умолчанию
install -m 0644 "$ROOT/packaging/profiles/default.yaml" \
    "$STAGE/usr/share/proxy-for-ubuntu/profiles/default.yaml"
install -m 0644 "$ROOT/packaging/profiles/example.yaml" \
    "$STAGE/usr/share/proxy-for-ubuntu/profiles/example.yaml"

# документация
for f in README.md README.en.md CHANGELOG.md LICENSE; do
    [[ -f "$ROOT/$f" ]] && install -m 0644 "$ROOT/$f" "$STAGE/usr/share/doc/proxy-for-ubuntu/$f"
done
[[ -d "$ROOT/docs" ]] && cp -r "$ROOT/docs" "$STAGE/usr/share/doc/proxy-for-ubuntu/"

# ── метаданные пакета ───────────────────────────────────────────────────────
cat > "$STAGE/DEBIAN/control" <<EOF
Package: proxy-for-ubuntu
Version: $PKG_VERSION
Section: net
Priority: optional
Architecture: $ARCH
Maintainer: Denis Zakharov <deniszakharov@msn.com>
Installed-Size: $(du -ks "$STAGE" | cut -f1)
Depends: libc6, adduser, nftables, iproute2, openssh-client
Recommends: policykit-1
Homepage: https://github.com/DenisZakharov2011/proxy-for-ubuntu
Description: system-wide proxy routing with a graphical interface
 proxy-for-ubuntu routes the whole system's TCP and UDP traffic through a
 proxy server, using nftables to intercept packets and a Clash-like rule
 engine to decide where each connection goes.
 .
 It ships its own implementations of the SOCKS5, HTTP CONNECT, Shadowsocks
 and Trojan protocols. DNS is resolved by the daemon itself, so domain names
 do not leak to the local resolver when the selected proxy takes them.
 .
 Applying a configuration is transactional: the daemon snapshots the current
 system state, validates the new configuration, verifies every outbound with
 a live connection, and rolls everything back if the system does not come up
 healthy afterwards.
EOF

install -m 0755 "$ROOT/debian/postinst" "$STAGE/DEBIAN/postinst"
install -m 0755 "$ROOT/debian/prerm"   "$STAGE/DEBIAN/prerm"
install -m 0755 "$ROOT/debian/postrm"  "$STAGE/DEBIAN/postrm"

# control-файлы не должны попасть в данные пакета
rm -f "$STAGE/DEBIAN/md5sums"

echo "==> dpkg-deb --build"
mkdir -p "$OUTPUT"
DEB_PATH="$OUTPUT/${PKG}.deb"
rm -f "$DEB_PATH"
dpkg-deb --root-owner-group --build "$STAGE" "$DEB_PATH" >/dev/null

# ── проверка результата ─────────────────────────────────────────────────────
echo "==> проверка"
dpkg-deb --info "$DEB_PATH" >/dev/null || die "повреждённый .deb"
dpkg-deb --contents "$DEB_PATH" >/dev/null || die "нечитаемое содержимое .deb"

if command -v lintian >/dev/null 2>&1; then
    lintian --no-tag-display-limit "$DEB_PATH" || info "lintian нашёл замечания (не критично)"
fi

SHA="$(sha256sum "$DEB_PATH" | cut -d' ' -f1)"
SIZE="$(du -h "$DEB_PATH" | cut -f1)"
echo "$SHA  ${PKG}.deb" > "$DEB_PATH.sha256"

echo
echo "готово:"
echo "  $DEB_PATH  ($SIZE)"
echo "  sha256: $SHA"
echo
echo "установка:"
echo "  sudo apt install ./${PKG}.deb"
