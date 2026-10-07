#!/usr/bin/env bash
#
# Публикация на GitHub.
#
# Скрипт существует, потому что публикация — это несколько шагов с
# чувствительными данными, и их нельзя набирать руками каждый раз.
# Токен читается из переменной окружения GITHUB_TOKEN и нигде не
# сохраняется: ни в истории команд, ни в файле.
#
#   GITHUB_TOKEN=github_pat_... ./scripts/publish.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

OWNER="${GITHUB_OWNER:-DenisZakharov2}"
REPO="${GITHUB_REPO:-proxy-for-ubuntu}"
API="https://api.github.com"
API_REPO="$API/repos/$OWNER/$REPO"

die() { echo "ошибка: $*" >&2; exit 1; }
info() { echo "  $*"; }

[[ -n "${GITHUB_TOKEN:-}" ]] || die "не задан GITHUB_TOKEN"

# ── 1. токен ───────────────────────────────────────────────────────────────
info "проверяю токен"
LOGIN="$(curl -sS -H "Authorization: Bearer $GITHUB_TOKEN" \
              -H "Accept: application/vnd.github+json" "$API/user" \
          | python3 -c 'import json,sys; print(json.load(sys.stdin).get("login",""))' 2>/dev/null || true)"
[[ -n "$LOGIN" ]] || die "токен не принят GitHub (проверьте, что он не истёк)"
info "авторизован как $LOGIN"

# ── 2. репозиторий ────────────────────────────────────────────────────────
if curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $GITHUB_TOKEN" \
       -H "Accept: application/vnd.github+json" "$API_REPO" | grep -q '^200$'; then
    info "репозиторий $OWNER/$REPO уже существует"
else
    info "репозиторий не найден, пробую создать"
    CODE="$(curl -sS -o /tmp/pfu_create.json -w '%{http_code}' -X POST \
            -H "Authorization: Bearer $GITHUB_TOKEN" \
            -H "Accept: application/vnd.github+json" \
            "$API/user/repos" \
            -d "{\"name\":\"$REPO\",\"description\":\"System-wide proxy routing for Ubuntu: transparent TCP/UDP interception with Clash-style rules. Own protocol implementations, no sing-box or Xray.\",\"private\":false,\"has_wiki\":true,\"has_issues\":true,\"topics\":[\"ubuntu\",\"proxy\",\"socks5\",\"shadowsocks\",\"trojan\",\"nftables\",\"vless\",\"vmess\",\"linux\",\"routing\",\"tproxy\",\"privacy\"]}")"
    if [[ "$CODE" == "201" ]]; then
        info "создан"
    else
        echo
        echo "GitHub отказал: $(python3 -c 'import json;print(json.load(open("/tmp/pfu_create.json")).get("message"))' 2>/dev/null || cat /tmp/pfu_create.json)"
        echo
        echo "Fine-grained токен не умеет создавать репозитории — это ограничение"
        echo "его типа, а не ошибка прав. Создайте пустой репозиторий в браузере:"
        echo
        echo "    https://github.com/new?name=$REPO"
        echo
        echo "и запустите скрипт снова. Флаги (галочки) можно не ставить —"
        echo "gitignore, лицензию и README мы добавим сами."
        echo
        exit 1
    fi
fi

# ── 3. push ───────────────────────────────────────────────────────────────
cd "$ROOT"
git remote set-url origin "https://github.com/$OWNER/$REPO.git"

info "пушу код"
URL="https://x-access-token:${GITHUB_TOKEN}@github.com/${OWNER}/${REPO}.git"
if ! GIT_TERMINAL_PROMPT=0 git push -u "https://x-access-token:${GITHUB_TOKEN}@github.com/${OWNER}/${REPO}.git" main 2>&1 | sed 's/x-access-token:[^@]*@/***@/'; then
    die "push не удался"
fi

# Токен не должен остаться в конфиге репозитория.
git remote set-url origin "https://github.com/$OWNER/$REPO.git"

# ── 4. релиз ──────────────────────────────────────────────────────────────
VERSION="$(sed -n 's/^version = "\(.*\)"$/\1/p' app/src-tauri/Cargo.toml | head -1)"
TAG="v${VERSION}"
info "ставлю тег $TAG"
git tag -a "$TAG" -m "proxy-for-ubuntu $VERSION" 2>/dev/null || info "тег уже существует"
GIT_TERMINAL_PROMPT=0 git push "https://x-access-token:${GITHUB_TOKEN}@github.com/${OWNER}/${REPO}.git" "$TAG" 2>&1 | sed 's/x-access-token:[^@]*@/***@/' || info "тег не отправлен"

# ── 5. раздел «Releases» ──────────────────────────────────────────────────
info "создаю релиз"
curl -sS -X POST -H "Authorization: Bearer $GITHUB_TOKEN" \
     -H "Accept: application/vnd.github+json" \
     "$API_REPO/releases" \
     -d "{\"tag_name\":\"$TAG\",\"name\":\"proxy-for-ubuntu $VERSION\",\"body\":\"Первая публичная версия.\\n\\nУстановка:\\n\\n\\\`\`\\\`bash\\nsudo apt install ./proxy-for-ubuntu_${VERSION}_amd64.deb\\n\\\`\\\`\\\`\\n\\nБинарник \\\`.deb\\\` соберётся в этом релизе автоматически через GitHub Actions.\\n\\nПротоколы \\\`vless\\\` и \\\`vmess\\\` реализованы, но не проверены против живого сервера — см. таблицу в README.\",\"draft\":false,\"prerelease\":false}" \
     | python3 -c 'import json,sys; d=json.load(sys.stdin); print("  релиз:", d.get("html_url") or d.get("message"))' 2>/dev/null || info "релиз создаст workflow"

echo
echo "готово: https://github.com/$OWNER/$REPO"
echo
echo "Теперь отзовите токен, если он больше не нужен:"
echo "  https://github.com/settings/personal-access-tokens"
