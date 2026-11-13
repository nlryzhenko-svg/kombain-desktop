#!/usr/bin/env bash
# Kombain node installer — VLESS+Reality, VLESS+XHTTP+Reality (Xray), Hysteria2, TUIC v5
# and a Telegram MTProto proxy (mtg, FakeTLS) on Debian/Ubuntu. No domain needed.
#
#   kombain-node.sh install  --host IP [--role single|entry] [--protocols vless,xhttp,hy2,tuic]
#                            [--sni www.microsoft.com] [--port 443] [--xh-port 8443] [--hy-port 443]
#                            [--tuic-port 8443] [--tg-port 9443] [--sd-port 8880] [--name "Мой сервер"] [--user "Телефон"]
#                            [--bridge] [--exit-link vless://...]
#                            [--fp firefox] [--antifreeze 1] [--sni-rotation 1] [--hop 0]
#   kombain-node.sh add-user NAME | remove-user NAME
#   kombain-node.sh links
#   kombain-node.sh status            (human readable)
#   kombain-node.sh stats             (KB_STATS <base64 JSON> for the app)
#   kombain-node.sh rotate [--port N] [--xh-port N] [--hy-port N] [--tuic-port N] [--tg-port N] [--sni HOST]
#                          new Reality keys, paths, passwords and user ids (old links stop working)
#   kombain-node.sh set-exit --exit-link vless://...   (entry node: point to a new exit)
#   kombain-node.sh enable-telegram [--tg-port N] | disable-telegram
#   kombain-node.sh enable-sudoku [--sd-port N] | disable-sudoku
#   kombain-node.sh find-sni [--host IP]     sites next to the server that suit Reality (KB_SNI <base64 JSON>)
#   kombain-node.sh set-sni --sni DOMAIN [--dest IP:443]   switch the masking site, keys stay
#   kombain-node.sh ensure-sub                subscription links for every user (HTTPS, pinned self-signed cert)
#   kombain-node.sh shuffle-ports             random new ports for the VPN protocols; keys, Telegram proxy and
#                                             the subscription stay as they are
#   kombain-node.sh auto-ports --every DAYS   shuffle ports on a schedule (0 = off)
#   kombain-node.sh harden [--antifreeze on|off] [--fp firefox|edge|chrome|safari|ios|android|360|qq|random|randomized]
#                          [--sni-rotation on|off] [--hop on|off]
#                          protection against DPI «freezes» (ТСПУ):
#                            antifreeze   — XHTTP: VLESS Encryption + Vision, stream-one, at most 2 connections (XMUX)
#                            fp           — browser TLS fingerprint in the links
#                            sni-rotation — 2–3 names of the masking site; Kombain spreads connections over them
#                            hop          — Hysteria2 port hopping over a range of 1000 UDP ports
#   kombain-node.sh export                    KB_EXPORT <base64 tar.gz>: keys, users, settings — a backup the app keeps
#   kombain-node.sh import --host IP --data BASE64 [--force]
#                                             move a server here from such a backup: same keys, users and links
#                                             (only the address changes)
#   kombain-node.sh uninstall
#
# With KB_WITH_EXPORT=1 every command that prints KB_RESULT also prints KB_EXPORT.
#
# Protocols: vless, xhttp, hy2, tuic, tg (Telegram proxy: one tg:// link for everybody),
#            sudoku (github.com/SUDOKU-ASCII/sudoku: traffic encoded as Sudoku puzzles — low-entropy,
#            looks like plain text; single nodes only, it can't hand traffic to a cascade's exit).
# Roles:
#   single — standalone node: clients exit to the internet from here.
#   entry  — first hop of a cascade: clients connect here, traffic leaves through the
#            exit node given by --exit-link (Russian sites go out directly).
#   --bridge on a single node also creates the credential an entry node uses to reach it.
#
# Output protocol (parsed by the Kombain app):
#   KB_STEP <text>     progress line
#   KB_ERROR <text>    fatal error
#   KB_RESULT <base64 JSON>  {"links":[{"user":..,"proto":..,"link":..}], "bridge": "vless://...",
#                             "telegram": "tg://proxy?...", "subs": [{"user":..,"url":..}], "info": {...}}
#   KB_SNI <base64 JSON>     [{"domain":..,"dest":"ip:443","ms":..}] best first
#   KB_STATS  <base64 JSON>  see cmd_stats
#   KB_EXPORT <base64 tar.gz> backup of $KB_DIR (see cmd_export)
set -euo pipefail

KB_DIR=${KB_DIR:-/etc/kombain}
KB_BIN=${KB_BIN:-/usr/local/bin}
KB_SHARE=${KB_SHARE:-/usr/local/share/kombain}
KB_SYSTEMD=${KB_SYSTEMD:-1}          # 0 = don't touch systemd/firewall (testing)
KB_DOWNLOAD=${KB_DOWNLOAD:-1}        # 0 = binaries are already in $KB_BIN (testing)
KB_TEST=${KB_TEST:-0}                # 1 = allow private targets, custom Reality target (testing only)
KB_REALITY_TARGET=${KB_REALITY_TARGET:-}
KB_SOCKS_PORT=${KB_SOCKS_PORT:-10808}  # local hand-off from Hysteria2 / TUIC to Xray
KB_API_PORT=${KB_API_PORT:-10085}      # Xray stats API (localhost only)
XRAY_URL_BASE=${XRAY_URL_BASE:-https://github.com/XTLS/Xray-core/releases/latest/download}
HY_URL_BASE=${HY_URL_BASE:-https://github.com/apernet/hysteria/releases/latest/download}
SB_REPO=${SB_REPO:-https://github.com/SagerNet/sing-box}
MTG_REPO=${MTG_REPO:-https://github.com/9seconds/mtg}
SD_URL_BASE=${SD_URL_BASE:-https://github.com/SUDOKU-ASCII/sudoku/releases/latest/download}

step() { echo "KB_STEP $*"; }
die() { echo "KB_ERROR $*"; exit 1; }
trap 'echo "KB_ERROR команда завершилась с ошибкой (строка $LINENO)"' ERR

need_root() { [ "$(id -u)" = 0 ] || die "нужны права root (запустите через sudo)"; }

# ---------------------------------------------------------------------------- state

state_file() { echo "$KB_DIR/state.env"; }
users_file() { echo "$KB_DIR/users"; }

load_state() {
  [ -f "$(state_file)" ] || die "Kombain на этом сервере ещё не установлен"
  # shellcheck disable=SC1090
  . "$(state_file)"
  XH_PORT=${XH_PORT:-8443}; TUIC_PORT=${TUIC_PORT:-8443}; XH_PATH=${XH_PATH:-/$(rand_hex 6)}
  TG_PORT=${TG_PORT:-9443}; TG_SECRET=${TG_SECRET:-}; DEST=${DEST:-}; SUB_PORT=${SUB_PORT:-}; AUTO_PORTS=${AUTO_PORTS:-0}
  FP=${FP:-firefox}; ANTIFREEZE=${ANTIFREEZE:-0}; XH_DEC=${XH_DEC:-}; XH_ENC=${XH_ENC:-}
  SNI_ROT=${SNI_ROT:-0}; SNI_ALTS=${SNI_ALTS:-}; HY_HOP=${HY_HOP:-}
  SD_PORT=${SD_PORT:-8880}; SD_PUB=${SD_PUB:-}; SD_MPRIV=${SD_MPRIV:-}
}

save_state() {
  mkdir -p "$KB_DIR"; chmod 700 "$KB_DIR"
  {
    for v in ROLE HOST PROTOCOLS SNI PORT XH_PORT XH_PATH HY_PORT TUIC_PORT TG_PORT TG_SECRET DEST SUB_PORT AUTO_PORTS FP ANTIFREEZE XH_DEC XH_ENC SNI_ROT SNI_ALTS HY_HOP SD_PORT SD_PUB SD_MPRIV NAME PRIV PUB SID HY_OBFS BRIDGE_UUID \
             EXIT_ADDR EXIT_PORT EXIT_UUID EXIT_FLOW EXIT_SNI EXIT_PBK EXIT_SID EXIT_FP; do
      printf "%s=%q\n" "$v" "${!v-}"
    done
  } > "$(state_file)"
  chmod 600 "$(state_file)"
}

has_proto() { case ",$PROTOCOLS," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }

urlenc() { python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "$1" 2>/dev/null \
  || printf '%s' "$1" | od -An -tx1 | tr -d ' \n' | sed 's/../%&/g'; }

rand_hex() { openssl rand -hex "$1"; }
hex_str() { printf '%s' "$1" | od -An -tx1 | tr -d ' \n'; }
json_str() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

# ---------------------------------------------------------------------------- install deps

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) XRAY_ARCH=64; HY_ARCH=amd64; SB_ARCH=amd64; MTG_ARCH=amd64 ;;
    aarch64|arm64) XRAY_ARCH=arm64-v8a; HY_ARCH=arm64; SB_ARCH=arm64; MTG_ARCH=arm64 ;;
    armv7l) XRAY_ARCH=arm32-v7a; HY_ARCH=arm; SB_ARCH=armv7; MTG_ARCH=armv7 ;;
    *) die "неподдерживаемая архитектура $(uname -m)" ;;
  esac
}

install_packages() {
  local missing=()
  for c in curl unzip openssl; do command -v "$c" >/dev/null || missing+=("$c"); done
  [ ${#missing[@]} -eq 0 ] && return 0
  step "Ставлю пакеты: ${missing[*]}"
  if command -v apt-get >/dev/null; then
    DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${missing[@]}" >/dev/null
  elif command -v dnf >/dev/null; then dnf install -y -q "${missing[@]}" >/dev/null
  elif command -v yum >/dev/null; then yum install -y -q "${missing[@]}" >/dev/null
  else die "не найден apt/dnf/yum — поставьте вручную: ${missing[*]}"; fi
}

download_binaries() {
  [ "$KB_DOWNLOAD" = 1 ] || return 0
  detect_arch
  local tmp; tmp=$(mktemp -d)
  mkdir -p "$KB_BIN" "$KB_SHARE"
  step "Скачиваю Xray-core"
  curl -fsSL --retry 3 -o "$tmp/xray.zip" "$XRAY_URL_BASE/Xray-linux-$XRAY_ARCH.zip" || die "не удалось скачать Xray (нет доступа к GitHub?)"
  unzip -qo "$tmp/xray.zip" -d "$tmp/xray"
  install -m 755 "$tmp/xray/xray" "$KB_BIN/kombain-xray"
  install -m 644 "$tmp/xray/geoip.dat" "$tmp/xray/geosite.dat" "$KB_SHARE/"
  if has_proto hy2; then
    step "Скачиваю Hysteria2"
    curl -fsSL --retry 3 -o "$tmp/hysteria" "$HY_URL_BASE/hysteria-linux-$HY_ARCH" || die "не удалось скачать Hysteria2"
    install -m 755 "$tmp/hysteria" "$KB_BIN/kombain-hysteria"
  fi
  if has_proto tuic && [ ! -x "$KB_BIN/kombain-singbox" ]; then
    step "Скачиваю sing-box (для TUIC)"
    local tag ver
    tag=$(curl -fsSI "$SB_REPO/releases/latest" 2>/dev/null | awk -F/ 'tolower($0) ~ /^location:/ {print $NF}' | tr -d '\r' || true)
    [ -n "$tag" ] || tag=$(curl -fsSL https://api.github.com/repos/SagerNet/sing-box/releases/latest 2>/dev/null \
      | grep -o '"tag_name": *"[^"]*"' | head -1 | grep -o 'v[^"]*' || true)
    ver=${tag#v}
    [ -n "$ver" ] || die "не удалось узнать версию sing-box"
    curl -fsSL --retry 3 -o "$tmp/sb.tgz" "$SB_REPO/releases/download/$tag/sing-box-$ver-linux-$SB_ARCH.tar.gz" || die "не удалось скачать sing-box"
    tar -xzf "$tmp/sb.tgz" -C "$tmp"
    install -m 755 "$tmp/sing-box-$ver-linux-$SB_ARCH/sing-box" "$KB_BIN/kombain-singbox"
  fi
  rm -rf "$tmp"
  if has_proto tg; then download_mtg; fi
  if has_proto sudoku; then download_sudoku; fi
  return 0
}

download_sudoku() {
  [ "$KB_DOWNLOAD" = 1 ] || return 0
  [ -x "$KB_BIN/kombain-sudoku" ] && return 0
  detect_arch
  case $SB_ARCH in amd64|arm64) ;; *) die "для Sudoku нет сборки под $(uname -m)" ;; esac
  step "Скачиваю Sudoku"
  local tmp; tmp=$(mktemp -d)
  curl -fsSL --retry 3 -o "$tmp/sd.tgz" "$SD_URL_BASE/sudoku-linux-$SB_ARCH.tar.gz" || die "не удалось скачать Sudoku"
  tar -xzf "$tmp/sd.tgz" -C "$tmp"
  install -m 755 "$tmp/sudoku" "$KB_BIN/kombain-sudoku"
  rm -rf "$tmp"
}

# Sudoku keys: the server holds the master public key, every user gets its own client key split from the
# master private key (the server's whitelist tells users apart). Kept in $KB_DIR/sudoku.keys as "name|key".
sd_out() { "$KB_BIN/kombain-sudoku" "$@" 2>&1 || true; }

sd_keygen() {
  local out; out=$(sd_out -keygen)
  SD_MPRIV=$(echo "$out" | sed -n 's/.*Master Private Key: *//p' | tr -d ' \r')
  SD_PUB=$(echo "$out" | sed -n 's/.*Master Public Key: *//p' | tr -d ' \r')
  [ -n "$SD_MPRIV" ] && [ -n "$SD_PUB" ] || die "не удалось создать ключи Sudoku"
  : > "$KB_DIR/sudoku.keys"; chmod 600 "$KB_DIR/sudoku.keys"
}

sd_user_key() { # name -> client key (created on first use)
  local f="$KB_DIR/sudoku.keys" k
  k=$(awk -F'|' -v n="$1" '$1 == n {print $2; exit}' "$f" 2>/dev/null || true)
  if [ -z "$k" ]; then
    k=$(sd_out -keygen -more "$SD_MPRIV" | sed -n 's/.*Split Private Key: *//p' | tr -d ' \r')
    [ -n "$k" ] || die "не удалось создать ключ Sudoku для «$1»"
    printf '%s|%s\n' "$1" "$k" >> "$f"; chmod 600 "$f"
  fi
  echo "$k"
}

b64url() { base64 | tr -d '\n=' | tr '+/' '-_'; }

sd_link() { # name label -> sudoku:// short link (the format of the official clients)
  local k; k=$(sd_user_key "$1")
  printf '{"n":"%s","h":"%s","p":%s,"k":"%s","a":"entropy","e":"chacha20-poly1305","hm":"ws"}' \
    "$(json_str "$2")" "$HOST" "$SD_PORT" "$k" | b64url | sed 's/^/sudoku:\/\//'
}

latest_tag() { # repo url -> vX.Y.Z (the releases/latest redirect, then the API)
  local repo=$1 tag
  tag=$(curl -fsSI "$repo/releases/latest" 2>/dev/null | awk -F/ 'tolower($0) ~ /^location:/ {print $NF}' | tr -d '\r' || true)
  [ -n "$tag" ] || tag=$(curl -fsSL "https://api.github.com/repos/${repo#https://github.com/}/releases/latest" 2>/dev/null \
    | grep -o '"tag_name": *"[^"]*"' | head -1 | grep -o 'v[^"]*' || true)
  echo "$tag"
}

download_mtg() {
  [ "$KB_DOWNLOAD" = 1 ] || return 0
  [ -x "$KB_BIN/kombain-mtg" ] && return 0
  detect_arch
  step "Скачиваю mtg (прокси для Telegram)"
  local tmp tag ver; tmp=$(mktemp -d)
  tag=$(latest_tag "$MTG_REPO"); ver=${tag#v}
  [ -n "$ver" ] || die "не удалось узнать версию mtg"
  curl -fsSL --retry 3 -o "$tmp/mtg.tgz" "$MTG_REPO/releases/download/$tag/mtg-$ver-linux-$MTG_ARCH.tar.gz" || die "не удалось скачать mtg"
  tar -xzf "$tmp/mtg.tgz" -C "$tmp"
  install -m 755 "$tmp/mtg-$ver-linux-$MTG_ARCH/mtg" "$KB_BIN/kombain-mtg"
  rm -rf "$tmp"
}

# ---------------------------------------------------------------------------- configs

gen_keys() {
  step "Генерирую ключи Reality"
  local out; out=$("$KB_BIN/kombain-xray" x25519)
  PRIV=$(echo "$out" | awk -F': *' 'tolower($1) ~ /private/ {print $2; exit}')
  PUB=$(echo "$out" | awk -F': *' 'tolower($1) ~ /public|password/ {print $2; exit}')
  [ -n "$PRIV" ] && [ -n "$PUB" ] || die "не удалось получить ключи Reality"
  SID=$(rand_hex 8)
  HY_OBFS=$(rand_hex 16)
  XH_PATH=/$(rand_hex 6)
  new_tg_secret
  XH_DEC=""; XH_ENC=""
  [ "${ANTIFREEZE:-0}" = 1 ] && gen_vlessenc
  return 0
}

FPS="firefox edge chrome safari ios android 360 qq random randomized"

# VLESS Encryption key pair (X25519 authentication) for the XHTTP inbound
gen_vlessenc() {
  local out
  out=$("$KB_BIN/kombain-xray" vlessenc 2>/dev/null || true)
  if [ -z "$out" ] && [ "$KB_DOWNLOAD" = 1 ]; then
    step "Обновляю Xray-core (нужна версия с VLESS Encryption)"
    detect_arch
    local tmp; tmp=$(mktemp -d)
    curl -fsSL --retry 3 -o "$tmp/xray.zip" "$XRAY_URL_BASE/Xray-linux-$XRAY_ARCH.zip" || die "не удалось скачать Xray"
    unzip -qo "$tmp/xray.zip" -d "$tmp/xray"
    install -m 755 "$tmp/xray/xray" "$KB_BIN/kombain-xray"
    rm -rf "$tmp"
    out=$("$KB_BIN/kombain-xray" vlessenc 2>/dev/null || true)
  fi
  XH_DEC=$(echo "$out" | awk -F'"' '/"decryption"/ {print $4; exit}')
  XH_ENC=$(echo "$out" | awk -F'"' '/"encryption"/ {print $4; exit}')
  [ -n "$XH_DEC" ] && [ -n "$XH_ENC" ] || die "Xray-core на сервере не умеет VLESS Encryption"
}

cert_sha() { # target host:port, servername -> sha256 of the certificate it presents ("" on any failure)
  local pem
  pem=$(timeout 6 openssl s_client -connect "$1" -servername "$2" </dev/null 2>/dev/null | openssl x509 2>/dev/null || true)
  [ -n "$pem" ] || return 0
  { printf '%s\n' "$pem" | openssl x509 -outform DER 2>/dev/null | openssl dgst -sha256 -r 2>/dev/null | cut -d' ' -f1; } || true
}

# Other names of the masking site served by the same address with the same certificate:
# Reality accepts all of them, and the app spreads connections over them (no burst to one name).
find_sni_alts() {
  SNI_ALTS=""
  local target=${KB_REALITY_TARGET:-${DEST:-$SNI:443}} main names n=0 tries=0 c
  main=$(cert_sha "$target" "$SNI")
  [ -n "$main" ] || { step "Не удалось проверить сертификат $SNI — чередование выключено"; return 0; }
  # -text instead of -ext subjectAltName: works with older OpenSSL too
  names=$({ timeout 6 openssl s_client -connect "$target" -servername "$SNI" </dev/null 2>/dev/null \
    | openssl x509 -noout -text 2>/dev/null | grep -A1 'Subject Alternative Name' | tail -1 \
    | tr ',' '\n' | sed -n 's/^ *DNS://p'; } || true)
  for c in $names; do
    case $c in "$SNI"|*'*'*|*[!a-zA-Z0-9.-]*) continue ;; esac
    [[ $c == *.* ]] || continue
    tries=$((tries + 1)); [ $tries -gt 12 ] && break
    [ "$(cert_sha "$target" "$c")" = "$main" ] || continue
    SNI_ALTS+="${SNI_ALTS:+,}$c"; n=$((n + 1)); [ $n -ge 2 ] && break
  done
  if [ $n -gt 0 ]; then step "Чередование имён сайта: $SNI, ${SNI_ALTS//,/, }"
  else step "У сайта $SNI нет других подходящих имён — чередовать нечего"; fi
  return 0
}

# a range of 1000 UDP ports for Hysteria2 port hopping that no other Kombain port falls into
pick_hop() {
  local used=" $(busy_ports | tr '\n' ' ') " fixed="$PORT $XH_PORT $TUIC_PORT $TG_PORT ${SUB_PORT:-0} $KB_SOCKS_PORT $KB_API_PORT $HY_PORT" a b i x ok
  for i in $(seq 1 100); do
    a=$((20000 + RANDOM % 39000)); b=$((a + 999)); ok=1
    for x in $fixed $used; do
      [[ $x =~ ^[0-9]+$ ]] || continue
      if [ "$x" -ge "$a" ] && [ "$x" -le "$b" ]; then ok=0; break; fi
    done
    [ $ok = 1 ] && { echo "$a-$b"; return 0; }
  done
  die "не нашёл свободный диапазон портов"
}

in_hop() { [ -n "${HY_HOP:-}" ] && [ "$1" -ge "${HY_HOP%-*}" ] && [ "$1" -le "${HY_HOP#*-}" ]; }

# FakeTLS secret: "ee" + 16 random bytes + the masking domain (Telegram sends it as SNI)
new_tg_secret() { TG_SECRET=ee$(rand_hex 16)$(hex_str "$SNI"); }

new_user_line() { # name [token] -> "name|uuid|hypass|token" (the token keeps the subscription link stable)
  printf '%s|%s|%s|%s\n' "$1" "$("$KB_BIN/kombain-xray" uuid)" "$(rand_hex 16)" "${2:-$(rand_hex 16)}"
}

# users added before subscriptions existed get a token
ensure_tokens() {
  local tmp; tmp=$(mktemp)
  while IFS='|' read -r name uuid hypass token; do
    [ -n "$uuid" ] || continue
    printf '%s|%s|%s|%s\n' "$name" "$uuid" "$hypass" "${token:-$(rand_hex 16)}"
  done < "$(users_file)" > "$tmp"
  cat "$tmp" > "$(users_file)"; rm -f "$tmp"
}

parse_exit_link() { # vless://uuid@host:port?query#name
  local link=$1 rest q
  [[ $link == vless://* ]] || die "ссылка выходной ноды должна быть vless://"
  rest=${link#vless://}; rest=${rest%%#*}
  EXIT_UUID=${rest%%@*}; rest=${rest#*@}
  q=${rest#*\?}; rest=${rest%%\?*}
  EXIT_PORT=${rest##*:}; EXIT_ADDR=${rest%:*}; EXIT_ADDR=${EXIT_ADDR#[}; EXIT_ADDR=${EXIT_ADDR%]}
  getq() { echo "$q" | tr '&' '\n' | awk -F= -v k="$1" '$1==k {print $2; exit}'; }
  EXIT_FLOW=$(getq flow); EXIT_SNI=$(getq sni); EXIT_PBK=$(getq pbk); EXIT_SID=$(getq sid); EXIT_FP=$(getq fp)
  EXIT_FP=${EXIT_FP:-chrome}
  [ -n "$EXIT_UUID" ] && [ -n "$EXIT_PBK" ] && [ -n "$EXIT_SNI" ] || die "в ссылке выходной ноды не хватает данных Reality"
}

json_clients() { # $1 = flow ("" for XHTTP)
  local first=1 flow=${1-}
  while IFS='|' read -r name uuid _; do
    [ -n "$uuid" ] || continue
    [ $first = 1 ] || printf ','
    first=0
    printf '{"id":"%s","flow":"%s","email":"%s"}' "$uuid" "$flow" "$(echo "$name" | sed 's/["\\]//g')"
  done < "$(users_file)"
  if [ -n "${BRIDGE_UUID-}" ]; then
    [ $first = 1 ] || printf ','
    printf '{"id":"%s","flow":"%s","email":"kombain-bridge"}' "$BRIDGE_UUID" "$flow"
  fi
}

render_xray() {
  local ru_rules="" outbound_main="direct" extra_out="" socks_in="" xh_in="" vless_in="" freedom_settings=""
  [ "$KB_TEST" = 1 ] && freedom_settings=', "settings": {"finalRules": [{"action": "allow"}]}'
  local names="\"$SNI\"" a
  for a in ${SNI_ALTS//,/ }; do names+=",\"$a\""; done
  local reality; reality=$(printf '"security":"reality","realitySettings":{"target":"%s","serverNames":[%s],"privateKey":"%s","shortIds":["%s"]}' \
    "${KB_REALITY_TARGET:-${DEST:-$SNI:443}}" "$names" "$PRIV" "$SID")
  local sniff='"sniffing":{"enabled":true,"destOverride":["http","tls","quic"],"routeOnly":true}'
  # the main VLESS inbound always exists: entry nodes and the bridge use it
  vless_in=$(printf '{"tag":"vless-in","listen":"0.0.0.0","port":%s,"protocol":"vless","settings":{"clients":[%s],"decryption":"none"},"streamSettings":{"network":"raw",%s},%s}' \
    "$PORT" "$(json_clients xtls-rprx-vision)" "$reality" "$sniff")
  if has_proto xhttp; then
    # «против заморозки»: VLESS Encryption + Vision inside XHTTP (the client also uses stream-one and XMUX)
    local xh_flow="" xh_dec=none
    if [ "${ANTIFREEZE:-0}" = 1 ] && [ -n "$XH_DEC" ]; then xh_flow=xtls-rprx-vision; xh_dec=$XH_DEC; fi
    xh_in=$(printf ',{"tag":"xhttp-in","listen":"0.0.0.0","port":%s,"protocol":"vless","settings":{"clients":[%s],"decryption":"%s"},"streamSettings":{"network":"xhttp","xhttpSettings":{"path":"%s","mode":"auto"},%s},%s}' \
      "$XH_PORT" "$(json_clients "$xh_flow")" "$xh_dec" "$XH_PATH" "$reality" "$sniff")
  fi
  if has_proto hy2 || has_proto tuic || has_proto tg; then
    socks_in=',{"tag":"hy-in","listen":"127.0.0.1","port":'"$KB_SOCKS_PORT"',"protocol":"socks","settings":{"udp":true}}'
  fi
  if [ "$ROLE" = entry ]; then
    outbound_main="to-exit"
    extra_out=$(printf ',{"tag":"to-exit","protocol":"vless","settings":{"vnext":[{"address":"%s","port":%s,"users":[{"id":"%s","encryption":"none","flow":"%s"}]}]},"streamSettings":{"network":"raw","security":"reality","realitySettings":{"serverName":"%s","fingerprint":"%s","publicKey":"%s","shortId":"%s"}}}' \
      "$EXIT_ADDR" "$EXIT_PORT" "$EXIT_UUID" "${EXIT_FLOW:-xtls-rprx-vision}" "$EXIT_SNI" "$EXIT_FP" "$EXIT_PBK" "$EXIT_SID")
    if [ -f "$KB_SHARE/geosite.dat" ]; then
      ru_rules='{"type":"field","domain":["geosite:category-ru"],"outboundTag":"direct"},{"type":"field","ip":["geoip:ru"],"outboundTag":"direct"},'
    fi
  fi
  cat > "$KB_DIR/xray.json" <<EOF
{
  "log": {"loglevel": "warning"},
  "api": {"tag": "api", "listen": "127.0.0.1:$KB_API_PORT", "services": ["StatsService"]},
  "stats": {},
  "policy": {"levels": {"0": {"statsUserUplink": true, "statsUserDownlink": true}},
             "system": {"statsInboundUplink": true, "statsInboundDownlink": true}},
  "inbounds": [$vless_in$xh_in$socks_in],
  "outbounds": [{"tag": "direct", "protocol": "freedom"$freedom_settings}, {"tag": "block", "protocol": "blackhole"}$extra_out],
  "routing": {"domainStrategy": "IPIfNonMatch", "rules": [
    ${ru_rules}
    {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"},
    {"type": "field", "network": "tcp,udp", "outboundTag": "$outbound_main"}
  ]}
}
EOF
  # geoip:private needs geoip.dat; drop the rule if it is missing (testing setups)
  if [ ! -f "$KB_SHARE/geoip.dat" ] || [ "$KB_TEST" = 1 ]; then
    sed -i '/"geoip:private"/d' "$KB_DIR/xray.json"
  fi
  chmod 600 "$KB_DIR/xray.json"
}

ensure_cert() {
  if [ ! -f "$KB_DIR/hy.crt" ]; then
    openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -days 3650 \
      -keyout "$KB_DIR/hy.key" -out "$KB_DIR/hy.crt" -subj "/CN=$SNI" >/dev/null 2>&1
    chmod 600 "$KB_DIR/hy.key"
  fi
}

render_tuic() {
  has_proto tuic || { rm -f "$KB_DIR/tuic.json"; return 0; }
  ensure_cert
  local users="" first=1 i=0
  while IFS='|' read -r _ uuid hypass _; do
    [ -n "$uuid" ] || continue
    i=$((i + 1))
    [ $first = 1 ] || users+=","; first=0
    users+=$(printf '{"name":"u%s","uuid":"%s","password":"%s"}' "$i" "$uuid" "$hypass")
  done < "$(users_file)"
  cat > "$KB_DIR/tuic.json" <<EOF
{
  "log": {"level": "warn"},
  "inbounds": [{"type": "tuic", "tag": "tuic-in", "listen": "::", "listen_port": $TUIC_PORT,
    "users": [$users], "congestion_control": "bbr",
    "tls": {"enabled": true, "server_name": "$SNI", "alpn": ["h3"],
            "certificate_path": "$KB_DIR/hy.crt", "key_path": "$KB_DIR/hy.key"}}],
  "outbounds": [{"type": "socks", "tag": "xray", "server": "127.0.0.1", "server_port": $KB_SOCKS_PORT}]
}
EOF
  chmod 600 "$KB_DIR/tuic.json"
}

render_hysteria() {
  has_proto hy2 || return 0
  ensure_cert
  {
    echo "listen: :$HY_PORT"
    echo "tls:"
    echo "  cert: $KB_DIR/hy.crt"
    echo "  key: $KB_DIR/hy.key"
    echo "obfs:"
    echo "  type: salamander"
    echo "  salamander:"
    echo "    password: $HY_OBFS"
    echo "auth:"
    echo "  type: userpass"
    echo "  userpass:"
    local i=0
    while IFS='|' read -r _ _ hypass _; do
      [ -n "$hypass" ] || continue
      i=$((i + 1)); echo "    u$i: $hypass"
    done < "$(users_file)"
    echo "masquerade:"
    echo "  type: proxy"
    echo "  proxy:"
    echo "    url: https://$SNI/"
    echo "    rewriteHost: true"
    # all traffic goes through Xray, so routing (direct / cascade) is the same for both protocols
    echo "outbounds:"
    echo "  - name: xray"
    echo "    type: socks5"
    echo "    socks5:"
    echo "      addr: 127.0.0.1:$KB_SOCKS_PORT"
  } > "$KB_DIR/hysteria.yaml"
  chmod 600 "$KB_DIR/hysteria.yaml"
}

# Hysteria2 port hopping: the UDP range HY_HOP is redirected to HY_PORT (nftables, or iptables)
render_hop() {
  local f="$KB_DIR/hop.sh"
  if [ -z "${HY_HOP:-}" ] || ! has_proto hy2; then rm -f "$f"; return 0; fi
  local a=${HY_HOP%-*} b=${HY_HOP#*-}
  if command -v nft >/dev/null; then
    cat > "$f" <<EOF
#!/bin/sh
# Kombain: Hysteria2 port hopping $a-$b/udp -> $HY_PORT
case \$1 in
  up) nft -f - <<'NFT'
table inet kombain_hop
delete table inet kombain_hop
table inet kombain_hop {
  chain pre {
    type nat hook prerouting priority dstnat; policy accept;
    udp dport $a-$b redirect to :$HY_PORT
  }
}
NFT
  ;;
  down) nft delete table inet kombain_hop 2>/dev/null; true ;;
esac
EOF
  else
    cat > "$f" <<EOF
#!/bin/sh
# Kombain: Hysteria2 port hopping $a-$b/udp -> $HY_PORT
for t in iptables ip6tables; do
  command -v \$t >/dev/null || continue
  \$t -t nat -D PREROUTING -j KOMBAIN_HOP 2>/dev/null
  \$t -t nat -F KOMBAIN_HOP 2>/dev/null; \$t -t nat -X KOMBAIN_HOP 2>/dev/null
  [ "\$1" = up ] || continue
  \$t -t nat -N KOMBAIN_HOP
  \$t -t nat -A KOMBAIN_HOP -p udp --dport $a:$b -j REDIRECT --to-ports $HY_PORT
  \$t -t nat -I PREROUTING -j KOMBAIN_HOP
done
true
EOF
  fi
  chmod 700 "$f"
}

apply_hop() {
  [ "$KB_SYSTEMD" = 1 ] || return 0
  if [ -f "$KB_DIR/hop.sh" ]; then
    cat > /etc/systemd/system/kombain-hop.service <<EOF
[Unit]
Description=Kombain: Hysteria2 port hopping
After=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh $KB_DIR/hop.sh up
ExecStop=/bin/sh $KB_DIR/hop.sh down
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable kombain-hop >/dev/null 2>&1 || true
    sh "$KB_DIR/hop.sh" up || die "не удалось включить прыжки портов (нет nftables/iptables?)"
    systemctl restart kombain-hop >/dev/null 2>&1 || true
  else
    nft delete table inet kombain_hop 2>/dev/null || true
    local t
    for t in iptables ip6tables; do
      command -v $t >/dev/null || continue
      $t -t nat -D PREROUTING -j KOMBAIN_HOP 2>/dev/null || true
      $t -t nat -F KOMBAIN_HOP 2>/dev/null || true; $t -t nat -X KOMBAIN_HOP 2>/dev/null || true
    done
    if [ -f /etc/systemd/system/kombain-hop.service ]; then
      systemctl disable --now kombain-hop >/dev/null 2>&1 || true
      rm -f /etc/systemd/system/kombain-hop.service
      systemctl daemon-reload
    fi
  fi
  return 0
}

render_sudoku() {
  has_proto sudoku || { rm -f "$KB_DIR/sudoku.json" "$KB_DIR/sudoku.keys"; return 0; }
  [ -n "$SD_PUB" ] && [ -n "$SD_MPRIV" ] || sd_keygen
  local users="" first=1 name k fallback
  # keys of removed users go away
  if [ -f "$KB_DIR/sudoku.keys" ]; then
    local tmp; tmp=$(mktemp)
    awk -F'|' 'NR == FNR {keep[$1] = 1; next} keep[$1]' "$(users_file)" "$KB_DIR/sudoku.keys" > "$tmp" || true
    cat "$tmp" > "$KB_DIR/sudoku.keys"; rm -f "$tmp"
  fi
  while IFS='|' read -r name _; do
    [ -n "$name" ] || continue
    k=$(sd_user_key "$name")
    [ $first = 1 ] || users+=","; first=0
    users+=$(printf '{"alias":"%s","key":"%s"}' "$(json_str "$name")" "$k")
  done < "$(users_file)"
  # a probe that fails the handshake gets the masking site's plain HTTP answer
  fallback="$SNI:80"; [ "$KB_TEST" = 1 ] && fallback="127.0.0.1:80"
  cat > "$KB_DIR/sudoku.json" <<EOF
{"mode": "server", "transport": "tcp", "local_port": $SD_PORT, "fallback_address": "$fallback",
 "key": "$SD_PUB", "aead": "chacha20-poly1305", "suspicious_action": "fallback",
 "padding_min": 5, "padding_max": 15, "ascii": "prefer_entropy", "enable_pure_downlink": true,
 "multiplex": "off", "httpmask": {"disable": false, "mode": "auto"},
 "users": [$users]}
EOF
  chmod 600 "$KB_DIR/sudoku.json"
}

render_mtg() {
  has_proto tg || { rm -f "$KB_DIR/mtg.toml"; return 0; }
  [ -n "$TG_SECRET" ] || new_tg_secret
  # on a cascade entry node Telegram traffic goes through Xray to the exit node
  local proxies=""
  [ "$ROLE" = entry ] && proxies="\"socks5://127.0.0.1:$KB_SOCKS_PORT\""
  cat > "$KB_DIR/mtg.toml" <<EOF
secret = "$TG_SECRET"
bind-to = "0.0.0.0:$TG_PORT"
prefer-ip = "prefer-ipv4"

[network]
proxies = [$proxies]

[defense.blocklist]
enabled = false
EOF
  chmod 600 "$KB_DIR/mtg.toml"
}

# ---------------------------------------------------------------------------- services

write_units() {
  [ "$KB_SYSTEMD" = 1 ] || return 0
  cat > /etc/systemd/system/kombain-xray.service <<EOF
[Unit]
Description=Kombain Xray
After=network-online.target
[Service]
Environment=XRAY_LOCATION_ASSET=$KB_SHARE
ExecStart=$KB_BIN/kombain-xray run -c $KB_DIR/xray.json
Restart=always
RestartSec=3
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF
  if has_proto tuic; then
    cat > /etc/systemd/system/kombain-tuic.service <<EOF
[Unit]
Description=Kombain TUIC
After=network-online.target kombain-xray.service
[Service]
ExecStart=$KB_BIN/kombain-singbox run -c $KB_DIR/tuic.json
Restart=always
RestartSec=3
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF
  fi
  if has_proto hy2; then
    cat > /etc/systemd/system/kombain-hysteria.service <<EOF
[Unit]
Description=Kombain Hysteria2
After=network-online.target kombain-xray.service
[Service]
ExecStart=$KB_BIN/kombain-hysteria server -c $KB_DIR/hysteria.yaml
Restart=always
RestartSec=3
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF
  fi
  if has_proto sudoku; then
    cat > /etc/systemd/system/kombain-sudoku.service <<EOF
[Unit]
Description=Kombain Sudoku
After=network-online.target
[Service]
WorkingDirectory=$KB_DIR
ExecStart=$KB_BIN/kombain-sudoku -c $KB_DIR/sudoku.json
Restart=always
RestartSec=3
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF
  fi
  if has_proto tg; then
    cat > /etc/systemd/system/kombain-mtg.service <<EOF
[Unit]
Description=Kombain Telegram proxy (mtg)
After=network-online.target kombain-xray.service
[Service]
ExecStart=$KB_BIN/kombain-mtg run $KB_DIR/mtg.toml
Restart=always
RestartSec=3
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF
  fi
  if [ -n "$SUB_PORT" ]; then
    cat > /etc/systemd/system/kombain-sub.service <<EOF
[Unit]
Description=Kombain subscription (HTTPS)
After=network-online.target
[Service]
WorkingDirectory=$KB_DIR/sub
ExecStart=$(command -v openssl) s_server -quiet -accept $SUB_PORT -cert $KB_DIR/sub.crt -key $KB_DIR/sub.key -WWW
Restart=always
RestartSec=3
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
[Install]
WantedBy=multi-user.target
EOF
  fi
  systemctl daemon-reload
}

svc_list() { echo "xray"; has_proto hy2 && echo hysteria; has_proto tuic && echo tuic; has_proto sudoku && echo sudoku; has_proto tg && echo mtg; [ -n "$SUB_PORT" ] && echo sub; return 0; }

svc_title() { case $1 in xray) echo Xray ;; hysteria) echo Hysteria2 ;; tuic) echo TUIC ;; mtg) echo Telegram ;; sudoku) echo Sudoku ;; sub) echo Подписка ;; esac; }

restart_services() {
  [ "$KB_SYSTEMD" = 1 ] || return 0
  open_firewall
  step "Запускаю службы"
  apply_hop
  local s
  for s in $(svc_list); do
    systemctl enable "kombain-$s" >/dev/null 2>&1 || true
    systemctl restart "kombain-$s"
  done
  sleep 2
  for s in $(svc_list); do
    systemctl is-active --quiet "kombain-$s" || die "$(svc_title "$s") не запустился: $(journalctl -u "kombain-$s" -n 5 --no-pager | tail -3 | tr '\n' ' ')"
  done
  # services of protocols that were switched off
  for s in hysteria tuic sudoku mtg sub; do
    svc_list | grep -qx "$s" || systemctl disable --now "kombain-$s" >/dev/null 2>&1 || true
  done
  return 0
}

open_firewall() {
  [ "$KB_SYSTEMD" = 1 ] || return 0
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    step "Открываю порты в ufw"
    ufw allow "$PORT/tcp" >/dev/null
    has_proto xhttp && ufw allow "$XH_PORT/tcp" >/dev/null
    has_proto hy2 && ufw allow "$HY_PORT/udp" >/dev/null
    has_proto hy2 && [ -n "${HY_HOP:-}" ] && ufw allow "${HY_HOP/-/:}/udp" >/dev/null
    has_proto tuic && ufw allow "$TUIC_PORT/udp" >/dev/null
    has_proto tg && ufw allow "$TG_PORT/tcp" >/dev/null
    has_proto sudoku && ufw allow "$SD_PORT/tcp" >/dev/null
    [ -n "$SUB_PORT" ] && ufw allow "$SUB_PORT/tcp" >/dev/null
  elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
    step "Открываю порты в firewalld"
    firewall-cmd -q --permanent --add-port="$PORT/tcp"
    has_proto xhttp && firewall-cmd -q --permanent --add-port="$XH_PORT/tcp"
    has_proto hy2 && firewall-cmd -q --permanent --add-port="$HY_PORT/udp"
    has_proto hy2 && [ -n "${HY_HOP:-}" ] && firewall-cmd -q --permanent --add-port="$HY_HOP/udp"
    has_proto tuic && firewall-cmd -q --permanent --add-port="$TUIC_PORT/udp"
    has_proto tg && firewall-cmd -q --permanent --add-port="$TG_PORT/tcp"
    has_proto sudoku && firewall-cmd -q --permanent --add-port="$SD_PORT/tcp"
    [ -n "$SUB_PORT" ] && firewall-cmd -q --permanent --add-port="$SUB_PORT/tcp"
    firewall-cmd -q --reload
  fi
  return 0
}

enable_bbr() {
  [ "$KB_SYSTEMD" = 1 ] || return 0
  if ! sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
    step "Включаю BBR"
    printf 'net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n' > /etc/sysctl.d/99-kombain.conf
    sysctl -q --system >/dev/null 2>&1 || true
  fi
}

# ---------------------------------------------------------------------------- output

host_for_link() { [[ $HOST == *:* ]] && echo "[$HOST]" || echo "$HOST"; }

user_links() { # name uuid hypass index -> "proto link" lines
  local name=$1 uuid=$2 hypass=$3 i=$4 h label alts=""
  h=$(host_for_link)
  # kbsni: other names of the masking site (Kombain spreads connections over them; other apps ignore it)
  [ -n "${SNI_ALTS:-}" ] && alts="&kbsni=$SNI_ALTS"
  if has_proto vless; then
    label=$(urlenc "$NAME · $name · VLESS")
    echo "vless vless://$uuid@$h:$PORT?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$SNI$alts&fp=$FP&pbk=$PUB&sid=$SID&type=tcp#$label"
  fi
  if has_proto xhttp; then
    label=$(urlenc "$NAME · $name · XHTTP")
    if [ "${ANTIFREEZE:-0}" = 1 ] && [ -n "$XH_ENC" ]; then
      echo "xhttp vless://$uuid@$h:$XH_PORT?encryption=$(urlenc "$XH_ENC")&flow=xtls-rprx-vision&security=reality&sni=$SNI$alts&fp=$FP&pbk=$PUB&sid=$SID&type=xhttp&path=$(urlenc "$XH_PATH")&mode=stream-one&extra=$(urlenc '{"xmux":{"maxConnections":2,"hMaxReusableSecs":"300-600","hKeepAlivePeriod":20}}')#$label"
    else
      echo "xhttp vless://$uuid@$h:$XH_PORT?encryption=none&security=reality&sni=$SNI$alts&fp=$FP&pbk=$PUB&sid=$SID&type=xhttp&path=$(urlenc "$XH_PATH")&mode=auto#$label"
    fi
  fi
  if has_proto tuic; then
    label=$(urlenc "$NAME · $name · TUIC")
    echo "tuic tuic://$uuid:$hypass@$h:$TUIC_PORT?sni=$SNI&alpn=h3&congestion_control=bbr&udp_relay_mode=native&allow_insecure=1#$label"
  fi
  if has_proto sudoku; then
    echo "sudoku $(sd_link "$name" "$NAME · $name · Sudoku")"
  fi
  if has_proto hy2; then
    label=$(urlenc "$NAME · $name · Hysteria2")
    echo "hy2 hysteria2://u$i:$hypass@$h:$HY_PORT/?sni=$SNI&insecure=1&obfs=salamander&obfs-password=$HY_OBFS${HY_HOP:+&mport=$HY_HOP}#$label"
  fi
  return 0
}

sub_pin() { openssl x509 -in "$KB_DIR/sub.crt" -outform DER 2>/dev/null | openssl dgst -sha256 -r | cut -d' ' -f1; }

print_result() {
  local h links="" first=1 subs="" sfirst=1 pin=""
  h=$(host_for_link)
  [ -n "$SUB_PORT" ] && [ -f "$KB_DIR/sub.crt" ] && pin=$(sub_pin)
  local i=0
  while IFS='|' read -r name uuid hypass token; do
    [ -n "$uuid" ] || continue
    i=$((i + 1))  # same numbering as render_hysteria
    local proto link
    while read -r proto link; do
      [ $first = 1 ] || links+=","; first=0
      links+=$(printf '{"user":"%s","proto":"%s","link":"%s"}' "$name" "$proto" "$link")
    done < <(user_links "$name" "$uuid" "$hypass" "$i")
    if [ -n "$pin" ] && [ -n "$token" ]; then
      [ $sfirst = 1 ] || subs+=","; sfirst=0
      subs+=$(printf '{"user":"%s","url":"https://%s:%s/%s#kbpin=%s"}' "$name" "$h" "$SUB_PORT" "$token" "$pin")
    fi
  done < "$(users_file)"
  local bridge=""
  if [ -n "${BRIDGE_UUID-}" ]; then
    bridge="vless://$BRIDGE_UUID@$h:$PORT?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$SNI&fp=$FP&pbk=$PUB&sid=$SID&type=tcp#bridge"
  fi
  local tg=""
  if has_proto tg && [ -n "$TG_SECRET" ]; then tg="tg://proxy?server=$HOST&port=$TG_PORT&secret=$TG_SECRET"; fi
  local info; info=$(printf '{"name":"%s","protocols":"%s","sni":"%s","dest":"%s","port":%s,"xhPort":%s,"hyPort":%s,"tuicPort":%s,"tgPort":%s,"subPort":%s,"autoPorts":%s,"fp":"%s","antifreeze":%s,"sniRotation":%s,"sniAlts":"%s","hyHop":"%s","sdPort":%s}' \
    "$(json_str "$NAME")" "$PROTOCOLS" "$SNI" "$DEST" "$PORT" "$XH_PORT" "$HY_PORT" "$TUIC_PORT" "$TG_PORT" "${SUB_PORT:-0}" "${AUTO_PORTS:-0}" \
    "$FP" "${ANTIFREEZE:-0}" "${SNI_ROT:-0}" "${SNI_ALTS:-}" "${HY_HOP:-}" "$SD_PORT")
  local json; json=$(printf '{"role":"%s","links":[%s],"bridge":"%s","telegram":"%s","subs":[%s],"info":%s}' "$ROLE" "$links" "$bridge" "$tg" "$subs" "$info")
  echo "KB_RESULT $(printf '%s' "$json" | base64 | tr -d '\n')"
  [ "${KB_WITH_EXPORT:-0}" = 1 ] && emit_export
  return 0
}

# what a new server needs to take over: everything else is rendered from these
EXPORT_FILES="state.env users sudoku.keys sub.crt sub.key hy.crt hy.key"

emit_export() {
  local f list=""
  for f in $EXPORT_FILES; do [ -f "$KB_DIR/$f" ] && list+=" $f"; done
  echo "KB_EXPORT $(tar -C "$KB_DIR" -czf - $list | base64 | tr -d '\n')"
}

# ---------------------------------------------------------------------------- commands

# Subscription: one file per user named by its random token, served over HTTPS by `openssl s_server -WWW`
# (no extra software). The certificate is self-signed; Kombain pins its SHA-256 (#kbpin= in the link).
render_sub() {
  [ -n "$SUB_PORT" ] || return 0
  ensure_tokens
  if [ ! -f "$KB_DIR/sub.crt" ]; then
    openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -days 3650 \
      -keyout "$KB_DIR/sub.key" -out "$KB_DIR/sub.crt" -subj "/CN=$SNI" >/dev/null 2>&1
    chmod 600 "$KB_DIR/sub.key"
  fi
  local d="$KB_DIR/sub" i=0
  # keep the directory itself: it is the running server's working directory
  mkdir -p "$d"; chmod 700 "$d"; find "$d" -mindepth 1 -delete
  while IFS='|' read -r name uuid hypass token; do
    [ -n "$uuid" ] && [ -n "$token" ] || continue
    i=$((i + 1))
    user_links "$name" "$uuid" "$hypass" "$i" | cut -d' ' -f2- > "$d/$token"
  done < "$(users_file)"
}

render_all() { render_xray; render_hysteria; render_hop; render_tuic; render_sudoku; render_mtg; render_sub; write_units; }

check_ports() {
  [ "$PORT" != "$XH_PORT" ] || ! has_proto xhttp || die "порты VLESS и XHTTP должны различаться"
  [ "$HY_PORT" != "$TUIC_PORT" ] || ! has_proto tuic || ! has_proto hy2 || die "порты Hysteria2 и TUIC должны различаться"
  if has_proto tg; then
    [ "$TG_PORT" != "$PORT" ] || die "порты VLESS и Telegram должны различаться"
    [ "$TG_PORT" != "$XH_PORT" ] || ! has_proto xhttp || die "порты XHTTP и Telegram должны различаться"
  fi
  if has_proto sudoku; then
    [ "$ROLE" != entry ] || die "Sudoku работает только на одиночном сервере: в каскаде он не умеет передавать трафик выходному"
    local x
    for x in "$PORT" "$TG_PORT" "${SUB_PORT:-0}"; do
      [ "$SD_PORT" != "$x" ] || die "порт Sudoku $SD_PORT уже занят другим протоколом"
    done
    [ "$SD_PORT" != "$XH_PORT" ] || ! has_proto xhttp || die "порты XHTTP и Sudoku должны различаться"
  fi
  return 0
}

cmd_install() {
  ROLE=single; HOST=""; PROTOCOLS="vless,xhttp,hy2"; SNI="www.microsoft.com"; PORT=443; HY_PORT=443
  XH_PORT=8443; TUIC_PORT=8443; TG_PORT=9443; TG_SECRET=""; DEST=""; SUB_PORT=$((20000 + RANDOM % 40000))
  SD_PORT=8880; SD_PUB=""; SD_MPRIV=""
  NAME="Kombain"; local first_user="Телефон" bridge=0 exit_link="" hop=0
  FP=firefox; ANTIFREEZE=1; SNI_ROT=1; SNI_ALTS=""; HY_HOP=""
  while [ $# -gt 0 ]; do
    case $1 in
      --host) HOST=$2; shift 2 ;;
      --role) ROLE=$2; shift 2 ;;
      --protocols) PROTOCOLS=$2; shift 2 ;;
      --sni) SNI=$2; shift 2 ;;
      --port) PORT=$2; shift 2 ;;
      --xh-port) XH_PORT=$2; shift 2 ;;
      --hy-port) HY_PORT=$2; shift 2 ;;
      --tuic-port) TUIC_PORT=$2; shift 2 ;;
      --tg-port) TG_PORT=$2; shift 2 ;;
      --sd-port) SD_PORT=$2; shift 2 ;;
      --dest) DEST=$2; shift 2 ;;
      --sub-port) SUB_PORT=$2; shift 2 ;;
      --name) NAME=$2; shift 2 ;;
      --user) first_user=$2; shift 2 ;;
      --bridge) bridge=1; shift ;;
      --exit-link) exit_link=$2; shift 2 ;;
      --fp) FP=$2; shift 2 ;;
      --antifreeze) ANTIFREEZE=$2; shift 2 ;;
      --sni-rotation) SNI_ROT=$2; shift 2 ;;
      --hop) hop=$2; shift 2 ;;
      *) die "неизвестный параметр $1" ;;
    esac
  done
  [ -n "$HOST" ] || die "не указан --host"
  case " $FPS " in *" $FP "*) ;; *) die "неизвестный отпечаток $FP" ;; esac
  [ "$ROLE" = single ] || [ "$ROLE" = entry ] || die "роль должна быть single или entry"
  check_ports
  [ "$KB_SYSTEMD" = 1 ] && need_root
  if [ "$ROLE" = entry ]; then
    [ -n "$exit_link" ] || die "для входной ноды нужна --exit-link"
    parse_exit_link "$exit_link"
  fi
  step "Сервер: $(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-Linux}"), $(uname -m)"
  install_packages
  download_binaries
  mkdir -p "$KB_DIR"; chmod 700 "$KB_DIR"
  gen_keys
  [ $bridge = 1 ] && BRIDGE_UUID=$("$KB_BIN/kombain-xray" uuid) || BRIDGE_UUID=""
  new_user_line "$first_user" > "$(users_file)"; chmod 600 "$(users_file)"
  rm -f "$KB_DIR/sudoku.keys"
  rm -f "$KB_DIR/sub.crt" "$KB_DIR/sub.key"
  [ "$SNI_ROT" = 1 ] && find_sni_alts
  [ "$hop" = 1 ] && has_proto hy2 && HY_HOP=$(pick_hop)
  save_state
  step "Пишу конфиги"
  render_all
  open_firewall; enable_bbr
  restart_services
  step "Готово"
  print_result
}

cmd_add_user() {
  [ $# -ge 1 ] || die "укажите имя пользователя"
  case $1 in *"|"*|"") die "недопустимое имя" ;; esac
  load_state
  grep -q "^$1|" "$(users_file)" && die "пользователь «$1» уже есть"
  new_user_line "$1" >> "$(users_file)"
  render_all; restart_services
  step "Пользователь «$1» добавлен"
  print_result
}

cmd_remove_user() {
  [ $# -ge 1 ] || die "укажите имя пользователя"
  load_state
  grep -q "^$1|" "$(users_file)" || die "пользователя «$1» нет"
  [ "$(grep -c . "$(users_file)")" -gt 1 ] || die "нельзя удалить последнего пользователя"
  local tmp; tmp=$(mktemp)
  awk -F'|' -v n="$1" '$1 != n' "$(users_file)" > "$tmp" && cat "$tmp" > "$(users_file)"; rm -f "$tmp"
  render_all; restart_services
  step "Пользователь «$1» удалён"
  print_result
}

cmd_status() {
  load_state
  echo "KB_STEP Роль: $ROLE, протоколы: $PROTOCOLS, пользователей: $(grep -c . "$(users_file)")"
  if [ "$KB_SYSTEMD" = 1 ]; then
    local s
    for s in $(svc_list); do echo "KB_STEP $(svc_title "$s"): $(systemctl is-active "kombain-$s" 2>/dev/null || true)"; done
  fi
  return 0
}

cmd_stats() {
  load_state
  local up load mem_total mem_avail disk iface rx=0 tx=0 svcs="" first=1 s st
  up=$(cut -d' ' -f1 /proc/uptime | cut -d. -f1)
  load=$(cut -d' ' -f1-3 /proc/loadavg)
  mem_total=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
  mem_avail=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)
  disk=$(df -P / 2>/dev/null | awk 'NR==2 {gsub("%","",$5); print $5}')
  iface=$(awk '$2 == "00000000" {print $1; exit}' /proc/net/route 2>/dev/null)
  if [ -n "$iface" ]; then
    rx=$(awk -v i="$iface:" '$1 == i {print $2}' /proc/net/dev); tx=$(awk -v i="$iface:" '$1 == i {print $10}' /proc/net/dev)
  fi
  for s in $(svc_list); do
    if [ "$KB_SYSTEMD" = 1 ]; then st=$(systemctl is-active "kombain-$s" 2>/dev/null || true); else st=unknown; fi
    [ $first = 1 ] || svcs+=","; first=0
    svcs+=$(printf '{"name":"%s","state":"%s"}' "$(svc_title "$s")" "$st")
  done
  # per-user traffic from the Xray stats API (VLESS / XHTTP; Hysteria2 and TUIC are counted as "other")
  local raw users="" ufirst=1
  raw=$("$KB_BIN/kombain-xray" api statsquery --server="127.0.0.1:$KB_API_PORT" 2>/dev/null | tr -d ' \n' || true)
  while IFS='|' read -r name _; do
    [ -n "$name" ] || continue
    local esc u d
    esc=$(printf '%s' "$name" | sed 's/["\\]//g')
    u=$(printf '%s' "$raw" | grep -o "\"name\":\"user>>>$esc>>>traffic>>>uplink\",\"value\":\"\?[0-9]*" | grep -o '[0-9]*$' || true)
    d=$(printf '%s' "$raw" | grep -o "\"name\":\"user>>>$esc>>>traffic>>>downlink\",\"value\":\"\?[0-9]*" | grep -o '[0-9]*$' || true)
    [ $ufirst = 1 ] || users+=","; ufirst=0
    users+=$(printf '{"name":"%s","up":%s,"down":%s}' "$(json_str "$name")" "${u:-0}" "${d:-0}")
  done < "$(users_file)"
  # is the server itself choking: crashes, memory kills, the connection table, a stolen CPU
  local restarts=0 oom=0 swap_total swap_free ct=0 ct_max=0 steal=0 cpus=1 xray_rss=0 a b pid n
  if [ "$KB_SYSTEMD" = 1 ]; then
    for s in $(svc_list); do
      n=$(systemctl show "kombain-$s" -p NRestarts --value 2>/dev/null || true)
      [[ $n =~ ^[0-9]+$ ]] && restarts=$((restarts + n))
    done
    pid=$(systemctl show kombain-xray -p MainPID --value 2>/dev/null || true)
    [[ $pid =~ ^[1-9][0-9]*$ ]] && xray_rss=$(awk '/^VmRSS:/ {print $2}' "/proc/$pid/status" 2>/dev/null || true)
  fi
  oom=$({ journalctl -k -b --no-pager 2>/dev/null || dmesg 2>/dev/null; } | grep -ciE 'out of memory|oom-kill|killed process' || true)
  swap_total=$(awk '/^SwapTotal:/ {print $2}' /proc/meminfo); swap_free=$(awk '/^SwapFree:/ {print $2}' /proc/meminfo)
  [ -r /proc/sys/net/netfilter/nf_conntrack_count ] && ct=$(cat /proc/sys/net/netfilter/nf_conntrack_count) && ct_max=$(cat /proc/sys/net/netfilter/nf_conntrack_max)
  cpus=$(grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo 1)
  # CPU time the host takes away from this VPS ("steal"), over one second
  a=$(awk '/^cpu / {t=0; for (i=2;i<=NF;i++) t+=$i; print t, $9}' /proc/stat); sleep 1
  b=$(awk '/^cpu / {t=0; for (i=2;i<=NF;i++) t+=$i; print t, $9}' /proc/stat)
  steal=$(awk -v a="$a" -v b="$b" 'BEGIN {split(a,x," "); split(b,y," "); d=y[1]-x[1]; if (d > 0) printf "%d", (y[2]-x[2])*100/d; else print 0}')
  local json
  json=$(printf '{"uptime":%s,"load":"%s","memTotalKb":%s,"memAvailKb":%s,"diskPct":%s,"rx":%s,"tx":%s,"role":"%s","protocols":"%s","services":[%s],"users":[%s],"restarts":%s,"oom":%s,"swapUsedKb":%s,"conntrack":%s,"conntrackMax":%s,"steal":%s,"cpus":%s,"xrayRssKb":%s}' \
    "${up:-0}" "$load" "${mem_total:-0}" "${mem_avail:-0}" "${disk:-0}" "${rx:-0}" "${tx:-0}" "$ROLE" "$PROTOCOLS" "$svcs" "$users" \
    "${restarts:-0}" "${oom:-0}" "$(( ${swap_total:-0} - ${swap_free:-0} ))" "${ct:-0}" "${ct_max:-0}" "${steal:-0}" "${cpus:-1}" "${xray_rss:-0}")
  echo "KB_STATS $(printf '%s' "$json" | base64 | tr -d '\n')"
}

cmd_rotate() {
  load_state
  [ "$KB_SYSTEMD" = 1 ] && need_root
  while [ $# -gt 0 ]; do
    case $1 in
      --port) PORT=$2; shift 2 ;;
      --xh-port) XH_PORT=$2; shift 2 ;;
      --hy-port) HY_PORT=$2; shift 2 ;;
      --tuic-port) TUIC_PORT=$2; shift 2 ;;
      --tg-port) TG_PORT=$2; shift 2 ;;
      --sd-port) SD_PORT=$2; shift 2 ;;
      --sni) SNI=$2; DEST=""; shift 2 ;;
      --dest) DEST=$2; shift 2 ;;
      *) die "неизвестный параметр $1" ;;
    esac
  done
  check_ports
  gen_keys
  [ "$SNI_ROT" = 1 ] && find_sni_alts
  in_hop "$HY_PORT" 2>/dev/null && HY_HOP=$(pick_hop)
  [ -n "${BRIDGE_UUID-}" ] && BRIDGE_UUID=$("$KB_BIN/kombain-xray" uuid)
  step "Выдаю пользователям новые ключи"
  local tmp; tmp=$(mktemp)
  while IFS='|' read -r name _ _ token; do
    [ -n "$name" ] && new_user_line "$name" "$token"
  done < "$(users_file)" > "$tmp"
  cat "$tmp" > "$(users_file)"; rm -f "$tmp"
  rm -f "$KB_DIR/hy.crt" "$KB_DIR/hy.key"
  SD_PUB=""; SD_MPRIV=""   # render_sudoku makes new ones
  render_sudoku
  save_state
  render_all; open_firewall; restart_services
  step "Ключи заменены — старые ссылки больше не работают"
  print_result
}

cmd_set_exit() {
  load_state
  [ "$ROLE" = entry ] || die "это не входная нода каскада"
  [ "${1-}" = "--exit-link" ] && [ -n "${2-}" ] || die "укажите --exit-link"
  parse_exit_link "$2"
  save_state
  render_xray; restart_services
  step "Входная нода переключена на новый выход"
  print_result
}

cmd_enable_telegram() {
  load_state
  [ "$KB_SYSTEMD" = 1 ] && need_root
  while [ $# -gt 0 ]; do
    case $1 in
      --tg-port) TG_PORT=$2; shift 2 ;;
      *) die "неизвестный параметр $1" ;;
    esac
  done
  has_proto tg || PROTOCOLS="$PROTOCOLS,tg"
  check_ports
  download_mtg
  [ -n "$TG_SECRET" ] || new_tg_secret
  save_state
  step "Настраиваю прокси для Telegram"
  render_all; open_firewall; restart_services
  step "Прокси для Telegram включён"
  print_result
}

cmd_enable_sudoku() {
  load_state
  [ "$KB_SYSTEMD" = 1 ] && need_root
  while [ $# -gt 0 ]; do
    case $1 in
      --sd-port) SD_PORT=$2; shift 2 ;;
      *) die "неизвестный параметр $1" ;;
    esac
  done
  has_proto sudoku || PROTOCOLS="$PROTOCOLS,sudoku"
  check_ports
  download_sudoku
  step "Настраиваю Sudoku"
  render_sudoku
  save_state
  render_all; open_firewall; restart_services
  step "Sudoku включён — у каждого пользователя появилась ссылка sudoku://"
  print_result
}

cmd_disable_sudoku() {
  load_state
  [ "$KB_SYSTEMD" = 1 ] && need_root
  PROTOCOLS=$(echo ",$PROTOCOLS," | sed 's/,sudoku,/,/g; s/^,//; s/,$//')
  save_state
  render_all; restart_services
  close_ports "$SD_PORT/tcp"
  step "Sudoku выключен"
  print_result
}

cmd_disable_telegram() {
  load_state
  [ "$KB_SYSTEMD" = 1 ] && need_root
  PROTOCOLS=$(echo ",$PROTOCOLS," | sed 's/,tg,/,/g; s/^,//; s/,$//')
  save_state
  render_all; restart_services
  step "Прокси для Telegram выключен"
  print_result
}

# One TLS probe: prints "ip domain ms" when the address serves TLS 1.3 + h2 with a valid
# certificate for a real domain — what Reality needs from its masking site.
probe_site() {
  local ip=$1 out cn domain t0 t1
  out=$(timeout 4 openssl s_client -connect "$ip:443" -noservername -tls1_3 -alpn h2 </dev/null 2>/dev/null) || return 0
  echo "$out" | grep -q "ALPN protocol: h2" || return 0
  cn=$(echo "$out" | openssl x509 -noout -subject -nameopt RFC2253 2>/dev/null | sed -n 's/.*CN=\([^,]*\).*/\1/p')
  domain=${cn#\*.}
  case $domain in ""|*" "*|localhost|*.local|*.lan|*.internal|*[!a-zA-Z0-9.-]*) return 0 ;; esac
  [[ $domain == *.* ]] || return 0
  # the same address must present a trusted certificate for that name
  t0=$(date +%s%N)
  out=$(timeout 4 openssl s_client -connect "$ip:443" -servername "$domain" -tls1_3 -alpn h2 -verify_return_error </dev/null 2>/dev/null) || return 0
  t1=$(date +%s%N)
  echo "$out" | grep -q "Verify return code: 0" || return 0
  echo "$ip $domain $(( (t1 - t0) / 1000000 ))"
}

# a masking site must speak TLS 1.3 with HTTP/2 and show a valid certificate for its name
check_site() { # name host:port
  local target=${KB_REALITY_TARGET:-$2} out verify=-verify_return_error
  [ "$KB_TEST" = 1 ] && verify=""  # the test site has a self-signed certificate
  step "Проверяю сайт $1"
  out=$(timeout 8 openssl s_client -connect "$target" -servername "$1" -tls1_3 -alpn h2 $verify </dev/null 2>/dev/null) \
    || die "сайт $1 не отвечает по TLS 1.3 с сервера или у него неверный сертификат — выберите другой"
  echo "$out" | grep -q "ALPN protocol: h2" || die "сайт $1 не поддерживает HTTP/2 — для маскировки он не годится, выберите другой"
}

cmd_find_sni() {
  local ip="" net
  while [ $# -gt 0 ]; do
    case $1 in
      --host) ip=$2; shift 2 ;;
      *) die "неизвестный параметр $1" ;;
    esac
  done
  [ -n "$ip" ] && ! [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && ip=$(getent ahostsv4 "$ip" 2>/dev/null | awk 'NR==1 {print $1}')
  [ -n "$ip" ] || ip=$(curl -4 -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)
  [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "не удалось узнать IPv4-адрес сервера"
  net=${ip%.*}
  [ "$KB_TEST" = 1 ] && [ -n "${KB_SCAN_NET:-}" ] && net=$KB_SCAN_NET
  step "Проверяю соседние адреса $net.1–254 (до минуты)"
  local tmp; tmp=$(mktemp)
  export -f probe_site
  seq 1 254 | grep -vx "${ip##*.}" | xargs -P 48 -I{} bash -c 'probe_site "$1"' _ "$net.{}" > "$tmp" 2>/dev/null || true
  local json="" first=1 n=0 a d ms
  while read -r a d ms; do
    [ -n "$d" ] || continue
    [ $first = 1 ] || json+=","; first=0
    json+=$(printf '{"domain":"%s","dest":"%s:443","ms":%s}' "$d" "$a" "$ms")
    n=$((n + 1)); [ $n -ge 10 ] && break
  done < <(sort -k2,2 -u "$tmp" | sort -k3,3n)
  rm -f "$tmp"
  if [ $n = 0 ]; then step "Рядом подходящих сайтов не нашлось"; else step "Подходящих сайтов: $n"; fi
  echo "KB_SNI $(printf '[%s]' "$json" | base64 | tr -d '\n')"
}

cmd_set_sni() {
  load_state
  [ "$KB_SYSTEMD" = 1 ] && need_root
  local sni="" dest=""
  while [ $# -gt 0 ]; do
    case $1 in
      --sni) sni=$2; shift 2 ;;
      --dest) dest=$2; shift 2 ;;
      *) die "неизвестный параметр $1" ;;
    esac
  done
  [ -n "$sni" ] || die "укажите --sni"
  check_site "$sni" "${dest:-$sni:443}"
  SNI=$sni; DEST=$dest
  if [ "$SNI_ROT" = 1 ]; then find_sni_alts; else SNI_ALTS=""; fi
  # the Telegram secret and the self-signed certificates carry the site name
  has_proto tg && new_tg_secret
  rm -f "$KB_DIR/hy.crt" "$KB_DIR/hy.key"
  save_state
  step "Маскировка: $SNI${DEST:+ ($DEST)}"
  render_all; restart_services
  step "Сайт для маскировки сменён — ключи прежние, в ссылках новый сайт"
  print_result
}

cmd_ensure_sub() {
  load_state
  if [ -z "$SUB_PORT" ]; then
    [ "$KB_SYSTEMD" = 1 ] && need_root
    SUB_PORT=$((20000 + RANDOM % 40000))
    save_state
    step "Включаю ссылки-подписки"
    render_all; restart_services
  elif [ ! -d "$KB_DIR/sub" ]; then
    render_sub
  fi
  print_result
}

# ports someone listens on right now (tcp and udp)
busy_ports() {
  if command -v ss >/dev/null; then
    ss -Htuln 2>/dev/null | awk '{n=split($5,a,":"); print a[n]}'
  else
    local h
    for h in $(awk 'NR>1 {split($2,a,":"); print a[2]}' /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6 2>/dev/null || true); do
      echo $((16#$h))
    done
  fi
}

# a random free port 20000–59999 that no other Kombain service uses
pick_port() {
  local used=" $(busy_ports | tr '\n' ' ') $TG_PORT ${SUB_PORT:-0} $KB_SOCKS_PORT $KB_API_PORT $* " p i
  for i in $(seq 1 200); do
    p=$((20000 + RANDOM % 40000))
    case $used in *" $p "*) continue ;; esac
    in_hop "$p" && continue
    echo "$p"; return 0
  done
  die "не нашёл свободный порт"
}

close_ports() { # "port/proto" ... — remove old firewall openings
  [ "$KB_SYSTEMD" = 1 ] || return 0
  local x
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    for x in "$@"; do ufw delete allow "${x/-/:}" >/dev/null 2>&1 || true; done
  elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
    for x in "$@"; do firewall-cmd -q --permanent --remove-port="$x" >/dev/null 2>&1 || true; done
    firewall-cmd -q --reload || true
  fi
  return 0
}

cmd_shuffle_ports() {
  load_state
  [ "$KB_SYSTEMD" = 1 ] && need_root
  # the exit node of a cascade is reached by its entry node: only the app can re-link them
  # the exit node of a cascade is reached by its entry node: only the app can re-link them (--relink)
  [ -n "${BRIDGE_UUID-}" ] && [ "${1-}" != "--relink" ] && die "это выходной сервер каскада — меняйте его порты из приложения"
  local old=() new_vless new_xh="" new_hy="" new_tuic=""
  old+=("$PORT/tcp")
  new_vless=$(pick_port)
  if has_proto xhttp; then old+=("$XH_PORT/tcp"); new_xh=$(pick_port "$new_vless"); fi
  if has_proto hy2; then old+=("$HY_PORT/udp"); new_hy=$(pick_port "$new_vless" "$new_xh"); fi
  if has_proto tuic; then old+=("$TUIC_PORT/udp"); new_tuic=$(pick_port "$new_vless" "$new_xh" "$new_hy"); fi
  local new_sd=""
  if has_proto sudoku; then old+=("$SD_PORT/tcp"); new_sd=$(pick_port "$new_vless" "$new_xh" "$new_hy" "$new_tuic"); fi
  PORT=$new_vless
  [ -n "$new_xh" ] && XH_PORT=$new_xh
  [ -n "$new_hy" ] && HY_PORT=$new_hy
  [ -n "$new_tuic" ] && TUIC_PORT=$new_tuic
  [ -n "$new_sd" ] && SD_PORT=$new_sd
  if [ -n "$HY_HOP" ] && has_proto hy2; then old+=("$HY_HOP/udp"); HY_HOP=""; HY_HOP=$(pick_hop); fi
  save_state
  step "Новые порты: VLESS $PORT${new_xh:+, XHTTP $XH_PORT}${new_hy:+, Hysteria2 $HY_PORT}${new_tuic:+, TUIC $TUIC_PORT}${new_sd:+, Sudoku $SD_PORT}${HY_HOP:+, прыжки $HY_HOP}"
  # Telegram proxy and the subscription server keep running untouched
  render_xray; render_hysteria; render_hop; render_tuic; render_sudoku; render_sub; write_units
  if [ "$KB_SYSTEMD" = 1 ]; then
    open_firewall
    apply_hop
    local s
    for s in xray hysteria tuic sudoku; do
      svc_list | grep -qx "$s" || continue
      systemctl restart "kombain-$s"
    done
    sleep 2
    for s in xray hysteria tuic sudoku; do
      svc_list | grep -qx "$s" || continue
      systemctl is-active --quiet "kombain-$s" || die "$(svc_title "$s") не запустился: $(journalctl -u "kombain-$s" -n 5 --no-pager | tail -3 | tr '\n' ' ')"
    done
    close_ports "${old[@]}"
  fi
  step "Порты сменены — Telegram и ключи не тронуты"
  print_result
}

cmd_auto_ports() {
  load_state
  [ "$KB_SYSTEMD" = 1 ] && need_root
  local days=0
  while [ $# -gt 0 ]; do
    case $1 in
      --every) days=$2; shift 2 ;;
      *) die "неизвестный параметр $1" ;;
    esac
  done
  [[ $days =~ ^[0-9]+$ ]] || die "--every: число дней"
  [ -n "${BRIDGE_UUID-}" ] && [ "$days" != 0 ] && die "на выходном сервере каскада автосмена портов недоступна"
  AUTO_PORTS=$days
  save_state
  ports_timer "$days"
  if [ "$days" -gt 0 ]; then step "Порты будут меняться раз в $days дн. (около 4–6 утра по времени сервера)"
  else step "Автосмена портов выключена"; fi
  print_result
}

ports_timer() { # days (0 = off)
  local days=$1
  if [ "$KB_SYSTEMD" = 1 ]; then
    systemctl disable --now kombain-ports.timer >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/kombain-ports.timer /etc/systemd/system/kombain-ports.service
    if [ "$days" -gt 0 ]; then
      # the script runs from a temporary file: keep a copy for the timer
      install -m 700 "$0" "$KB_DIR/kombain-node.sh"
      cat > /etc/systemd/system/kombain-ports.service <<EOF
[Unit]
Description=Kombain: random new VPN ports
[Service]
Type=oneshot
ExecStart=/usr/bin/env bash $KB_DIR/kombain-node.sh shuffle-ports
EOF
      cat > /etc/systemd/system/kombain-ports.timer <<EOF
[Unit]
Description=Kombain: change VPN ports every $days day(s)
[Timer]
OnCalendar=*-*-1/$days 04:00:00
RandomizedDelaySec=2h
Persistent=true
[Install]
WantedBy=timers.target
EOF
      systemctl daemon-reload
      systemctl enable --now kombain-ports.timer >/dev/null 2>&1
    else
      systemctl daemon-reload
    fi
  fi
  return 0
}

cmd_harden() {
  load_state
  [ "$KB_SYSTEMD" = 1 ] && need_root
  local af="" fp="" rot="" hop="" old_hop sni="" dest="" site_changed=0
  while [ $# -gt 0 ]; do
    case $1 in
      --sni) sni=$2; shift 2 ;;
      --dest) dest=$2; shift 2 ;;
      --antifreeze) af=$2; shift 2 ;;
      --fp) fp=$2; shift 2 ;;
      --sni-rotation) rot=$2; shift 2 ;;
      --hop) hop=$2; shift 2 ;;
      *) die "неизвестный параметр $1" ;;
    esac
  done
  onoff() { case $1 in on|1|yes) echo 1 ;; off|0|no) echo 0 ;; *) die "ожидается on или off" ;; esac; }
  old_hop=$HY_HOP
  if [ -n "$sni" ] && [ "$sni" != "$SNI" ]; then
    [[ $sni =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] || die "«$sni» не похоже на адрес сайта"
    check_site "$sni" "${dest:-$sni:443}"
    SNI=$sni; DEST=$dest; site_changed=1
    has_proto tg && new_tg_secret
    rm -f "$KB_DIR/hy.crt" "$KB_DIR/hy.key"
    step "Маскировка: $SNI"
  fi
  if [ -n "$fp" ]; then
    case " $FPS " in *" $fp "*) FP=$fp ;; *) die "неизвестный отпечаток $fp (есть: $FPS)" ;; esac
  fi
  if [ -n "$af" ]; then
    ANTIFREEZE=$(onoff "$af")
    if [ "$ANTIFREEZE" = 1 ]; then
      has_proto xhttp || step "XHTTP на этом сервере выключен — защита от заморозки включится вместе с ним"
      [ -n "$XH_DEC" ] || gen_vlessenc
    fi
  fi
  [ -n "$rot" ] && SNI_ROT=$(onoff "$rot")
  if [ -n "$rot" ] || [ $site_changed = 1 ]; then
    if [ "$SNI_ROT" = 1 ]; then find_sni_alts; else SNI_ALTS=""; fi
  fi
  if [ -n "$hop" ]; then
    if [ "$(onoff "$hop")" = 1 ]; then
      has_proto hy2 || die "прыжки портов нужны только Hysteria2, а она на сервере выключена"
      [ -n "$HY_HOP" ] || HY_HOP=$(pick_hop)
    else
      HY_HOP=""
    fi
  fi
  save_state
  yn() { [ "$1" = 1 ] && echo вкл || echo выкл; }
  step "Защита: от заморозки — $(yn "$ANTIFREEZE"), отпечаток — $FP, чередование имён — $(yn "$SNI_ROT"), прыжки портов — ${HY_HOP:-выкл}"
  if [ $site_changed = 1 ]; then
    # the site name is in every service's config (Telegram secret, certificates, Sudoku fallback)
    render_all; restart_services
    [ "$KB_SYSTEMD" = 1 ] && [ -n "$old_hop" ] && [ "$old_hop" != "$HY_HOP" ] && close_ports "$old_hop/udp"
  else
  render_xray; render_hysteria; render_hop; render_sub
  if [ "$KB_SYSTEMD" = 1 ]; then
    open_firewall
    apply_hop
    systemctl restart kombain-xray
    sleep 2
    systemctl is-active --quiet kombain-xray || die "Xray не запустился: $(journalctl -u kombain-xray -n 5 --no-pager | tail -3 | tr '\n' ' ')"
    [ -n "$old_hop" ] && [ "$old_hop" != "$HY_HOP" ] && close_ports "$old_hop/udp"
  fi
  fi
  step "Готово — устройства с подпиской получат новые настройки сами"
  print_result
}

cmd_export() {
  load_state
  emit_export
}

cmd_import() {
  local host="" data="" force=0
  while [ $# -gt 0 ]; do
    case $1 in
      --host) host=$2; shift 2 ;;
      --data) data=$2; shift 2 ;;
      --force) force=1; shift ;;
      *) die "неизвестный параметр $1" ;;
    esac
  done
  [ -n "$host" ] && [ -n "$data" ] || die "нужны --host и --data"
  [ "$KB_SYSTEMD" = 1 ] && need_root
  if [ -f "$(state_file)" ] && [ $force = 0 ]; then
    die "на этом сервере уже стоит Kombain — переезд затрёт его настройки"
  fi
  step "Сервер: $(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-Linux}"), $(uname -m)"
  install_packages
  local tmp; tmp=$(mktemp -d)
  printf '%s' "$data" | base64 -d > "$tmp/backup.tgz" 2>/dev/null || die "резервная копия повреждена"
  tar -xzf "$tmp/backup.tgz" -C "$tmp" || die "резервная копия повреждена"
  [ -f "$tmp/state.env" ] && [ -f "$tmp/users" ] || die "в резервной копии нет настроек"
  mkdir -p "$KB_DIR"; chmod 700 "$KB_DIR"
  local f
  for f in $EXPORT_FILES; do
    [ -f "$tmp/$f" ] && install -m 600 "$tmp/$f" "$KB_DIR/$f"
  done
  rm -rf "$tmp"
  load_state
  step "Переношу «$NAME»: ${PROTOCOLS//,/, }"
  HOST=$host
  # the neighbour site found next to the old server is far from this one: mask as the site itself
  DEST=""
  # ports that were fine on the old server may be taken here
  local b; b=" $(busy_ports | tr '\n' ' ') "
  case $b in *" $PORT "*) PORT=$(pick_port) ;; esac
  if has_proto xhttp; then case $b in *" $XH_PORT "*) XH_PORT=$(pick_port "$PORT") ;; esac; fi
  if has_proto sudoku; then case $b in *" $SD_PORT "*) SD_PORT=$(pick_port "$PORT" "$XH_PORT") ;; esac; fi
  check_ports
  download_binaries
  save_state
  step "Пишу конфиги"
  render_all
  open_firewall; enable_bbr
  restart_services
  ports_timer "${AUTO_PORTS:-0}"
  step "Готово — ключи и пользователи прежние, сменился только адрес"
  print_result
}

cmd_uninstall() {
  [ "$KB_SYSTEMD" = 1 ] && need_root
  [ -f "$KB_DIR/hop.sh" ] && sh "$KB_DIR/hop.sh" down >/dev/null 2>&1
  if [ "$KB_SYSTEMD" = 1 ]; then
    systemctl disable --now kombain-hop >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/kombain-hop.service
    systemctl disable --now kombain-xray kombain-hysteria kombain-tuic kombain-sudoku kombain-mtg kombain-sub kombain-ports.timer >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/kombain-sudoku.service
    rm -f /etc/systemd/system/kombain-ports.timer /etc/systemd/system/kombain-ports.service
    rm -f /etc/systemd/system/kombain-xray.service /etc/systemd/system/kombain-hysteria.service \
      /etc/systemd/system/kombain-tuic.service /etc/systemd/system/kombain-mtg.service \
      /etc/systemd/system/kombain-sub.service /etc/sysctl.d/99-kombain.conf
    systemctl daemon-reload
  fi
  rm -rf "$KB_DIR" "$KB_SHARE" "$KB_BIN/kombain-xray" "$KB_BIN/kombain-hysteria" "$KB_BIN/kombain-singbox" "$KB_BIN/kombain-mtg" "$KB_BIN/kombain-sudoku"
  step "Kombain удалён с сервера"
}

# the copy kept for the port timer follows app updates
if [ -f "$KB_DIR/kombain-node.sh" ] && [ "$(readlink -f "$0")" != "$KB_DIR/kombain-node.sh" ] && [ -w "$KB_DIR" ]; then
  install -m 700 "$0" "$KB_DIR/kombain-node.sh" 2>/dev/null || true
fi

case ${1-} in
  install) shift; cmd_install "$@" ;;
  add-user) shift; cmd_add_user "$@" ;;
  remove-user) shift; cmd_remove_user "$@" ;;
  links) load_state; print_result ;;
  status) cmd_status ;;
  stats) cmd_stats ;;
  rotate) shift; cmd_rotate "$@" ;;
  set-exit) shift; cmd_set_exit "$@" ;;
  enable-telegram) shift; cmd_enable_telegram "$@" ;;
  disable-telegram) cmd_disable_telegram ;;
  enable-sudoku) shift; cmd_enable_sudoku "$@" ;;
  disable-sudoku) cmd_disable_sudoku ;;
  find-sni) shift; cmd_find_sni "$@" ;;
  set-sni) shift; cmd_set_sni "$@" ;;
  ensure-sub) cmd_ensure_sub ;;
  shuffle-ports) shift; cmd_shuffle_ports "$@" ;;
  auto-ports) shift; cmd_auto_ports "$@" ;;
  harden) shift; cmd_harden "$@" ;;
  export) cmd_export ;;
  import) shift; cmd_import "$@" ;;
  uninstall) cmd_uninstall ;;
  *) die "команды: install | add-user NAME | remove-user NAME | links | status | stats | rotate | set-exit | enable-telegram | disable-telegram | enable-sudoku | disable-sudoku | find-sni | set-sni | ensure-sub | shuffle-ports | auto-ports | harden | export | import | uninstall" ;;
esac
