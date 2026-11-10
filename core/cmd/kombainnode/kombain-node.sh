#!/usr/bin/env bash
# Kombain node installer — VLESS+Reality, VLESS+XHTTP+Reality (Xray), Hysteria2, TUIC v5
# and a Telegram MTProto proxy (mtg, FakeTLS) on Debian/Ubuntu. No domain needed.
#
#   kombain-node.sh install  --host IP [--role single|entry] [--protocols vless,xhttp,hy2,tuic]
#                            [--sni www.microsoft.com] [--port 443] [--xh-port 8443] [--hy-port 443]
#                            [--tuic-port 8443] [--tg-port 9443] [--name "Мой сервер"] [--user "Телефон"]
#                            [--bridge] [--exit-link vless://...]
#   kombain-node.sh add-user NAME | remove-user NAME
#   kombain-node.sh links
#   kombain-node.sh status            (human readable)
#   kombain-node.sh stats             (KB_STATS <base64 JSON> for the app)
#   kombain-node.sh rotate [--port N] [--xh-port N] [--hy-port N] [--tuic-port N] [--tg-port N] [--sni HOST]
#                          new Reality keys, paths, passwords and user ids (old links stop working)
#   kombain-node.sh set-exit --exit-link vless://...   (entry node: point to a new exit)
#   kombain-node.sh enable-telegram [--tg-port N] | disable-telegram
#   kombain-node.sh uninstall
#
# Protocols: vless, xhttp, hy2, tuic, tg (Telegram proxy: one tg:// link for everybody).
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
#                             "telegram": "tg://proxy?...", "info": {name, protocols, sni, ports}}
#   KB_STATS  <base64 JSON>  see cmd_stats
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
  TG_PORT=${TG_PORT:-9443}; TG_SECRET=${TG_SECRET:-}
}

save_state() {
  mkdir -p "$KB_DIR"; chmod 700 "$KB_DIR"
  {
    for v in ROLE HOST PROTOCOLS SNI PORT XH_PORT XH_PATH HY_PORT TUIC_PORT TG_PORT TG_SECRET NAME PRIV PUB SID HY_OBFS BRIDGE_UUID \
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
  return 0
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
}

# FakeTLS secret: "ee" + 16 random bytes + the masking domain (Telegram sends it as SNI)
new_tg_secret() { TG_SECRET=ee$(rand_hex 16)$(hex_str "$SNI"); }

new_user_line() { # name -> "name|uuid|hypass"
  printf '%s|%s|%s\n' "$1" "$("$KB_BIN/kombain-xray" uuid)" "$(rand_hex 16)"
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
  local reality; reality=$(printf '"security":"reality","realitySettings":{"target":"%s","serverNames":["%s"],"privateKey":"%s","shortIds":["%s"]}' \
    "${KB_REALITY_TARGET:-$SNI:443}" "$SNI" "$PRIV" "$SID")
  local sniff='"sniffing":{"enabled":true,"destOverride":["http","tls","quic"],"routeOnly":true}'
  # the main VLESS inbound always exists: entry nodes and the bridge use it
  vless_in=$(printf '{"tag":"vless-in","listen":"0.0.0.0","port":%s,"protocol":"vless","settings":{"clients":[%s],"decryption":"none"},"streamSettings":{"network":"raw",%s},%s}' \
    "$PORT" "$(json_clients xtls-rprx-vision)" "$reality" "$sniff")
  if has_proto xhttp; then
    xh_in=$(printf ',{"tag":"xhttp-in","listen":"0.0.0.0","port":%s,"protocol":"vless","settings":{"clients":[%s],"decryption":"none"},"streamSettings":{"network":"xhttp","xhttpSettings":{"path":"%s","mode":"auto"},%s},%s}' \
      "$XH_PORT" "$(json_clients "")" "$XH_PATH" "$reality" "$sniff")
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
  while IFS='|' read -r _ uuid hypass; do
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
    while IFS='|' read -r _ _ hypass; do
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
  systemctl daemon-reload
}

svc_list() { echo "xray"; has_proto hy2 && echo hysteria; has_proto tuic && echo tuic; has_proto tg && echo mtg; return 0; }

svc_title() { case $1 in xray) echo Xray ;; hysteria) echo Hysteria2 ;; tuic) echo TUIC ;; mtg) echo Telegram ;; esac; }

restart_services() {
  [ "$KB_SYSTEMD" = 1 ] || return 0
  step "Запускаю службы"
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
  for s in hysteria tuic mtg; do
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
    has_proto tuic && ufw allow "$TUIC_PORT/udp" >/dev/null
    has_proto tg && ufw allow "$TG_PORT/tcp" >/dev/null
  elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
    step "Открываю порты в firewalld"
    firewall-cmd -q --permanent --add-port="$PORT/tcp"
    has_proto xhttp && firewall-cmd -q --permanent --add-port="$XH_PORT/tcp"
    has_proto hy2 && firewall-cmd -q --permanent --add-port="$HY_PORT/udp"
    has_proto tuic && firewall-cmd -q --permanent --add-port="$TUIC_PORT/udp"
    has_proto tg && firewall-cmd -q --permanent --add-port="$TG_PORT/tcp"
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

print_result() {
  local h links="" first=1 label
  h=$(host_for_link)
  local i=0
  while IFS='|' read -r name uuid hypass; do
    [ -n "$uuid" ] || continue
    i=$((i + 1))  # same numbering as render_hysteria
    if has_proto vless; then
      label=$(urlenc "$NAME · $name · VLESS")
      local l="vless://$uuid@$h:$PORT?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$SNI&fp=chrome&pbk=$PUB&sid=$SID&type=tcp#$label"
      [ $first = 1 ] || links+=","; first=0
      links+=$(printf '{"user":"%s","proto":"vless","link":"%s"}' "$name" "$l")
    fi
    if has_proto xhttp; then
      label=$(urlenc "$NAME · $name · XHTTP")
      local l="vless://$uuid@$h:$XH_PORT?encryption=none&security=reality&sni=$SNI&fp=chrome&pbk=$PUB&sid=$SID&type=xhttp&path=$(urlenc "$XH_PATH")&mode=auto#$label"
      [ $first = 1 ] || links+=","; first=0
      links+=$(printf '{"user":"%s","proto":"xhttp","link":"%s"}' "$name" "$l")
    fi
    if has_proto tuic; then
      label=$(urlenc "$NAME · $name · TUIC")
      local l="tuic://$uuid:$hypass@$h:$TUIC_PORT?sni=$SNI&alpn=h3&congestion_control=bbr&udp_relay_mode=native&allow_insecure=1#$label"
      [ $first = 1 ] || links+=","; first=0
      links+=$(printf '{"user":"%s","proto":"tuic","link":"%s"}' "$name" "$l")
    fi
    if has_proto hy2; then
      label=$(urlenc "$NAME · $name · Hysteria2")
      local l="hysteria2://u$i:$hypass@$h:$HY_PORT/?sni=$SNI&insecure=1&obfs=salamander&obfs-password=$HY_OBFS#$label"
      [ $first = 1 ] || links+=","; first=0
      links+=$(printf '{"user":"%s","proto":"hy2","link":"%s"}' "$name" "$l")
    fi
  done < "$(users_file)"
  local bridge=""
  if [ -n "${BRIDGE_UUID-}" ]; then
    bridge="vless://$BRIDGE_UUID@$h:$PORT?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$SNI&fp=chrome&pbk=$PUB&sid=$SID&type=tcp#bridge"
  fi
  local tg=""
  if has_proto tg && [ -n "$TG_SECRET" ]; then tg="tg://proxy?server=$HOST&port=$TG_PORT&secret=$TG_SECRET"; fi
  local info; info=$(printf '{"name":"%s","protocols":"%s","sni":"%s","port":%s,"xhPort":%s,"hyPort":%s,"tuicPort":%s,"tgPort":%s}' \
    "$(json_str "$NAME")" "$PROTOCOLS" "$SNI" "$PORT" "$XH_PORT" "$HY_PORT" "$TUIC_PORT" "$TG_PORT")
  local json; json=$(printf '{"role":"%s","links":[%s],"bridge":"%s","telegram":"%s","info":%s}' "$ROLE" "$links" "$bridge" "$tg" "$info")
  echo "KB_RESULT $(printf '%s' "$json" | base64 | tr -d '\n')"
}

# ---------------------------------------------------------------------------- commands

render_all() { render_xray; render_hysteria; render_tuic; render_mtg; write_units; }

check_ports() {
  [ "$PORT" != "$XH_PORT" ] || ! has_proto xhttp || die "порты VLESS и XHTTP должны различаться"
  [ "$HY_PORT" != "$TUIC_PORT" ] || ! has_proto tuic || ! has_proto hy2 || die "порты Hysteria2 и TUIC должны различаться"
  if has_proto tg; then
    [ "$TG_PORT" != "$PORT" ] || die "порты VLESS и Telegram должны различаться"
    [ "$TG_PORT" != "$XH_PORT" ] || ! has_proto xhttp || die "порты XHTTP и Telegram должны различаться"
  fi
  return 0
}

cmd_install() {
  ROLE=single; HOST=""; PROTOCOLS="vless,xhttp,hy2"; SNI="www.microsoft.com"; PORT=443; HY_PORT=443
  XH_PORT=8443; TUIC_PORT=8443; TG_PORT=9443; TG_SECRET=""
  NAME="Kombain"; local first_user="Телефон" bridge=0 exit_link=""
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
      --name) NAME=$2; shift 2 ;;
      --user) first_user=$2; shift 2 ;;
      --bridge) bridge=1; shift ;;
      --exit-link) exit_link=$2; shift 2 ;;
      *) die "неизвестный параметр $1" ;;
    esac
  done
  [ -n "$HOST" ] || die "не указан --host"
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
  local json
  json=$(printf '{"uptime":%s,"load":"%s","memTotalKb":%s,"memAvailKb":%s,"diskPct":%s,"rx":%s,"tx":%s,"role":"%s","protocols":"%s","services":[%s],"users":[%s]}' \
    "${up:-0}" "$load" "${mem_total:-0}" "${mem_avail:-0}" "${disk:-0}" "${rx:-0}" "${tx:-0}" "$ROLE" "$PROTOCOLS" "$svcs" "$users")
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
      --sni) SNI=$2; shift 2 ;;
      *) die "неизвестный параметр $1" ;;
    esac
  done
  check_ports
  gen_keys
  [ -n "${BRIDGE_UUID-}" ] && BRIDGE_UUID=$("$KB_BIN/kombain-xray" uuid)
  step "Выдаю пользователям новые ключи"
  local tmp; tmp=$(mktemp)
  while IFS='|' read -r name _; do
    [ -n "$name" ] && new_user_line "$name"
  done < "$(users_file)" > "$tmp"
  cat "$tmp" > "$(users_file)"; rm -f "$tmp"
  rm -f "$KB_DIR/hy.crt" "$KB_DIR/hy.key"
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

cmd_disable_telegram() {
  load_state
  [ "$KB_SYSTEMD" = 1 ] && need_root
  PROTOCOLS=$(echo ",$PROTOCOLS," | sed 's/,tg,/,/g; s/^,//; s/,$//')
  save_state
  render_all; restart_services
  step "Прокси для Telegram выключен"
  print_result
}

cmd_uninstall() {
  [ "$KB_SYSTEMD" = 1 ] && need_root
  if [ "$KB_SYSTEMD" = 1 ]; then
    systemctl disable --now kombain-xray kombain-hysteria kombain-tuic kombain-mtg >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/kombain-xray.service /etc/systemd/system/kombain-hysteria.service \
      /etc/systemd/system/kombain-tuic.service /etc/systemd/system/kombain-mtg.service /etc/sysctl.d/99-kombain.conf
    systemctl daemon-reload
  fi
  rm -rf "$KB_DIR" "$KB_SHARE" "$KB_BIN/kombain-xray" "$KB_BIN/kombain-hysteria" "$KB_BIN/kombain-singbox" "$KB_BIN/kombain-mtg"
  step "Kombain удалён с сервера"
}

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
  uninstall) cmd_uninstall ;;
  *) die "команды: install | add-user NAME | remove-user NAME | links | status | stats | rotate | set-exit | enable-telegram | disable-telegram | uninstall" ;;
esac
