#!/bin/bash
# Test helper for the MAB captive portal (proj-ap#905); not for production.
#
# first time on a box:
#   curl -fsSL https://raw.githubusercontent.com/xinnige/firewalla/905-captive-portal/scripts/captive_portal_test.sh -o /tmp/cpt.sh
#   bash /tmp/cpt.sh install
#
#   captive_portal_test.sh install    # firewalla -> branch 905-captive-portal, pinned (.no_auto_upgrade), services restarted
#   captive_portal_test.sh uninstall  # back to the branch it was on, pin removed
#   captive_portal_test.sh freeradius-update  # pull and recreate the freeradius container
#   captive_portal_test.sh check
#   captive_portal_test.sh on  <ssid profile id> <portal network uuid> <internet network uuid>
#   captive_portal_test.sh off <ssid profile id> <portal network uuid>
#   captive_portal_test.sh ids        # list MAB SSID profiles and the networks the APs carry
#   captive_portal_test.sh watch [ssid]   # follow the portal: grants/kicks, RADIUS answers, rejects, new leases
#   captive_portal_test.sh prototype-off   # stop the earlier mab-portal script and remove its chains
#
# on:  points the SSID's MAB default (freeradius mab_defaults allow_default) at the portal network
#      and turns on the captivePortal policy of the portal network (sensor/CaptivePortalPlugin.js)
# off: turns both off again

set -e
FWAPC=http://localhost:8841
FIREROUTER=http://localhost:8837
FIREMAIN=http://localhost:8834
CONTAINER=freeradius_freeradius_1
BACKUP=$HOME/freeradius_server.before-portal.json
REPO=/home/pi/firewalla
FORK=https://github.com/xinnige/firewalla.git
BRANCH=905-captive-portal
ORIG=$HOME/.captive_portal_orig_branch
PIN=/home/pi/.firewalla/config/.no_auto_upgrade
COMPOSE_DIR=/home/pi/.firewalla/run/docker/freeradius
PORT=8890

die() { echo "ERROR: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }

intf_of() { # network uuid -> interface name
  curl -s $FIREROUTER/v1/config/active | jq -r --arg u "$1" \
    '.interface | to_entries[] | .value | to_entries[] | select(.value.meta.uuid == $u) | .key' | head -1
}

ids() {
  echo "MAB SSID profiles:"
  curl -s $FWAPC/v1/config/active | jq -r '.profile | to_entries[] | select(.value.radius.macAuth == true)
    | "  \(.key)  \(.value.ssid)  \(.value.encryption)\(if .value.oweTransition then " owe-transition" else "" end)"'
  echo "Networks the APs carry:"
  local carried
  carried=$(curl -s $FWAPC/v1/config/active | jq -r '[.assets_template[].wifiNetworks[]? | .intf] | unique | .[]')
  curl -s $FIREROUTER/v1/config/active | jq -r '.interface | to_entries[] | .value | to_entries[]
    | select(.value.meta.uuid) | "\(.key) \(.value.meta.uuid) \(.value.meta.name)"' | while read -r i u n; do
    grep -qx "$i" <<<"$carried" && echo "  $u  $i  $n  $(ip -4 -o addr show dev "$i" 2>/dev/null | awk '{print $4}')"
  done
}

restart_services() {
  sudo systemctl restart firemain firemon firekick fireapi
  local i
  for i in $(seq 1 60); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' "$FIREMAIN/v1/encipher/simple?command=get&item=language")" = 200 ] && return
    sleep 3
  done
  die "fireapi did not come back in 180s"
}

install() {
  cd $REPO
  [ -f "$ORIG" ] || git rev-parse --abbrev-ref HEAD > "$ORIG"
  git remote get-url xinnige >/dev/null 2>&1 || git remote add xinnige $FORK
  # boxes with slow GitHub access get the branch pushed in over ssh instead:
  #   git push pi@<box>:/home/pi/firewalla +905-captive-portal:refs/remotes/xinnige/905-captive-portal
  timeout 120 git fetch -q xinnige $BRANCH \
    || { git rev-parse -q --verify xinnige/$BRANCH >/dev/null && echo "warn: fetch failed, using the copy already on the box"; } \
    || die "cannot fetch $BRANCH from $FORK, push it in over ssh (see the comment above)"
  # local edits (e.g. a locale file updated at runtime) are kept in a stash, restored by uninstall
  git diff --quiet || git stash push -q -m captive-portal-install
  git checkout -q -B $BRANCH xinnige/$BRANCH || die "checkout failed (git status in $REPO)"
  touch $PIN
  restart_services
  ok "firewalla on $(git log --oneline -1), was $(cat "$ORIG"); auto upgrade paused ($PIN)"
}

uninstall() {
  [ -f "$ORIG" ] || die "no recorded branch ($ORIG), nothing to undo"
  cd $REPO
  git checkout -q "$(cat "$ORIG")"
  local stash
  stash=$(git stash list | grep -m1 'captive-portal-install' | cut -d: -f1)
  [ -z "$stash" ] || git stash pop -q "$stash" || echo "warn: could not restore $stash, see git stash list"
  rm -f $PIN
  restart_services
  ok "firewalla back on $(cat "$ORIG") ($(git log --oneline -1)), auto upgrade on again"
  rm -f "$ORIG"
}

freeradius_update() {
  cd $COMPOSE_DIR
  local dc="sudo docker-compose"
  command -v docker-compose >/dev/null || dc="sudo docker compose"
  $dc pull -q 2>&1 | grep -v ContainerConfig || true
  $dc up -d 2>&1 | grep -v ContainerConfig || true
  local i
  for i in $(seq 1 30); do
    sudo docker exec $CONTAINER grep -q 'reply:Tmp-String-9' /etc/freeradius/policy.d/policy_mab 2>/dev/null && break
    sleep 3
  done
  ok "freeradius $(sudo docker inspect $CONTAINER --format '{{.Config.Image}} {{index .Config.Labels "org.opencontainers.image.version"}} {{index .Config.Labels "org.opencontainers.image.revision"}}')"
}

aps() { # each AP: name, model, fwap, image (MAC auth needs fwap >= 1.19.16 and a new enough image)
  curl -s -XPOST $FWAPC/acp/runs -H 'Content-Type: application/json' -d '{"agent_name":"firewalla-ap-controller",
    "input":[{"role":"user","parts":[{"content_type":"application/json","content":"{\"action\":\"get_ap_status\",\"params\":{}}"}]}]}' \
  | python3 -c '
import json, sys
def walk(x):
    if isinstance(x, dict):
        if "imageVersion" in x:
            print("  AP %s %s fwap %s %s image %s" % (x.get("uid") or x.get("mac"), x.get("name"), x.get("version"), x.get("model"), x.get("imageVersion")))
        for v in x.values(): walk(v)
    elif isinstance(x, list):
        for v in x: walk(v)
    elif isinstance(x, str) and x[:1] in "{[":
        try: walk(json.loads(x))
        except Exception: pass
walk(json.load(sys.stdin))' | sort -u
}

check() {
  [ "$(curl -s -o /dev/null -w '%{http_code}' $FWAPC/v1/mac_auth/accepted)" = 200 ] \
    || die "fwapc has no MAB accepted list, need fwapc 0.20.23+ (firewalla/ap #900)"
  ok "fwapc $(/home/pi/.firewalla/run/assets/fwapc -V)"
  [ "$(curl -s -o /dev/null -w '%{http_code}' -XPOST $FWAPC/v1/control/block_station -H 'Content-Type: application/json' -d '{}')" != 404 ] \
    || echo "warn: fwapc has no /v1/control/block_station (firewalla/ap 905-captive-portal); OK then waits up to 31s before the kick"
  sudo docker exec $CONTAINER grep -q 'reply:Tmp-String-9' /etc/freeradius/policy.d/policy_mab \
    || die "freeradius image is older than 1.1.6 (dockers ppsk_redis_mab 1b2cd90)"
  ok "freeradius $(sudo docker inspect $CONTAINER --format '{{index .Config.Labels "org.opencontainers.image.version"}} {{index .Config.Labels "org.opencontainers.image.revision"}}')"
  grep -q CaptivePortalPlugin /home/pi/firewalla/net2/config.json \
    || die "firewalla is not on branch 905-captive-portal (no CaptivePortalPlugin in net2/config.json)"
  ok "firewalla $(git -C /home/pi/firewalla rev-parse --abbrev-ref HEAD) $(git -C /home/pi/firewalla log --oneline -1)"
  ! systemctl is-active -q mab-portal 2>/dev/null || die "the prototype mab-portal service is running, run: $0 prototype-off"
  echo "APs (MAC auth: fwap >= 1.19.16; image fwap-F 0.1.121+ or 0.3.2+, fwap-FW 0.3.1+, fwap-D 0.2.11+):"
  aps
}

ssid_of() { # profile id -> ssid name, MAB and not WPA3 PPSK
  local p
  p=$(curl -s $FWAPC/v1/config/active | jq -c --arg id "$1" '.profile[$id] // empty')
  [ -n "$p" ] || die "no SSID profile $1"
  [ "$(jq -r '.radius.macAuth // false' <<<"$p")" = true ] || die "SSID profile $1 has no MAC Address Authentication"
  jq -r .ssid <<<"$p"
}

set_default() { # ssid, portal network uuid or "" to remove
  [ -f "$BACKUP" ] || (umask 077; redis-cli hget policy:system freeradius_server > "$BACKUP")
  local cur new
  cur=$(redis-cli hget policy:system freeradius_server)
  [ -n "$cur" ] || die "no freeradius_server policy, is RADIUS set up on this box?"
  new=$(jq -c --arg s "$1" --arg n "$2" '.radius.mab_defaults = (((.radius.mab_defaults // [])
    | map(select(.ssid != $s and .ssid != ($s + "-OWE")))) + (if $n == "" then [] else
    [{ssid: $s, allow_default: true, network: $n}] end))' <<<"$cur")
  redis-cli -x hset policy:system freeradius_server <<<"$new" >/dev/null
  sudo docker exec $CONTAINER bash -c "bash /root/freeradius/freeradius.sh generate" >/dev/null
  echo "freeradius DEFAULT entries now:"
  sudo docker exec $CONTAINER sh -c "grep -A5 '^DEFAULT' /etc/freeradius/wpa3/macs | grep -E 'DEFAULT|Group-ID'" || echo "  (none)"
  echo "freeradius reloads within ~30s"
}

set_policy() { # network uuid, json
  curl -s -XPOST "$FIREMAIN/v1/encipher/simple?command=set&item=policy&target=network:$1" \
    -H 'Content-Type: application/json' -d "{\"captivePortal\": $2}" >/dev/null
}

on() {
  [ $# -eq 3 ] || die "usage: $0 on <ssid profile id> <portal network uuid> <internet network uuid>"
  local profile=$1 portal=$2 inet=$3 ssid pintf iintf carried ip intf
  check
  ssid=$(ssid_of "$profile")
  [ "$portal" != "$inet" ] || die "portal and internet networks must differ"
  pintf=$(intf_of "$portal"); iintf=$(intf_of "$inet")
  [ -n "$pintf" ] || die "no network $portal"
  [ -n "$iintf" ] || die "no network $inet"
  carried=$(curl -s $FWAPC/v1/config/active | jq -r '[.assets_template[].wifiNetworks[]? | .intf] | unique | .[]')
  grep -qx "$pintf" <<<"$carried" || die "the APs don't carry the portal network ($pintf), add it to an AP network in the app"
  grep -qx "$iintf" <<<"$carried" || die "the APs don't carry the internet network ($iintf)"
  ip=$(ip -4 -o addr show dev "$pintf" | awk '{print $4}' | cut -d/ -f1 | head -1)
  [ -n "$ip" ] || die "portal network $pintf has no IPv4 address"
  ok "SSID '$ssid', portal $pintf $ip, internet $iintf"

  set_default "$ssid" "$portal"
  set_policy "$portal" "{\"state\": true, \"profileId\": \"$profile\", \"internetNetwork\": \"$inet\", \"port\": $PORT}"
  # firemain applies iptables rules through a queue
  local i
  for i in $(seq 1 15); do
    sudo iptables -w -t nat -S FW_PREROUTING_CAPTIVE 2>/dev/null | grep -q "dport 80" && break
    sleep 2
  done
  sudo iptables -w -t nat -S FW_PREROUTING_CAPTIVE | grep -q "dport 80" || die "portal redirect rule missing, see /home/pi/logs/FireMain.log"
  sudo iptables -w -t nat -S FW_PREROUTING_CAPTIVE | grep -q "dport 53" || die "portal DNS redirect rule missing, see /home/pi/logs/FireMain.log"
  sudo iptables -w -S FW_FORWARD_CAPTIVE | grep -q DROP || die "portal isolation rules missing, see /home/pi/logs/FireMain.log"
  sudo ip6tables -w -S FW_FORWARD_CAPTIVE | grep -q DROP || die "portal IPv6 isolation rules missing, see /home/pi/logs/FireMain.log"
  sudo iptables -w -S FW_FORWARD_CAPTIVE | grep -q -- "-i $pintf" || die "portal isolation is not on $pintf, see /home/pi/logs/FireMain.log"
  [ "$(curl -s -o /dev/null -w '%{http_code}' "http://$ip:$PORT/")" = 200 ] || die "portal page not answering on $ip:$PORT"
  for intf in "$pintf" "$iintf"; do
    [ "$(cat /proc/sys/net/ipv4/conf/$intf/arp_ignore)" = 1 ] || die "arp_ignore not set on $intf, see /home/pi/logs/FireMain.log"
  done
  ok "portal on: unknown devices on '$ssid' land on $pintf and get http://$ip:$PORT/"
}

off() {
  [ $# -eq 2 ] || die "usage: $0 off <ssid profile id> <portal network uuid>"
  set_policy "$2" '{"state": false}'
  set_default "$(ssid_of "$1")" ""
  ok "portal off; the original policy is in $BACKUP"
}

prototype_off() {
  sudo systemctl stop mab-portal 2>/dev/null || true
  local intf
  for intf in $(sudo iptables -w -S FORWARD | sed -n 's/^-A FORWARD -i \(.*\) -j MAB_PORTAL_FWD$/\1/p'); do
    sudo iptables -w -t nat -D PREROUTING -i "$intf" -j MAB_PORTAL_NAT 2>/dev/null || true
    sudo iptables -w -D INPUT -i "$intf" -j MAB_PORTAL_IN 2>/dev/null || true
    sudo iptables -w -D FORWARD -i "$intf" -j MAB_PORTAL_FWD 2>/dev/null || true
    sudo iptables -w -D FORWARD -o "$intf" -j MAB_PORTAL_FWD_OUT 2>/dev/null || true
  done
  local c
  for c in MAB_PORTAL_IN MAB_PORTAL_FWD MAB_PORTAL_FWD_OUT; do
    sudo iptables -w -F $c 2>/dev/null && sudo iptables -w -X $c 2>/dev/null || true
  done
  sudo iptables -w -t nat -F MAB_PORTAL_NAT 2>/dev/null && sudo iptables -w -t nat -X MAB_PORTAL_NAT 2>/dev/null || true
  ok "prototype stopped and its chains removed"
}

watch_portal() { # ssid filter, optional
  local ssid=${1:-} F
  F=$(ls -t /home/pi/logs/FireMain*.log 2>/dev/null | head -1); [ -n "$F" ] || F=/home/pi/.forever/main.log
  echo "following the portal${ssid:+ on $ssid}, Ctrl-C to stop"
  trap 'kill 0' EXIT
  tail -n0 -F "$F" 2>/dev/null | grep --line-buffered 'Captive portal' \
    | sed -u -E 's/^[0-9-]+ ([0-9:]+) .*CaptivePortalPlugin: /\1 PORTAL /' &
  tail -n0 -F /home/pi/.forever/fwapc.log 2>/dev/null | grep --line-buffered '"auth_method":"mab"' | grep --line-buffered -F "$ssid" \
    | sed -u -E 's/.*\[[0-9-]+ ([0-9:]+).*"src":"([a-z]*)".*"result":"([A-Za-z-]+)".*"mac":"([0-9A-Fa-f:-]+)".*"nas_ip":"([0-9.]+)".*"ssid":"([^"]*)","vlan":"([0-9]*)".*/\1 RADIUS \3 \4 ssid=\6 src=\2 vlan=\7 ap=\5/' &
  sudo docker exec $CONTAINER sh -c 'tail -n0 -F /var/log/freeradius/radius.log' 2>/dev/null \
    | grep --line-buffered -E 'FW-Root-Reject-Reason :?= mab' | grep --line-buffered -F "$ssid" | sed -u -E 's/.*(mab: .*)/REJECT \1/' &
  local L=/home/pi/.router/run/dhcp/dnsmasq.leases prev cur
  prev=$(cat $L)
  while true; do
    sleep 2
    cur=$(cat $L 2>/dev/null)
    diff <(echo "$prev") <(echo "$cur") | grep '^>' | awk '{print strftime("%H:%M:%S"), "LEASE", $3, $4, $5}'
    prev=$cur
  done
}

cmd=$1; shift || true
case "$cmd" in
  check) check ;;
  ids) ids ;;
  on) on "$@" ;;
  off) off "$@" ;;
  install) install ;;
  uninstall) uninstall ;;
  freeradius-update) freeradius_update ;;
  prototype-off) prototype_off ;;
  watch) watch_portal "$@" ;;
  *) die "usage: $0 install | uninstall | freeradius-update | check | ids | on <profile> <portal net> <internet net> | off <profile> <portal net> | prototype-off" ;;
esac
