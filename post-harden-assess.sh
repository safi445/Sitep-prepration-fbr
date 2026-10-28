#!/usr/bin/env bash
# Ubuntu Post-Hardening Assessment v1.0 — read-only
set -uo pipefail
export LC_ALL=C
VERSION=1.0.0
OUTDIR="${OUTDIR:-$PWD/security-reports}"
REPORT=""
PASS=0 FAIL=0 WARN=0 SKIP=0
COLOR=1
[[ -t 1 ]] || COLOR=0
usage(){ cat <<HELP
Ubuntu Post-Hardening Assessment $VERSION
Usage: $0 [--output-dir DIR] [--no-color] [--help]
Read-only Ubuntu security baseline assessment. Run as root for full coverage.
Reports are written with restrictive permissions to the selected output directory.
HELP
}
while (($#)); do
 case "$1" in
 --output-dir) [[ $# -ge 2 ]] || { echo 'Missing output directory' >&2; exit 2; }; OUTDIR=$2; shift 2;;
 --no-color) COLOR=0; shift;;
 -h|--help) usage; exit 0;;
 *) echo "Unknown argument: $1" >&2; usage >&2; exit 2;;
 esac
done
umask 077
mkdir -p -- "$OUTDIR" || exit 1
OUTDIR=$(cd -- "$OUTDIR" && pwd -P) || exit 1
REPORT="$OUTDIR/post-hardening-$(hostname -s 2>/dev/null | tr -cd 'A-Za-z0-9_.-' | cut -c1-48)-$(date +%Y%m%d-%H%M%S)-$$.txt"
: > "$REPORT" || exit 1
log(){ printf '%s\n' "$*" | tee -a "$REPORT"; }
section(){ log ''; log "========== $* =========="; }
result(){
 local state=$1 label=$2 evidence=$3
 case "$state" in PASS) ((PASS+=1));; FAIL) ((FAIL+=1));; WARN) ((WARN+=1));; SKIP) ((SKIP+=1));; esac
 log "[$state] $label — $evidence"
}
command_exists(){ command -v "$1" >/dev/null 2>&1; }
read_setting(){ sysctl -n "$1" 2>/dev/null || :; }
check_sysctl(){
 local key=$1 expected=$2 actual
 actual=$(read_setting "$key")
 if [[ -z "$actual" ]]; then result SKIP "$key" 'setting unavailable';
 elif [[ "$actual" == "$expected" ]]; then result PASS "$key" "$actual";
 else result FAIL "$key" "actual=$actual expected=$expected"; fi
}
service_state(){ systemctl is-active "$1" 2>/dev/null || :; }
service_enabled(){ systemctl is-enabled "$1" 2>/dev/null || :; }
apt_value(){ apt-config dump 2>/dev/null | grep -E "^$1[[:space:]]" | tail -1 || :; }
log "Ubuntu Post-Hardening Security Assessment v$VERSION"
log "Generated: $(date -Is)"
log "Host: $(hostname 2>/dev/null || echo unknown)"
log "Assessment user: $(id -un) (UID $(id -u))"
log "Report: $REPORT"
if (( EUID != 0 )); then log 'NOTICE: Run with sudo for complete checks; privileged checks will be SKIP.'; fi
section 'SYSTEM DETAILS'
if [[ -r /etc/os-release ]]; then . /etc/os-release; log "OS: ${PRETTY_NAME:-unknown}"; log "OS ID: ${ID:-unknown} ${VERSION_ID:-}"; fi
log "Kernel: $(uname -r)"
log "Architecture: $(uname -m)"
log "Uptime: $(uptime -p 2>/dev/null || echo unavailable)"
log "Virtualization: $(systemd-detect-virt 2>/dev/null || echo unknown)"
log "CPU: $(awk -F: '/^model name/{sub(/^ +/,"",$2);print $2;exit}' /proc/cpuinfo)"
log "CPU threads: $(nproc 2>/dev/null || echo unknown)"
log "Memory: $(free -h 2>/dev/null | awk '/^Mem:/{print $2 " total; " $3 " used"}')"
log 'Storage (root and mounted block filesystems):'
lsblk -o NAME,TYPE,TRAN,SIZE,FSTYPE,MOUNTPOINTS 2>/dev/null | tee -a "$REPORT" || :
log 'Network interfaces (addresses may be sensitive):'
ip -br addr 2>/dev/null | tee -a "$REPORT" || :
section 'FIREWALL AND NETWORK'
if command_exists ufw; then
 ufw_out=$(ufw status verbose 2>&1 || :)
 if grep -q '^Status: active' <<<"$ufw_out"; then result PASS 'UFW firewall' 'active';
 else result FAIL 'UFW firewall' 'inactive or status unavailable'; fi
 if grep -Eq 'Default: deny \(incoming\)' <<<"$ufw_out"; then result PASS 'Default incoming policy' 'deny';
 elif grep -q '^Status: active' <<<"$ufw_out"; then result WARN 'Default incoming policy' 'not confirmed deny';
 else result SKIP 'Default incoming policy' 'firewall inactive or unavailable'; fi
else result WARN 'UFW firewall' 'not installed (another firewall may be in use)'; fi
if command_exists ss; then
 tcp_listen=$(ss -H -ltn 2>/dev/null | awk '{print $4}' | grep -Ev '^(127\.|\[::1\]:|\[::1%|\[::ffff:127\.)' || :)
 if [[ -z "$tcp_listen" ]]; then result PASS 'Non-loopback TCP listeners' 'none detected';
 else result WARN 'Non-loopback TCP listeners' "review: $(tr '\n' ' ' <<<"$tcp_listen" | cut -c1-240)"; fi
 log 'Listening TCP/UDP sockets:'
 ss -tuln 2>/dev/null | tee -a "$REPORT" || :
else result SKIP 'Listening sockets' 'ss unavailable'; fi
ssh_active=$(service_state ssh.service); ssh_socket=$(service_state ssh.socket)
if [[ "$ssh_active" == active || "$ssh_socket" == active ]]; then result WARN 'SSH exposure' 'SSH service/socket active; verify firewall and access policy';
else result PASS 'SSH exposure' 'SSH service and socket not active (SSH is not required to be disabled)'; fi
section 'KERNEL AND NETWORK HARDENING'
for entry in \
 'kernel.randomize_va_space=2' 'kernel.kptr_restrict=1' 'kernel.dmesg_restrict=1' \
 'kernel.yama.ptrace_scope=1' 'fs.protected_hardlinks=1' 'fs.protected_symlinks=1' \
 'net.ipv4.ip_forward=0' 'net.ipv4.conf.all.accept_redirects=0' \
 'net.ipv4.conf.all.send_redirects=0' 'net.ipv4.conf.default.send_redirects=0' \
 'net.ipv4.tcp_syncookies=1'; do check_sysctl "${entry%%=*}" "${entry#*=}"; done
section 'APPARMOR'
if command_exists aa-status; then
 if aa-status --enabled >/dev/null 2>&1; then
  result PASS 'AppArmor' 'enabled'
  log "$(aa-status 2>/dev/null | head -5)"
 else result FAIL 'AppArmor' 'not enabled'; fi
else
 if [[ -r /sys/module/apparmor/parameters/enabled ]] && grep -q '^Y' /sys/module/apparmor/parameters/enabled; then result PASS 'AppArmor kernel module' 'enabled (aa-status unavailable)';
 else result WARN 'AppArmor' 'not verifiable'; fi
fi
section 'AUDIT LOGGING'
if [[ $(service_state auditd.service) == active ]]; then result PASS 'auditd service' 'active'; else result FAIL 'auditd service' 'not active'; fi
if command_exists auditctl && (( EUID == 0 )); then
 audit_status=$(auditctl -s 2>/dev/null || :)
 if grep -Eq '^enabled[[:space:]]+[12]' <<<"$audit_status"; then result PASS 'Kernel audit' "$(grep '^enabled' <<<"$audit_status")";
 else result FAIL 'Kernel audit' 'not enabled or inaccessible'; fi
 lost=$(awk '$1=="lost"{print $2}' <<<"$audit_status")
 if [[ "$lost" =~ ^[0-9]+$ ]]; then
  if ((lost==0)); then result PASS 'Lost audit events' '0'; else result WARN 'Lost audit events' "$lost"; fi
 else result SKIP 'Lost audit events' 'unavailable'; fi
 rules=$(auditctl -l 2>/dev/null || :)
 if grep -Eq '/etc/(passwd|shadow|sudoers|audit)' <<<"$rules"; then result PASS 'Sensitive-file audit rules' 'at least one configured';
 else result WARN 'Sensitive-file audit rules' 'no matching rules detected'; fi
else result SKIP 'Audit kernel status and rules' 'root access or auditctl unavailable'; fi
section 'MALWARE PROTECTION'
if command_exists clamscan; then
 log "ClamAV: $(clamscan --version 2>/dev/null | head -1)"
 result PASS 'ClamAV scanner' 'installed'
else result WARN 'ClamAV scanner' 'not installed'; fi
if [[ $(service_state clamav-freshclam.service) == active ]]; then result PASS 'FreshClam updates' 'active';
else result WARN 'FreshClam updates' 'not active'; fi
if [[ $(service_enabled clamav-freshclam.service) == enabled ]]; then result PASS 'FreshClam startup' 'enabled';
else result WARN 'FreshClam startup' 'not enabled'; fi
section 'AUTOMATIC UPDATES'
if command_exists apt-config; then
 periodic=$(apt_value 'APT::Periodic::Unattended-Upgrade')
 if grep -q '"1"' <<<"$periodic"; then result PASS 'Unattended upgrades configuration' "$periodic";
 else result WARN 'Unattended upgrades configuration' 'not enabled as 1'; fi
 reboot=$(apt_value 'Unattended-Upgrade::Automatic-Reboot')
 if grep -q '"false"' <<<"$reboot"; then result PASS 'Unattended automatic reboot' 'explicitly disabled';
 elif grep -q '"true"' <<<"$reboot"; then result WARN 'Unattended automatic reboot' 'enabled';
 else result WARN 'Unattended automatic reboot' 'not explicitly set (usually defaults to false)'; fi
else result SKIP 'APT automatic update policy' 'apt-config unavailable'; fi
for unit in apt-daily.timer apt-daily-upgrade.timer; do
 if [[ $(service_enabled "$unit") == enabled ]]; then result PASS "$unit" 'enabled';
 else result WARN "$unit" 'not enabled'; fi
done
if [[ -f /run/reboot-required ]]; then result WARN 'Pending reboot' 'system requests a reboot'; else result PASS 'Pending reboot' 'none requested'; fi
section 'AUTHENTICATION AND DESKTOP'
if command_exists passwd; then
 root_line=$(passwd -S root 2>/dev/null || :)
 if [[ -z "$root_line" ]]; then result SKIP 'Root password lock' 'insufficient permission';
 elif [[ "$root_line" =~ ^root[[:space:]]+L([[:space:]]|$) ]]; then result PASS 'Root password lock' 'locked';
 else result WARN 'Root password lock' "review: $(awk '{print $1,$2}' <<<"$root_line")"; fi
fi
if command_exists gsettings; then
 desktop_user=${SUDO_USER:-$(id -un)}
 if [[ "$desktop_user" == root ]]; then result SKIP 'GNOME desktop settings' 'no unprivileged desktop user detected';
 else
  # Reading GNOME settings as root without a session bus gives misleading defaults.
  if (( EUID == 0 )); then
   result SKIP 'GNOME desktop settings' "run without sudo in $desktop_user's desktop session";
  else
   for key in automount automount-open; do
    value=$(gsettings get org.gnome.desktop.media-handling "$key" 2>/dev/null || :)
    if [[ "$value" == false ]]; then result PASS "GNOME $key" 'disabled';
    elif [[ "$value" == true ]]; then result WARN "GNOME $key" 'enabled';
    else result SKIP "GNOME $key" 'settings unavailable'; fi
   done
   lock=$(gsettings get org.gnome.desktop.screensaver lock-enabled 2>/dev/null || :)
   if [[ "$lock" == true ]]; then result PASS 'GNOME screen lock' 'enabled';
   elif [[ "$lock" == false ]]; then result FAIL 'GNOME screen lock' 'disabled';
   else result SKIP 'GNOME screen lock' 'unavailable'; fi
   idle=$(gsettings get org.gnome.desktop.session idle-delay 2>/dev/null || :)
   if [[ "$idle" =~ ^uint32[[:space:]]+([0-9]+)$ ]]; then
    secs=${BASH_REMATCH[1]}
    if ((secs>0 && secs<=600)); then result PASS 'GNOME idle timeout' "${secs}s";
    else result WARN 'GNOME idle timeout' "${secs}s (recommended 1–600s)"; fi
   else result SKIP 'GNOME idle timeout' 'unavailable'; fi
  fi
 fi
else result SKIP 'GNOME settings' 'gsettings unavailable'; fi
section 'BOOT AND STORAGE'
if [[ -d /sys/firmware/efi ]]; then result PASS 'Boot mode' 'UEFI'; else result WARN 'Boot mode' 'legacy BIOS'; fi
if command_exists mokutil; then
 sb=$(mokutil --sb-state 2>/dev/null || :)
 if grep -qi 'SecureBoot enabled' <<<"$sb"; then result PASS 'Secure Boot' 'enabled';
 elif grep -qi 'SecureBoot disabled' <<<"$sb"; then result WARN 'Secure Boot' 'disabled (accepted risk if intentional)';
 else result SKIP 'Secure Boot' "unknown: $sb"; fi
else result SKIP 'Secure Boot' 'mokutil not installed'; fi
root_src=$(findmnt -n -o SOURCE / 2>/dev/null || :)
if [[ "$root_src" == /dev/mapper/* ]]; then
 result WARN 'Root encryption' "device mapper in use ($root_src); encryption not established by this check"
else result WARN 'Root encryption' "not verified; root source=$root_src (inspect cryptsetup/lsblk)"; fi
section 'SYSTEM HEALTH'
if command_exists systemctl; then
 failed=$(systemctl --failed --no-legend --plain 2>/dev/null | sed '/^[[:space:]]*$/d' || :)
 if [[ -z "$failed" ]]; then result PASS 'Failed systemd units' 'none';
 else result WARN 'Failed systemd units' "$(printf '%s' "$failed" | head -3 | tr '\n' ' ' | cut -c1-240)"; fi
fi
section 'ASSESSMENT SUMMARY'
log "PASS: $PASS | FAIL: $FAIL | WARN: $WARN | SKIP: $SKIP"
log 'PASS = observed expected state; FAIL = observed baseline violation; WARN = review required; SKIP = not assessed.'
if ((FAIL>0)); then log 'OVERALL: BASELINE GAPS DETECTED';
elif ((WARN>0 || SKIP>0)); then log 'OVERALL: BASELINE CHECKS PASSED WITH WARNINGS / UNVERIFIED ITEMS';
else log 'OVERALL: ALL IMPLEMENTED BASELINE CHECKS PASSED'; fi
log 'Scope: custom baseline only; not a CIS certification, vulnerability scan, or penetration test.'
log "Saved report: $REPORT"
