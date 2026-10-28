#!/usr/bin/env bash
# Ubuntu Security Hardening Toolkit - interactive, conservative, reversible
set -Eeuo pipefail
IFS=$'\n\t'
VERSION='1.0.0'
STATE_DIR='/var/lib/ubuntu-hardening-toolkit'
BACKUP_DIR="$STATE_DIR/backups"
LOG_DIR='/var/log/ubuntu-hardening-toolkit'
SYSCTL_FILE='/etc/sysctl.d/90-ubuntu-hardening-toolkit.conf'
AUDIT_FILE='/etc/audit/rules.d/50-ubuntu-hardening-toolkit.rules'
APT_FILE='/etc/apt/apt.conf.d/90-ubuntu-hardening-toolkit'
CURRENT_RUN="$(date -u +%Y%m%dT%H%M%SZ)-$$"
RUN_BACKUP="$BACKUP_DIR/$CURRENT_RUN"
LOGFILE=""
DRY_RUN=0
ASSUME_YES=0

color() { if [[ -t 1 ]]; then printf '\033[%sm' "$1"; fi; }
info() { printf '[INFO] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
fail() { printf '[ERROR] %s\n' "$*" >&2; }
section() { printf '\n%s\n' "========== $* =========="; }
command_exists() { command -v "$1" >/dev/null 2>&1; }
require_ubuntu() {
  [[ -r /etc/os-release ]] || { fail 'Cannot identify operating system.'; exit 1; }
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ "${ID:-}" == ubuntu ]] || { fail 'This tool supports Ubuntu only.'; exit 1; }
}
init_logging() {
  if [[ $EUID -eq 0 && $DRY_RUN -eq 0 ]]; then
    install -d -m 0700 "$BACKUP_DIR" "$LOG_DIR"
    LOGFILE="$LOG_DIR/$CURRENT_RUN.log"
    touch "$LOGFILE"; chmod 0600 "$LOGFILE"
    exec > >(tee -a "$LOGFILE") 2>&1
  fi
}
confirm() {
  local prompt="${1:-Proceed?}"
  if (( ASSUME_YES )); then return 0; fi
  [[ -t 0 ]] || { warn "Non-interactive confirmation refused: $prompt"; return 1; }
  local reply
  read -r -p "$prompt [y/N]: " reply || return 1
  [[ "$reply" == [yY] || "$reply" == [yY][eE][sS] ]]
}
need_root() {
  if (( DRY_RUN )); then return 0; fi
  if [[ $EUID -ne 0 ]]; then fail 'Run with sudo for changes (or --dry-run to preview).'; return 1; fi
}
run() {
  printf '+ '; printf '%q ' "$@"; printf '\n'
  if (( ! DRY_RUN )); then "$@"; fi
}
backup_path() {
  local path="$1" dest="$RUN_BACKUP${path}"
  if (( DRY_RUN )); then info "Would back up $path"; return 0; fi
  install -d -m 0700 "$(dirname "$dest")"
  if [[ -e "$path" || -L "$path" ]]; then
    cp -a -- "$path" "$dest"
    printf 'EXISTS\t%s\n' "$path" >> "$RUN_BACKUP/manifest.tsv"
  else
    printf 'ABSENT\t%s\n' "$path" >> "$RUN_BACKUP/manifest.tsv"
  fi
}
write_managed() {
  local path="$1" content="$2" temp
  if (( DRY_RUN )); then info "Would write $path:"; printf '%s\n' "$content"; return; fi
  install -d -m 0700 "$RUN_BACKUP"
  backup_path "$path"
  temp="$(mktemp "$(dirname "$path")/.hardening.XXXXXX")"
  printf '%s\n' "$content" > "$temp"
  chmod 0644 "$temp"
  mv -f -- "$temp" "$path"
  info "Wrote $path (backup: $RUN_BACKUP)"
}
readval() { sysctl -n "$1" 2>/dev/null || printf 'unavailable'; }
report() {
  section 'SYSTEM AND NETWORK'
  printf 'Host: %s\n' "$(hostname)"
  printf 'OS: %s\n' "$(. /etc/os-release; echo "$PRETTY_NAME")"
  printf 'Kernel: %s\n' "$(uname -r)"
  printf 'UFW: '; if command_exists ufw; then ufw status 2>/dev/null | head -1 || true; else echo 'not installed'; fi
  printf 'SSH: ' ; if command_exists systemctl; then systemctl is-active ssh.service 2>/dev/null || true; else echo unknown; fi
  section 'KERNEL PARAMETERS'
  local k
  for k in kernel.randomize_va_space kernel.kptr_restrict kernel.dmesg_restrict kernel.yama.ptrace_scope fs.protected_hardlinks fs.protected_symlinks fs.protected_fifos fs.protected_regular net.ipv4.ip_forward net.ipv4.conf.all.accept_redirects net.ipv4.conf.default.accept_redirects net.ipv4.conf.all.send_redirects net.ipv4.conf.default.send_redirects net.ipv4.tcp_syncookies; do
    printf '%-48s %s\n' "$k" "$(readval "$k")"
  done
  section 'APPLICATION CONFINEMENT AND AUDITING'
  if command_exists aa-status; then aa-status 2>/dev/null | head -4 || true; else echo 'AppArmor utilities unavailable'; fi
  if command_exists auditctl; then auditctl -s 2>/dev/null || true; else echo 'auditctl unavailable'; fi
  section 'MALWARE AND UPDATES'
  if command_exists clamscan; then clamscan --version; else echo 'ClamAV not installed'; fi
  if command_exists systemctl; then
    printf 'FreshClam: '; systemctl is-active clamav-freshclam.service 2>/dev/null || true
    printf 'APT daily timer: '; systemctl is-enabled apt-daily.timer 2>/dev/null || true
    printf 'APT upgrade timer: '; systemctl is-enabled apt-daily-upgrade.timer 2>/dev/null || true
  fi
  if command_exists apt-config; then apt-config dump | grep -E 'Unattended-Upgrade::Automatic-Reboot|APT::Periodic::Unattended-Upgrade' || true; fi
  section 'DESKTOP'
  if command_exists gsettings && [[ -n "${DBUS_SESSION_BUS_ADDRESS:-}" ]]; then
    gsettings get org.gnome.desktop.media-handling automount || true
    gsettings get org.gnome.desktop.screensaver lock-enabled || true
  else echo 'GNOME settings must be checked in the desktop user session.'; fi
  section 'FAILED SERVICES'
  if command_exists systemctl; then systemctl --failed --no-pager || true; fi
  info 'Assessment complete. SSH and Wazuh are never changed by this toolkit.'
}
apply_sysctl() {
  section 'KERNEL AND NETWORK HARDENING'
  info 'IPv4 forwarding and redirects will be disabled; do not use on routers, VPN gateways or container hosts requiring forwarding.'
  confirm 'Apply workstation sysctl profile?' || return 0
  need_root || return 1
  local cfg
  cfg=$(cat <<'CONFIG'
# Managed by Ubuntu Security Hardening Toolkit
kernel.randomize_va_space = 2
kernel.kptr_restrict = 1
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.tcp_syncookies = 1
CONFIG
)
  write_managed "$SYSCTL_FILE" "$cfg"
  run sysctl -p "$SYSCTL_FILE"
}
apply_firewall() {
  section 'UFW FIREWALL'
  warn 'Enabling UFW can block incoming SSH, web, database, VPN or other services.'
  info 'This module NEVER changes SSH service configuration and NEVER enables UFW automatically without confirmation.'
  if ! command_exists ufw; then warn 'UFW not installed. Install it manually first if required.'; return 0; fi
  run ufw status verbose
  confirm 'Set UFW default deny incoming / allow outgoing (may affect existing rules)?' || return 0
  need_root || return 1
  run ufw default deny incoming
  run ufw default allow outgoing
  if (( DRY_RUN )); then info 'Would ask for a second confirmation before ufw enable'; return; fi
  if ufw status | grep -q '^Status: inactive'; then
    warn 'Firewall is currently inactive. Ensure all required incoming ports are allowed FIRST.'
    if confirm 'Enable UFW NOW? This may disconnect remote access.'; then run ufw --force enable; fi
  else info 'UFW already active; existing allow/deny rules were retained.'; fi
}
apply_audit() {
  section 'AUDITD AND ACCOUNT CHANGE RULES'
  info 'Adds audit watches only; no existing audit rule files are deleted.'
  confirm 'Install auditd if missing and add identity/sudo/audit rules?' || return 0
  need_root || return 1
  if ! command_exists auditctl; then
    run apt-get update
    run env DEBIAN_FRONTEND=noninteractive apt-get install -y auditd
  fi
  local cfg
  cfg=$(cat <<'CONFIG'
# Managed by Ubuntu Security Hardening Toolkit
-w /etc/passwd -p wa -k identity_changes
-w /etc/group -p wa -k identity_changes
-w /etc/shadow -p wa -k identity_changes
-w /etc/gshadow -p wa -k identity_changes
-w /etc/sudoers -p wa -k sudo_changes
-w /etc/sudoers.d -p wa -k sudo_changes
-w /etc/audit -p wa -k audit_configuration
CONFIG
)
  write_managed "$AUDIT_FILE" "$cfg"
  if command_exists augenrules; then run augenrules --load; fi
  if command_exists systemctl; then run systemctl enable --now auditd.service; fi
}
apply_clamav() {
  section 'LIGHTWEIGHT ON-DEMAND ANTIVIRUS'
  info 'Installs clamscan and FreshClam signatures, NOT the resident clamd daemon.'
  confirm 'Install/enable ClamAV and FreshClam?' || return 0
  need_root || return 1
  run apt-get update
  run env DEBIAN_FRONTEND=noninteractive apt-get install -y clamav clamav-freshclam
  if [[ -f /etc/clamav/freshclam.conf ]] && grep -Eq '^[[:space:]]*NotifyClamd[[:space:]]' /etc/clamav/freshclam.conf; then
    info 'NotifyClamd directive detected; leaving existing FreshClam configuration unchanged.'
    warn 'If no clamd is installed, FreshClam may log a harmless NotifyClamd warning.'
  fi
  if command_exists systemctl; then run systemctl enable --now clamav-freshclam.service; fi
}
apply_updates() {
  section 'AUTOMATIC SECURITY UPDATES'
  info 'Enables APT periodic security updates and explicitly disables unattended reboots.'
  info 'The distribution-provided unattended-upgrades origin allowlist is left unchanged.'
  confirm 'Configure automatic security updates?' || return 0
  need_root || return 1
  run apt-get update
  run env DEBIAN_FRONTEND=noninteractive apt-get install -y unattended-upgrades
  write_managed "$APT_FILE" $'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\nUnattended-Upgrade::Automatic-Reboot "false";'
  if command_exists systemctl; then
    run systemctl enable --now apt-daily.timer
    run systemctl enable --now apt-daily-upgrade.timer
  fi
}
apply_desktop() {
  section 'GNOME REMOVABLE MEDIA AND LOCK'
  info 'GNOME settings belong to the logged-in desktop user, not root.'
  if [[ $EUID -eq 0 ]]; then warn 'Run this module as the desktop user (without sudo).'; return 1; fi
  if ! command_exists gsettings || [[ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ]]; then warn 'GNOME desktop session not detected.'; return 1; fi
  confirm 'Disable GNOME USB automount and enable screen locking?' || return 0
  run gsettings set org.gnome.desktop.media-handling automount false
  run gsettings set org.gnome.desktop.media-handling automount-open false
  run gsettings set org.gnome.desktop.screensaver lock-enabled true
  run gsettings set org.gnome.desktop.session idle-delay 300
  run gsettings set org.gnome.desktop.screensaver lock-delay 0
}
review_services() {
  section 'SERVICES AND NETWORK PORT REVIEW (READ ONLY)'
  if command_exists systemctl; then
    systemctl --failed --no-pager || true
    systemctl list-units --type=service --state=running --no-pager || true
  fi
  if command_exists ss; then ss -tulnp || true; fi
  info 'No services are disabled automatically (including SSH, Wazuh, printing, Bluetooth or networking).'
}
review_boot() {
  section 'BOOT AND STORAGE SECURITY (READ ONLY)'
  if command_exists mokutil; then mokutil --sb-state || true; fi
  if command_exists lsblk; then lsblk -o NAME,TYPE,TRAN,FSTYPE,SIZE,MOUNTPOINTS || true; fi
  if command_exists passwd && [[ $EUID -eq 0 ]]; then passwd -S root || true; fi
  info 'Secure Boot, encryption, root password, sudo policy, and kernel versions are not modified.'
}
restore() {
  section 'RESTORE MANAGED CONFIGURATION FILES'
  need_root || return 1
  if [[ ! -d "$BACKUP_DIR" ]]; then warn 'No backup directory exists.'; return 0; fi
  local entries=() d i=1 selection manifest status path saved
  while IFS= read -r d; do entries+=("$d"); done < <(find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d -print | sort -r)
  if (( ${#entries[@]} == 0 )); then warn 'No backups found.'; return 0; fi
  for d in "${entries[@]}"; do printf '%2d) %s\n' "$i" "$(basename "$d")"; ((i+=1)); done
  read -r -p 'Select backup number (0 to cancel): ' selection
  [[ "$selection" =~ ^[0-9]+$ ]] || return 0
  (( selection >= 1 && selection <= ${#entries[@]} )) || return 0
  d="${entries[selection-1]}"; manifest="$d/manifest.tsv"
  [[ -f "$manifest" ]] || { warn 'No manifest found.'; return 1; }
  cat "$manifest"
  warn 'Restoration replaces ONLY the listed managed files. It does not revert packages, firewall policy, or GNOME settings.'
  confirm "Restore files from $(basename "$d")?" || return 0
  while IFS=$'\t' read -r status path; do
    case "$path" in "$SYSCTL_FILE"|"$AUDIT_FILE"|"$APT_FILE") ;; *) warn "Unexpected path $path skipped"; continue;; esac
    saved="$d$path"
    if [[ "$status" == EXISTS && -f "$saved" ]]; then run cp -a -- "$saved" "$path"
    elif [[ "$status" == ABSENT ]]; then run rm -f -- "$path"
    fi
  done < "$manifest"
  warn 'Review restored files and reload sysctl/audit rules manually as appropriate.'
}
full_guided() {
  section 'GUIDED HARDENING (EXCLUDES SSH AND WAZUH)'
  info 'Each step asks for confirmation. Desktop settings must be run as the desktop user.'
  apply_sysctl
  apply_firewall
  apply_audit
  apply_clamav
  apply_updates
  review_services
  review_boot
  info 'Guided run finished. Use option 1 to verify.'
}
usage() {
  cat <<'USAGE'
Usage: ./harden.sh [--dry-run] [--yes] [--audit] [--help]
  --dry-run  Preview writes/commands; no changes, no packages installed.
  --yes      Accept module confirmations (NOT recommended for firewall on remote hosts).
  --audit    Run read-only assessment and exit.
  --help     Show this help.
Run as normal user for assessment and GNOME settings; use sudo for system changes.
SSH and Wazuh are never modified.
USAGE
}
main() {
  if [[ "${1:-}" == --help || "${1:-}" == -h ]]; then usage; return; fi
  require_ubuntu
  while (($#)); do
    case "$1" in
      --dry-run) DRY_RUN=1;;
      --yes) ASSUME_YES=1;;
      --audit) report; return;;
      --help|-h) usage; return;;
      *) fail "Unknown option: $1"; usage; return 2;;
    esac
    shift
  done
  init_logging
  local choice
  while true; do
    printf '\n===== Ubuntu Hardening Toolkit v%s =====\n' "$VERSION"
    printf '%s\n' ' 1) Assess current security (read-only)' \
      ' 2) Kernel and network sysctl hardening' \
      ' 3) UFW firewall configuration (high impact)' \
      ' 4) Auditd and security event rules' \
      ' 5) ClamAV and signature updates' \
      ' 6) Automatic security updates / no auto reboot' \
      ' 7) GNOME USB automount and screen lock (desktop user)' \
      ' 8) Review services and ports (read-only)' \
      ' 9) Review boot, storage and authentication (read-only)' \
      '10) Guided hardening (confirm each step)' \
      '11) Restore managed configuration files from backup' \
      ' 0) Exit'
    if (( DRY_RUN )); then warn 'DRY RUN: no changes will be made'; fi
    read -r -p 'Choose option: ' choice || break
    case "$choice" in
      1) report;; 2) apply_sysctl;; 3) apply_firewall;; 4) apply_audit;;
      5) apply_clamav;; 6) apply_updates;; 7) apply_desktop;;
      8) review_services;; 9) review_boot;; 10) full_guided;;
      11) restore;; 0) break;; *) warn 'Invalid option';;
    esac
  done
}
main "$@"
