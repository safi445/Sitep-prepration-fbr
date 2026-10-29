#!/usr/bin/env bash
# Ubuntu Security Hardening Toolkit v2.0
# Hardware-independent; no firewall, SSH, PAM, sudoers, Wazuh, driver or kernel changes.
set -Eeuo pipefail
umask 077
export LC_ALL=C

[[ ${EUID} -eq 0 ]] || { echo 'ERROR: Run with sudo.' >&2; exit 1; }
[[ -r /etc/os-release ]] || { echo 'ERROR: /etc/os-release missing.' >&2; exit 1; }
# shellcheck disable=SC1091
. /etc/os-release
[[ ${ID:-} == ubuntu ]] || { echo 'ERROR: This toolkit supports Ubuntu only.' >&2; exit 1; }

BASE=/var/lib/ubuntu-security-hardening
SYSCTL_FILE=/etc/sysctl.d/90-ubuntu-security-hardening.conf
AUDIT_FILE=/etc/audit/rules.d/50-ubuntu-security-hardening.rules
REBOOT_FILE=/etc/apt/apt.conf.d/99-ubuntu-security-hardening-no-reboot
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
RUN="$BASE/runs/$RUN_ID"
mkdir -p "$RUN/backups" "$BASE/runs"
chmod 700 "$BASE" "$BASE/runs" "$RUN" "$RUN/backups"
LOG="$RUN/session.log"
exec > >(tee -a "$LOG") 2>&1
trap 'printf "\nERROR: command failed near line %s; see %s\n" "$LINENO" "$LOG" >&2' ERR

section(){ printf '\n========== %s ==========\n' "$*"; }
info(){ printf '[INFO] %s\n' "$*"; }
warn(){ printf '[WARN] %s\n' "$*"; }
pass(){ printf '[PASS] %s\n' "$*"; }
fail(){ printf '[FAIL] %s\n' "$*"; }
confirm(){ local ans; read -r -p "$1 [type YES]: " ans || return 1; [[ $ans == YES ]]; }
need(){ command -v "$1" >/dev/null 2>&1 || { warn "Missing command: $1"; return 1; }; }

# Back up only once per file per session, preserving metadata and original absence.
backup_file(){
 local file=$1 rel=${1#/} dst="$RUN/backups/${1#/}"
 if [[ -e "$RUN/backups/$rel" || -e "$RUN/backups/$rel.ABSENT" ]]; then return 0; fi
 mkdir -p "$(dirname "$dst")"
 if [[ -e "$file" || -L "$file" ]]; then
   [[ -f "$file" && ! -L "$file" ]] || { warn "Refusing non-regular or symlink target: $file"; return 1; }
   cp -a -- "$file" "$dst"
 else
   : > "$dst.ABSENT"
 fi
 printf '%s\n' "$file" >> "$RUN/changed-files.txt"
}

# Accept content via stdin. Existing identical files are not rewritten.
write_config(){
 local file=$1 mode=$2 tmp
 tmp=$(mktemp "$RUN/config.XXXXXX")
 cat > "$tmp"
 if [[ -e "$file" || -L "$file" ]]; then
   [[ -f "$file" && ! -L "$file" ]] || { rm -f "$tmp"; warn "Unsafe target: $file"; return 1; }
   if cmp -s "$tmp" "$file" && [[ $(stat -c %a "$file") == "$mode" ]] && [[ $(stat -c %u:%g "$file") == 0:0 ]]; then
     rm -f "$tmp"; pass "Already configured: $file"; return 0
   fi
 fi
 backup_file "$file" || { rm -f "$tmp"; return 1; }
 mkdir -p "$(dirname "$file")"
 install -o root -g root -m "$mode" -- "$tmp" "$file"
 rm -f "$tmp"
 pass "Updated: $file"
}

inventory(){
 section 'SYSTEM INVENTORY — READ ONLY'
 printf 'OS: %s\nHost: %s\nKernel: %s\nUptime: %s\n' "${PRETTY_NAME:-Ubuntu}" "$(hostname)" "$(uname -r)" "$(uptime -p)"
 section 'IMPORTANT SERVICES'
 for s in ssh.service ssh.socket teleport.service xrdp.service auditd.service apparmor.service; do
   printf '%-23s active=%-12s enabled=%s\n' "$s" "$(systemctl is-active "$s" 2>/dev/null || :)" "$(systemctl is-enabled "$s" 2>/dev/null || :)"
 done
 section 'NETWORK — READ ONLY'
 ip -br address || :
 ip route show default || :
 section 'FIREWALL — OBSERVATION ONLY'
 if command -v ufw >/dev/null 2>&1; then ufw status verbose || :; else info 'UFW not installed'; fi
 section 'AUDIT'
 if command -v auditctl >/dev/null 2>&1; then auditctl -s || :; auditctl -l || :; else info 'auditctl not installed'; fi
 section 'SYSCTL'
 for k in net.ipv4.conf.all.accept_redirects net.ipv4.conf.default.accept_redirects net.ipv4.conf.all.send_redirects net.ipv4.conf.default.send_redirects net.ipv4.ip_forward; do sysctl "$k" 2>/dev/null || :; done
 section 'AUTOMATIC REBOOT POLICY'
 if command -v apt-config >/dev/null 2>&1; then apt-config shell AutoReboot Unattended-Upgrade::Automatic-Reboot; fi
 section 'FAILED SERVICES'
 systemctl --failed --no-pager || :
 info 'Inventory does not change the system.'
}

# Require zero removals and zero upgrades; no apt update, autoremove, kernel/driver manipulation.
audit_preflight(){
 section 'AUDITD PACKAGE INSTALLATION PREFLIGHT'
 need apt-get || return 1
 local simulation
 if ! simulation=$(apt-get -s --no-install-recommends install auditd audispd-plugins 2>&1); then printf '%s\n' "$simulation"; warn 'APT simulation failed'; return 1; fi
 printf '%s\n' "$simulation"
 if grep -Eq '^Remv |^Inst (linux-|nvidia-|libnvidia-|openssh-|network-manager|systemd|docker|containerd|teleport)' <<< "$simulation"; then
   warn 'Protected package operation proposed. Refusing.'; return 1
 fi
 if grep -Eq '^Remv ' <<< "$simulation"; then warn 'Package removals proposed. Refusing.'; return 1; fi
 if grep -E '^Inst ' <<< "$simulation" | grep -Ev '^Inst (auditd |audispd-plugins |libauparse|libauplugin)' >/dev/null; then
   warn 'Unexpected package installation or upgrade proposed. Refusing.'; return 1
 fi
 pass 'Package preflight accepted (only auditd and expected dependencies).'
}

# Use modern path/dir filesystem audit rules rather than deprecated -w watches.
audit_rules_text(){ cat <<'RULES'
## Ubuntu Security Hardening Toolkit v2 — conservative monitoring
## File modifications/attribute changes only; no broad syscall tracing.
-a always,exit -F path=/etc/passwd -F perm=wa -k identity
-a always,exit -F path=/etc/group -F perm=wa -k identity
-a always,exit -F path=/etc/shadow -F perm=wa -k identity
-a always,exit -F path=/etc/gshadow -F perm=wa -k identity
-a always,exit -F dir=/etc/pam.d/ -F perm=wa -k authentication
-a always,exit -F path=/etc/sudoers -F perm=wa -k privilege
-a always,exit -F dir=/etc/sudoers.d/ -F perm=wa -k privilege
-a always,exit -F path=/etc/ssh/sshd_config -F perm=wa -k ssh_config
-a always,exit -F path=/etc/localtime -F perm=wa -k time_change
RULES
}

audit_setup(){
 section 'AUDITD SETUP — CONFIRMATION REQUIRED'
 if ! command -v auditctl >/dev/null 2>&1 || ! dpkg-query -W -f='${Status}' auditd 2>/dev/null | grep -q 'install ok installed'; then
   audit_preflight || return 1
   confirm 'Install auditd and audispd-plugins?' || { info 'Cancelled'; return 0; }
   DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends auditd audispd-plugins || return 1
 else pass 'Auditd already installed; skipping package installation'; fi
 if ! systemctl is-active --quiet auditd.service; then
   warn 'auditd is not active. Review systemctl status auditd; no automatic service restart.'
   return 1
 fi
 local tmp
 tmp=$(mktemp "$RUN/audit.XXXXXX")
 audit_rules_text > "$tmp"
 if [[ -f "$AUDIT_FILE" ]] && cmp -s "$tmp" "$AUDIT_FILE" && [[ $(stat -c %a "$AUDIT_FILE") == 640 ]]; then
   pass 'Persistent audit rules already configured.'
 else
   printf '\nProposed audit rules:\n'; cat "$tmp"
   if ! confirm 'Save and load these audit monitoring rules?'; then rm -f "$tmp"; info 'Rules unchanged'; return 0; fi
   write_config "$AUDIT_FILE" 640 < "$tmp" || { rm -f "$tmp"; return 1; }
 fi
 rm -f "$tmp"
 if ! need augenrules; then return 1; fi
 # augenrules merges all rules in /etc/audit/rules.d; show warnings rather than masking errors.
 if ! augenrules --load; then warn 'Audit rules failed to load. Review existing rules and backups.'; return 1; fi
 local rules
 rules=$(auditctl -l 2>/dev/null || :)
 local key
 for key in identity authentication privilege ssh_config time_change; do
   if grep -Eq -- "(-k[[:space:]]+$key|-F[[:space:]]+key=$key)([[:space:]]|$)" <<< "$rules"; then pass "Audit key loaded: $key"; else warn "Audit key not confirmed: $key"; fi
 done
 auditctl -s || :
 info 'No SSH, PAM, sudo or account policies were modified.'
}

sysctl_text(){ cat <<'CONFIG'
# Ubuntu Security Hardening Toolkit v2: non-router IPv4 redirect protection.
# No changes to forwarding, reverse-path filtering, routes, IPv6, or interfaces.
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
CONFIG
}
sysctl_keys=(net.ipv4.conf.all.accept_redirects net.ipv4.conf.default.accept_redirects net.ipv4.conf.all.send_redirects net.ipv4.conf.default.send_redirects)
sysctl_setup(){
 section 'CONSERVATIVE SYSCTL HARDENING'
 info 'Applies only four IPv4 ICMP redirect settings; no routing or rp_filter changes.'
 local forward
 forward=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo unknown)
 if [[ $forward != 0 ]]; then warn "IPv4 forwarding is $forward; router-like host detected. Skipping this module."; return 0; fi
 local desired=0 k value
 for k in "${sysctl_keys[@]}"; do value=$(sysctl -n "$k" 2>/dev/null || echo unknown); [[ $value == 0 ]] || desired=1; done
 local tmp; tmp=$(mktemp "$RUN/sysctl.XXXXXX"); sysctl_text > "$tmp"
 if [[ -f "$SYSCTL_FILE" ]] && cmp -s "$tmp" "$SYSCTL_FILE" && [[ $(stat -c %a "$SYSCTL_FILE") == 644 ]] && (( desired == 0 )); then
   rm -f "$tmp"; pass 'Sysctl configuration already saved and effective'; return 0
 fi
 cat "$tmp"
 confirm 'Save and apply only these four sysctl values immediately?' || { rm -f "$tmp"; info 'Cancelled'; return 0; }
 write_config "$SYSCTL_FILE" 644 < "$tmp" || { rm -f "$tmp"; return 1; }
 rm -f "$tmp"
 # Do not reload all sysctl files: only this file is applied.
 sysctl -p "$SYSCTL_FILE" || return 1
 for k in "${sysctl_keys[@]}"; do
   value=$(sysctl -n "$k" 2>/dev/null || echo unknown)
   [[ $value == 0 ]] && pass "$k=0" || { fail "$k=$value"; return 1; }
 done
 info 'Existing interface-level settings may differ; the assessment reports them separately.'
}

updates_setup(){
 section 'UNATTENDED-UPGRADES AUTOMATIC REBOOT'
 info 'Only adds an automatic-reboot=false override; does not change package selection or upgrade timers.'
 local tmp; tmp=$(mktemp "$RUN/reboot.XXXXXX")
 printf '%s\n' 'Unattended-Upgrade::Automatic-Reboot "false";' > "$tmp"
 if [[ -f "$REBOOT_FILE" ]] && cmp -s "$tmp" "$REBOOT_FILE" && [[ $(stat -c %a "$REBOOT_FILE") == 644 ]]; then
   rm -f "$tmp"; pass 'No-auto-reboot override already configured'; return 0
 fi
 confirm 'Write no-auto-reboot override?' || { rm -f "$tmp"; info 'Cancelled'; return 0; }
 write_config "$REBOOT_FILE" 644 < "$tmp" || { rm -f "$tmp"; return 1; }
 rm -f "$tmp"
 if command -v apt-config >/dev/null 2>&1; then apt-config shell AutoReboot Unattended-Upgrade::Automatic-Reboot || :; fi
 warn 'This does NOT prevent automatic kernel/driver package upgrades; review your upgrade policy separately.'
}

permissions_check(){
 section 'PERMISSIONS AND ACCOUNTS — READ ONLY'
 for f in /etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/ssh/sshd_config; do
   [[ -e "$f" ]] && stat -c '%a %U:%G %n' "$f"
 done
 printf 'UID 0 users: '; awk -F: '$3==0 {printf "%s ", $1} END{print ""}' /etc/passwd
 info 'No account, SSH, PAM, password, sudoers, or login-attempt policy modifications.'
}

# Return nonzero only for explicit failures; warnings are separately counted.
assess(){
 section 'POST-HARDENING ASSESSMENT — READ ONLY'
 local passes=0 warnings=0 failures=0 val k key rules
 ok(){ pass "$*"; ((passes+=1)); }
 caution(){ warn "$*"; ((warnings+=1)); }
 bad(){ fail "$*"; ((failures+=1)); }
 if command -v aa-status >/dev/null 2>&1 && aa-status --enabled >/dev/null 2>&1; then ok 'AppArmor enabled'; else caution 'AppArmor not confirmed enabled'; fi
 if command -v auditctl >/dev/null 2>&1 && systemctl is-active --quiet auditd.service; then
   ok 'auditd service active'
   val=$(auditctl -s 2>/dev/null | awk '$1=="lost" {print $2}')
   [[ $val == 0 ]] && ok 'Audit lost-event counter = 0' || caution "Audit lost-event counter = ${val:-unknown}"
   rules=$(auditctl -l 2>/dev/null || :)
   for key in identity authentication privilege ssh_config time_change; do
     if grep -Eq -- "(-k[[:space:]]+$key|-F[[:space:]]+key=$key)([[:space:]]|$)" <<< "$rules"; then ok "Audit monitoring key present: $key"; else caution "Audit monitoring key missing: $key"; fi
   done
 else caution 'auditd not active or not installed'; fi
 for k in "${sysctl_keys[@]}"; do
   val=$(sysctl -n "$k" 2>/dev/null || echo unknown)
   [[ $val == 0 ]] && ok "$k=0 (effective)" || caution "$k=$val (not hardened)"
 done
 if [[ -f "$SYSCTL_FILE" ]] && grep -q 'net.ipv4.conf.all.accept_redirects = 0' "$SYSCTL_FILE"; then ok 'Persistent sysctl file present'; else caution 'Persistent sysctl configuration not confirmed'; fi
 # Interface values matter too; report rather than changing network configuration.
 for k in /proc/sys/net/ipv4/conf/*/accept_redirects /proc/sys/net/ipv4/conf/*/send_redirects; do
   [[ -r "$k" ]] || continue
   val=$(cat "$k")
   [[ $val == 0 ]] || caution "Interface-level value: $k=$val (review effective semantics)"
 done
 if command -v apt-config >/dev/null 2>&1; then
   val=$(apt-config shell AutoReboot Unattended-Upgrade::Automatic-Reboot 2>/dev/null || :)
   if grep -Eqi 'AutoReboot[[:space:]]+"?false"?;' <<< "$val"; then ok 'Effective unattended automatic reboot disabled'; else caution "Effective unattended automatic reboot not confirmed: ${val:-unset}"; fi
 else caution 'apt-config unavailable'; fi
 section 'REMOTE ACCESS SERVICES — OBSERVATION ONLY'
 for k in ssh.service ssh.socket teleport.service xrdp.service; do
   printf '%-20s %s\n' "$k" "$(systemctl is-active "$k" 2>/dev/null || :)"
 done
 section 'FIREWALL — INTENTIONALLY NOT MANAGED'
 if command -v ufw >/dev/null 2>&1; then ufw status || :; else info 'UFW not installed'; fi
 section 'FAILED SERVICES'
 systemctl --failed --no-pager || :
 section 'SUMMARY'
 printf 'PASS=%s WARN=%s FAIL=%s\n' "$passes" "$warnings" "$failures"
 info 'Warnings may reflect intentional exclusions. No security test proves the host is fully secure.'
 info 'Remote access must also be tested end-to-end, not only by systemctl status.'
 info "Session log: $LOG"
 ((failures==0))
}

show_backups(){
 section 'AVAILABLE BACKUP SESSIONS'
 local d found=0
 for d in "$BASE"/runs/*; do
   [[ -d "$d" && -s "$d/changed-files.txt" ]] || continue
   found=1
   printf '%s\n' "$(basename "$d")"
   sed 's/^/    /' "$d/changed-files.txt"
 done
 ((found)) || info 'No backed-up configuration changes found.'
}

restore(){
 section 'CONFIGURATION RESTORE — EXPLICIT CONFIRMATION'
 show_backups
 local id src file rel saved
 read -r -p 'Enter exact session ID to restore (blank cancels): ' id || return 0
 [[ -n "$id" ]] || return 0
 [[ $id =~ ^[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || { warn 'Invalid session ID'; return 1; }
 src="$BASE/runs/$id"
 [[ -d "$src/backups" && -f "$src/changed-files.txt" ]] || { warn 'Session backups not found'; return 1; }
 printf 'Files to restore:\n'; cat "$src/changed-files.txt"
 warn 'Restoring files does not uninstall packages or revert package installation side effects.'
 confirm 'Restore the listed configuration files from this session?' || { info 'Cancelled'; return 0; }
 local changed_sysctl=0 changed_audit=0
 while IFS= read -r file; do
   case "$file" in "$SYSCTL_FILE"|"$AUDIT_FILE"|"$REBOOT_FILE") ;; *) warn "Skipping unexpected target: $file"; continue;; esac
   rel=${file#/}; saved="$src/backups/$rel"
   backup_file "$file" || return 1
   if [[ -f "$saved" && ! -L "$saved" ]]; then
     cp -a -- "$saved" "$file"; pass "Restored: $file"
   elif [[ -f "$saved.ABSENT" ]]; then
     rm -f -- "$file"; pass "Removed newly created file: $file"
   else warn "No valid backup for $file"; continue
   fi
   [[ $file == "$SYSCTL_FILE" ]] && changed_sysctl=1
   [[ $file == "$AUDIT_FILE" ]] && changed_audit=1
 done < "$src/changed-files.txt"
 if ((changed_sysctl)); then
   warn 'Sysctl file restored; live values are NOT automatically reverted. Reboot or review/reapply desired settings.'
 fi
 if ((changed_audit)); then
   warn 'Audit rules file restored; active rules are NOT automatically reloaded. Review then run augenrules --load if appropriate.'
 fi
 info "Rollback backup of pre-restore state: $RUN"
}

security_logs(){
 section 'AUDITD STATUS AND RECENT EVENTS — READ ONLY'
 if command -v auditctl >/dev/null 2>&1; then auditctl -s || :; auditctl -l || :; else warn 'auditctl unavailable'; fi
 if command -v ausearch >/dev/null 2>&1; then
   echo 'Recent audit events (last 20 lines):'
   ausearch -ts recent 2>/dev/null | tail -20 || :
 fi
 if command -v journalctl >/dev/null 2>&1; then journalctl -u auditd --no-pager -n 15 || :; fi
}

apply_all(){
 section 'CONTROLLED DEPLOYMENT'
 info 'Modules: auditd monitoring, IPv4 redirect protection, unattended no-auto-reboot.'
 info 'Excluded: firewall, SSH, Wazuh, PAM, sudoers, passwords, GPU, drivers, kernel, networking.'
 confirm 'Start interactive hardening modules?' || { info 'Cancelled'; return 0; }
 audit_setup || warn 'Audit module incomplete'
 sysctl_setup || warn 'Sysctl module incomplete'
 updates_setup || warn 'Automatic reboot module incomplete'
 section 'DEPLOYMENT ASSESSMENT'
 assess || :
}

menu(){
 local choice
 while :; do
 cat <<'MENU'

=====================================================
       UBUNTU SECURITY HARDENING TOOLKIT v2
=====================================================
 1) System inventory and baseline (read only)
 2) Apply security hardening (interactive)
 3) Install/configure auditd and audit rules
 4) Configure/apply IPv4 redirect protection
 5) Disable unattended-upgrades automatic reboot
 6) Post-hardening assessment (read only)
 7) Permissions and account review (read only)
 8) View audit events and security logs
 9) List backups / restore configuration
 0) Exit
=====================================================
Firewall, SSH, Wazuh and hardware settings are NOT changed.
MENU
 read -r -p 'Select option: ' choice || break
 case "$choice" in
  1) inventory;; 2) apply_all;; 3) audit_setup;; 4) sysctl_setup;;
  5) updates_setup;; 6) assess || :;; 7) permissions_check;;
  8) security_logs;; 9) restore;; 0) break;; *) warn 'Invalid option';;
 esac
 done
}

case "${1:-menu}" in
 menu) menu;; inventory) inventory;; assess) assess;; backups) show_backups;;
 *) echo 'Usage: sudo bash ubuntu-security-hardening-v2.sh [menu|inventory|assess|backups]' >&2; exit 2;;
esac
