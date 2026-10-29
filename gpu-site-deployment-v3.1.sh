#!/usr/bin/env bash
# GPU site desktop preparation. No production-service management.
set -Eeuo pipefail
umask 077
BASE=/var/lib/gpu-site-desktop
VALIDATED_THIS_RUN=0
mkdir -p "$BASE"
RUN="$BASE/$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -p "$RUN"
exec > >(tee -a "$RUN/run.log") 2>&1
trap 'echo "[ERROR] Line $LINENO. Log: $RUN/run.log" >&2' ERR
log(){ printf '\n[%s] %s\n' "$(date +%T)" "$*"; }
warn(){ printf '[WARNING] %s\n' "$*"; }
ask(){ local a; read -r -p "$1 (type YES): " a; [[ "$a" == YES ]]; }
require_root(){ (( EUID == 0 )) || { echo 'Run using sudo'; exit 1; }; }
version(){ . /etc/os-release; [[ "$ID" == ubuntu ]] || { warn 'Ubuntu only'; return 1; }; case "$VERSION_ID" in 22.04|24.04|26.04) :;; *) warn "Ubuntu $VERSION_ID not in approved target list"; return 1;; esac; }
unit_state(){ printf '%-27s enabled=%-12s active=%s\n' "$1" "$(systemctl is-enabled "$1" 2>/dev/null || :)" "$(systemctl is-active "$1" 2>/dev/null || :)"; }
backup(){ local p=$1; [[ -f "$RUN/manifest" ]] && grep -Fqx "$p" "$RUN/manifest" && return 0; echo "$p" >> "$RUN/manifest"; if [[ -e "$p" || -L "$p" ]]; then mkdir -p "$RUN/old$(dirname "$p")"; cp -a -- "$p" "$RUN/old$p"; else echo "$p" >> "$RUN/new"; fi; }
write_file(){
 local target=$1 dir tmp
 backup "$target"
 dir=$(dirname "$target")
 mkdir -p "$dir"
 tmp=$(mktemp "$dir/.gpu-site.XXXXXXXX")
 if ! cat > "$tmp"; then rm -f "$tmp"; return 1; fi
 chown root:root "$tmp"
 chmod 644 "$tmp"
 mv -f -- "$tmp" "$target"
}
status_snapshot(){ for u in docker.service containerd.service teleport.service upower.service snapd.service snapd.socket lightdm.service gdm3.service display-manager.service xrdp.service xrdp-sesman.service; do unit_state "$u"; done; }
inventory(){
 log 'INVENTORY AND DIAGNOSIS (READ ONLY)'
 grep -E '^(PRETTY_NAME|VERSION_ID|ID)=' /etc/os-release || :
 printf 'Hostname: '; hostname; printf 'Kernel: '; uname -r; printf 'Uptime: '; uptime -p || :
 log 'CPU / MEMORY / STORAGE'; lscpu | grep -E 'Model name:|Architecture:' || :; free -h; df -h /; 
 log 'GPU'; if command -v lspci >/dev/null; then lspci | grep -Ei 'VGA|3D controller|Display controller' || :; else warn 'lspci not installed'; fi
 if command -v nvidia-smi >/dev/null; then timeout 12 nvidia-smi -L || warn 'nvidia-smi failed'; else warn 'nvidia-smi not available'; fi
 log 'NETWORK (READ ONLY)'; ip -br address || :; ip route show default || :
 log 'DESKTOP'; cat /etc/X11/default-display-manager 2>/dev/null || :; ls /usr/share/xsessions/ 2>/dev/null || :
 log 'SERVICE STATUS'; status_snapshot
 log 'XRDP/XORG RECENT ERRORS'; journalctl -u xrdp -u xrdp-sesman -n 15 --no-pager 2>/dev/null || :
 log 'UPower / SNAPD ERRORS'; journalctl -u upower.service -u snapd.service -n 12 --no-pager 2>/dev/null || :
 log 'BIOS POWER RECOVERY'; warn 'AC power-loss recovery must be configured in BIOS/UEFI; not automatically modified.'
}
PKGS=(xfce4 xfce4-terminal xfce4-goodies lightdm lightdm-gtk-greeter xrdp xorgxrdp dbus-x11 xserver-xorg-input-libinput)
# Fail closed if apt would modify any preexisting package other than desktop stack.
plan(){
 version || return 1
 [[ -d /run/systemd/system ]] || { warn 'systemd required'; return 1; }
 log 'APT SIMULATION'; local sim line name
 sim=$(apt-get -s -o Debug::NoLocking=1 install --no-install-recommends "${PKGS[@]}") || return 1
 printf '%s\n' "$sim" | tee "$RUN/apt-simulation.txt"
 if grep -Eq '^(Remv|Purg) ' <<< "$sim"; then warn 'APT proposes package removal or purge; refusing'; return 1; fi
 if grep -Eq '^Inst (linux-|nvidia-|libnvidia-|cuda-|docker|containerd|teleport|network-manager|netplan.io|openssh-)' <<< "$sim"; then warn 'APT proposes modifying protected components; refusing'; return 1; fi

 # Existing packages outside a restricted desktop allowlist must not be upgraded/replaced.
 while read -r name; do
   [[ -z "$name" ]] && continue
   if dpkg-query -W -f='${Status}' "$name" 2>/dev/null | grep -q 'install ok installed'; then
     case "$name" in xfce4*|libxfce4*|xfconf*|xfdesktop*|xfwm4*|thunar*|lightdm*|xrdp*|xorgxrdp*|dbus-x11|xfce4-session|xfce4-panel|xserver-xorg-input-libinput) :;; *) warn "APT would change existing package $name; refusing to protect production dependencies"; return 1;; esac
   fi
 done < <(awk '/^Inst /{print $2}' <<< "$sim")
 warn 'APT scripts can still affect services indirectly; package simulation is not a full isolation guarantee.'
}
install_desktop(){
 log 'INSTALLING DESKTOP PACKAGES';
 # Preflight before apt update, then refresh package lists and recheck.
 plan || return 1
 apt-get update || return 1
 plan || return 1
 # Avoid interactive DM prompt; does not restart running DM itself.
 printf 'lightdm shared/default-x-display-manager select lightdm\n' | debconf-set-selections
 DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${PKGS[@]}"
}
configure_desktop(){
 log 'CONFIGURING XFCE / LIGHTDM / XRDP'
 [[ -x /usr/bin/startxfce4 && -f /usr/share/xsessions/xfce.desktop && -f /etc/xrdp/startwm.sh && -x /usr/sbin/lightdm ]] || { warn 'Required desktop packages missing'; return 1; }
 write_file /etc/xrdp/startwm.sh <<'EOF'
#!/bin/sh
unset DBUS_SESSION_BUS_ADDRESS
unset XDG_RUNTIME_DIR
export XDG_CURRENT_DESKTOP=XFCE
export DESKTOP_SESSION=xfce
export XDG_SESSION_TYPE=x11
exec /usr/bin/startxfce4
EOF
 chmod 755 /etc/xrdp/startwm.sh
 write_file /etc/lightdm/lightdm.conf.d/90-gpu-site.conf <<'EOF'
[Seat:*]
user-session=xfce
allow-guest=false
EOF
 # Configure systemd's DM selection without restarting an active graphical session.
 backup /etc/X11/default-display-manager
 printf '/usr/sbin/lightdm\n' > /etc/X11/default-display-manager
 if [[ -L /etc/systemd/system/display-manager.service ]]; then backup /etc/systemd/system/display-manager.service; fi
 # systemctl enable --force lightdm changes the DM symlink; do not start/restart it.
 systemctl enable --force lightdm.service
 systemctl enable xrdp.service
 if systemctl list-unit-files xrdp-sesman.service --no-legend 2>/dev/null | grep -q '^xrdp-sesman.service'; then systemctl enable xrdp-sesman.service; fi
 if id xrdp >/dev/null 2>&1 && getent group ssl-cert >/dev/null; then usermod -aG ssl-cert xrdp; fi
 log 'XFCE selected. GNOME retained. No display manager restarted; XRDP firewall untouched.'
}
configure_no_sleep(){
 log 'CONFIGURING 24/7 POWER POLICY WITHOUT MASKING SLEEP TARGETS'
 # Drop-ins do not restart logind or alter running user sessions.
 write_file /etc/systemd/logind.conf.d/90-gpu-server.conf <<'EOF'
[Login]
IdleAction=ignore
HandleLidSwitch=ignore
HandleLidSwitchExternalPower=ignore
HandleLidSwitchDocked=ignore
HandleSuspendKey=ignore
HandleHibernateKey=ignore
HandlePowerKey=poweroff
EOF
 write_file /etc/systemd/sleep.conf.d/90-gpu-server.conf <<'EOF'
[Sleep]
AllowSuspend=no
AllowHibernation=no
AllowHybridSleep=no
AllowSuspendThenHibernate=no
EOF
 # XFCE system defaults: users with existing per-user settings may override these.
 # System sleep is independently blocked by systemd sleep.conf.
 write_file /etc/xdg/xfce4/xfconf/xfce-perchannel-xml/xfce4-power-manager.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<channel name="xfce4-power-manager" version="1.0">
  <property name="xfce4-power-manager" type="empty">
    <property name="inactivity-on-ac" type="uint" value="14"/>
    <property name="inactivity-on-battery" type="uint" value="14"/>
    <property name="dpms-enabled" type="bool" value="false"/>
    <property name="blank-on-ac" type="int" value="0"/>
    <property name="blank-on-battery" type="int" value="0"/>
  </property>
</channel>
EOF
 log 'Power policy saved; it becomes effective after controlled reboot/new XFCE login.'
 warn 'Existing per-user XFCE preferences can override system defaults; check actual sessions after reboot.'
 warn 'BIOS/UEFI AC power recovery must be enabled manually; no firmware changes performed.'
}
repair_desktop_support(){
 log 'REPAIRING KNOWN MASKED DESKTOP SUPPORT SERVICES'
 local u pkg st
 for entry in upower.service:upower snapd.service:snapd snapd.socket:snapd; do
   u=${entry%%:*}; pkg=${entry#*:}
   if ! dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q 'install ok installed'; then warn "$pkg absent; skipping $u"; continue; fi
   st=$(systemctl is-enabled "$u" 2>/dev/null || :)
   if [[ "$st" == masked ]]; then
     log "$u is masked"; systemctl unmask "$u"; log "Unmasked $u (no service restart)"
   else log "$u is $st; no changes"; fi
 done
 # Restore power-profiles-daemon activation if it was masked and installed.
 if dpkg-query -W -f='${Status}' power-profiles-daemon 2>/dev/null | grep -q 'install ok installed'; then
   st=$(systemctl is-enabled power-profiles-daemon.service 2>/dev/null || :)
   if [[ "$st" == masked ]]; then systemctl unmask power-profiles-daemon.service; log 'Unmasked power-profiles-daemon (not started)'; fi
 fi
}
# Read-only repeat-run assessment. Any mismatch requires explicit operator approval.
deployment_state(){
 local missing=0 pkg f
 log 'CHECKING EXISTING DEPLOYMENT (READ ONLY)'
 for pkg in "${PKGS[@]}"; do
  if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -qx 'install ok installed'; then
   printf '[PASS] Package %s installed\n' "$pkg"
  else printf '[CHANGE] Package %s missing\n' "$pkg"; missing=$((missing+1)); fi
 done
 for f in /usr/share/xsessions/xfce.desktop /usr/lib/xorg/modules/input/libinput_drv.so; do
  if [[ -r "$f" ]]; then printf '[PASS] %s\n' "$f"; else printf '[CHANGE] Missing %s\n' "$f"; missing=$((missing+1)); fi
 done
 # Compare the exact managed configuration, not merely whether files exist.
 local expected
 expected=$(cat <<'EOF'
#!/bin/sh
unset DBUS_SESSION_BUS_ADDRESS
unset XDG_RUNTIME_DIR
export XDG_CURRENT_DESKTOP=XFCE
export DESKTOP_SESSION=xfce
export XDG_SESSION_TYPE=x11
exec /usr/bin/startxfce4
EOF
)
 if [[ -f /etc/xrdp/startwm.sh ]] && [[ $(cat /etc/xrdp/startwm.sh) == "$expected" ]] && [[ $(stat -c %a /etc/xrdp/startwm.sh) == 755 ]]; then
  echo '[PASS] XRDP launcher matches deployment configuration'
 else echo '[CHANGE] XRDP launcher differs'; missing=$((missing+1)); fi
 expected=$(printf '[Seat:*]\nuser-session=xfce\nallow-guest=false')
 if [[ -f /etc/lightdm/lightdm.conf.d/90-gpu-site.conf ]] && [[ $(cat /etc/lightdm/lightdm.conf.d/90-gpu-site.conf) == "$expected" ]] && [[ $(stat -c %a /etc/lightdm/lightdm.conf.d/90-gpu-site.conf) == 644 ]]; then
  echo '[PASS] LightDM config and permissions match'
 else echo '[CHANGE] LightDM configuration or permissions differ'; missing=$((missing+1)); fi
 if [[ $(cat /etc/X11/default-display-manager 2>/dev/null || :) == /usr/sbin/lightdm ]] && [[ $(readlink -f /etc/systemd/system/display-manager.service 2>/dev/null || :) == *lightdm* ]]; then
  echo '[PASS] LightDM selected'
 else echo '[CHANGE] LightDM selection differs'; missing=$((missing+1)); fi
 for f in /etc/systemd/logind.conf.d/90-gpu-server.conf /etc/systemd/sleep.conf.d/90-gpu-server.conf /etc/xdg/xfce4/xfconf/xfce-perchannel-xml/xfce4-power-manager.xml; do
  if [[ -f "$f" && $(stat -c %a "$f") == 644 ]]; then
   case "$f" in
    */logind.conf.d/*) grep -qFx 'IdleAction=ignore' "$f" || { echo "[CHANGE] $f policy differs"; missing=$((missing+1)); continue; };;
    */sleep.conf.d/*) for setting in AllowSuspend AllowHibernation AllowHybridSleep AllowSuspendThenHibernate; do grep -qFx "$setting=no" "$f" || { echo "[CHANGE] $f: $setting"; missing=$((missing+1)); }; done;;
    */xfce4-power-manager.xml) grep -qF 'dpms-enabled' "$f" || { echo "[CHANGE] $f differs"; missing=$((missing+1)); continue; };;
   esac
   echo "[PASS] $f present with correct permissions"
  else echo "[CHANGE] $f missing or permissions differ"; missing=$((missing+1)); fi
 done
 for pkg in xrdp.service xrdp-sesman.service lightdm.service; do
  if systemctl is-enabled --quiet "$pkg" 2>/dev/null; then echo "[PASS] $pkg enabled"; else echo "[CHANGE] $pkg not enabled"; missing=$((missing+1)); fi
 done
 for pkg in upower.service snapd.service snapd.socket power-profiles-daemon.service; do
  if [[ $(systemctl is-enabled "$pkg" 2>/dev/null || :) == masked ]]; then echo "[CHANGE] $pkg masked"; missing=$((missing+1)); fi
 done
 printf '\nDeployment differences found: %d\n' "$missing"
 (( missing == 0 ))
}
confirm_reapply(){
 local response
 cat <<'EOF'

WARNING: Reapplying may overwrite local XRDP, LightDM and power
settings, modify packages, and indirectly affect running sessions.
Backups of managed configuration files are recorded for this run.
This is NOT a rollback or a guarantee of uninterrupted operation.
EOF
 read -r -p 'Type REAPPLY to proceed (anything else cancels): ' response || return 1
 [[ "$response" == REAPPLY ]]
}
activate(){
 log 'ACTIVATION — REPEAT-SAFE DESKTOP SETUP'
 version || return 1
 local choice
 if deployment_state; then
  cat <<'EOF'

SYSTEM ALREADY CONFIGURED (STATIC CHECKS)
 1) Skip installation (Recommended)
 2) Reapply deployment (requires confirmation)
 3) Cancel
EOF
  read -r -p 'Select option: ' choice || return 0
  case "$choice" in
   1) log 'No deployment changes made'; return 0;;
   2) confirm_reapply || { warn 'Cancelled'; return 0; };;
   *) warn 'Cancelled; no deployment changes'; return 0;;
  esac
 else
  cat <<'EOF'

DEPLOYMENT IS INCOMPLETE OR DIFFERS FROM EXPECTED SETTINGS.
 1) Skip (Recommended until reviewed)
 2) Repair/reapply deployment (requires confirmation)
 3) Cancel
EOF
  read -r -p 'Select option: ' choice || return 0
  case "$choice" in
   2) confirm_reapply || { warn 'Cancelled'; return 0; };;
   *) warn 'Cancelled; no deployment changes'; return 0;;
  esac
 fi
 warn 'Run only with local console and independent recovery access.'
 warn 'APT may indirectly affect services. No reboot or display-manager restart is intentional.'
 install_desktop || return 1
 configure_desktop || return 1
 repair_desktop_support || return 1
 configure_no_sleep || return 1
 VALIDATED_THIS_RUN=0
 log 'ACTIVATION FINISHED — checking configuration'
 validate || { warn 'Validation failed. Do not reboot or deploy to production.'; return 1; }
 warn 'Physical keyboard/mouse, local login and XRDP require manual acceptance after reboot.'
}

validate(){
 VALIDATED_THIS_RUN=0
 log 'VALIDATION AND VERIFICATION (READ ONLY)'; local failures=0
 check_file(){ if [[ -f "$1" ]]; then echo "PASS file $1"; else echo "FAIL file $1"; failures=$((failures+1)); fi; }
 check_cmd(){ if command -v "$1" >/dev/null; then echo "PASS command $1"; else echo "FAIL command $1"; failures=$((failures+1)); fi; }
 check_file /usr/share/xsessions/xfce.desktop
 check_file /etc/xrdp/startwm.sh
 check_file /etc/lightdm/lightdm.conf.d/90-gpu-site.conf
 check_file /etc/systemd/logind.conf.d/90-gpu-server.conf
 check_file /etc/systemd/sleep.conf.d/90-gpu-server.conf
 check_file /etc/xdg/xfce4/xfconf/xfce-perchannel-xml/xfce4-power-manager.xml
 if grep -Eq '^IdleAction=ignore$' /etc/systemd/logind.conf.d/90-gpu-server.conf 2>/dev/null; then echo 'PASS logind idle sleep disabled'; else echo 'FAIL logind idle policy'; failures=$((failures+1)); fi
 for setting in AllowSuspend AllowHibernation AllowHybridSleep AllowSuspendThenHibernate; do
   if grep -Eq "^${setting}=no$" /etc/systemd/sleep.conf.d/90-gpu-server.conf 2>/dev/null; then echo "PASS ${setting}=no"; else echo "FAIL ${setting} policy"; failures=$((failures+1)); fi
 done
 for u in upower.service snapd.service snapd.socket power-profiles-daemon.service; do
   if [[ $(systemctl is-enabled "$u" 2>/dev/null || :) == masked ]]; then echo "FAIL masked desktop support unit: $u"; failures=$((failures+1)); fi
 done
 check_cmd startxfce4; check_cmd Xorg; check_cmd xrdp
 if dpkg-query -W -f='${Status}' xserver-xorg-input-libinput 2>/dev/null | grep -qx 'install ok installed' && [[ -r /usr/lib/xorg/modules/input/libinput_drv.so ]]; then
   echo 'PASS Xorg physical input driver installed'
 else echo 'FAIL Xorg physical input driver missing'; failures=$((failures+1)); fi
 if [[ -f /etc/lightdm/lightdm.conf.d/90-gpu-site.conf ]]; then
   conf_mode=$(stat -c %a /etc/lightdm/lightdm.conf.d/90-gpu-site.conf)
   if [[ "$conf_mode" == 644 ]]; then echo 'PASS LightDM config permissions 644'; else echo "FAIL LightDM config permissions: $conf_mode"; failures=$((failures+1)); fi
 fi
 if [[ $(cat /etc/X11/default-display-manager 2>/dev/null || :) == /usr/sbin/lightdm ]]; then echo 'PASS default DM preference: LightDM'; else echo 'FAIL default DM preference'; failures=$((failures+1)); fi
 if [[ $(readlink -f /etc/systemd/system/display-manager.service 2>/dev/null || :) == *lightdm* ]]; then echo 'PASS systemd display manager: LightDM'; else echo 'WARN systemd display manager not linked to LightDM'; fi
 if grep -q 'exec /usr/bin/startxfce4' /etc/xrdp/startwm.sh 2>/dev/null; then echo 'PASS XRDP starts XFCE'; else echo 'FAIL XRDP XFCE launcher'; failures=$((failures+1)); fi
 for u in xrdp.service xrdp-sesman.service lightdm.service upower.service snapd.service snapd.socket; do unit_state "$u"; done
 if command -v nvidia-smi >/dev/null; then timeout 12 nvidia-smi -L || { echo 'FAIL NVIDIA health check'; failures=$((failures+1)); }; else echo 'WARN nvidia-smi unavailable (verify GPU requirement)'; fi
 log "Verification failures: $failures; logs: $RUN/run.log"
 if (( failures == 0 )); then VALIDATED_THIS_RUN=1; echo 'STATIC CONFIGURATION PASS ONLY — local input, physical login, XRDP login, and workload recovery require manual acceptance tests'; else echo 'CONFIGURATION INCOMPLETE'; return 1; fi
}
reboot_menu(){
 while :; do
 cat <<'EOF'

==============================================
                REBOOT SERVER
==============================================
Before rebooting, run Option 3 (Validation & Verification)
and check production workloads, remote access, and local console.
Reboot interrupts all running processes and connections.

 1) Status checked
 2) Back
==============================================
EOF
 local c confirm
 read -r -p 'Select option: ' c || return 0
 case "$c" in
  1)
    if (( VALIDATED_THIS_RUN != 1 )); then
      warn 'First run Option 3 successfully in this script session. Reboot not initiated.'
      continue
    fi
    warn 'Static checks do not verify physical keyboard/mouse, physical login, XRDP login, camera streams, or GPU workload recovery.'
    warn 'Reboot is permitted only during an approved maintenance window with independent recovery access.' 
    read -r -p 'Type REBOOT to confirm immediate system reboot: ' confirm || return 0
    if [[ "$confirm" == REBOOT ]]; then
      log 'Operator confirmed status checked and reboot. Initiating reboot.'
      sync
      systemctl reboot
      return $?
    fi
    warn 'Reboot cancelled.'
    ;;
  2) return 0;;
  *) warn 'Invalid option';;
 esac
 done
}
menu(){
 while :; do
 cat <<'EOF'

==============================================
         GPU SERVER SITE PREPARATION
==============================================
 1) Inventory & Diagnosis
 2) Activate the Process
 3) Validation & Verification
 4) Reboot
 0) Exit
==============================================
EOF
 local c; read -r -p 'Select option: ' c || break
 case "$c" in
 1) inventory;;
 2) activate || warn 'Activation stopped due to an error; review log.';;
 3) validate || warn 'Validation failed.';;
 4) reboot_menu || warn 'Reboot command failed.';;
 0) break;;
 *) warn 'Invalid option';;
 esac
 done
}
require_root
case "${1:-menu}" in menu) menu;; inventory) inventory;; activate) activate;; validate) validate;; reboot) reboot_menu;; *) echo 'Usage: sudo bash gpu-site-deployment-final.sh [menu|inventory|activate|validate|reboot]'; exit 2;; esac