# Ubuntu Security Hardening Toolkit (Bash)

Interactive, conservative hardening for Ubuntu desktops. **Never modifies Wazuh or SSH.**

## Usage

```bash
chmod +x harden.sh
./harden.sh --audit              # Read-only assessment
./harden.sh --dry-run            # Preview each module
sudo ./harden.sh                 # System-wide modules (2–6, 10, 11)
./harden.sh                      # GNOME desktop-user settings (7)
```

`0` exits the main menu. Each change requires confirmation. The guided workflow requests confirmation for each module. For a new machine, assess first, then configure modules individually. Avoid running guided hardening on production/remote machines.

## Modules

1. Read-only assessment
2. Kernel/sysctl workstation profile
3. UFW defaults and optional activation; **may block remote services**
4. Auditd identity, sudo and audit-config watches
5. Lightweight ClamAV and FreshClam
6. Automatic security updates; unattended reboot disabled
7. GNOME removable-media automount and screen-lock settings (run without sudo)
8. Read-only service and port review
9. Read-only Secure Boot, storage and authentication review
10. Guided hardening (system modules, confirmations)
11. Restore managed config files from backups

## Safety and limitations

- Ubuntu-only. No SSH or Wazuh changes, including SSH disabling.
- Does not modify Secure Boot, disk encryption, sudo policy, passwords, kernel packages, or existing AppArmor profiles.
- Does not stop services automatically.
- Writes dedicated config files rather than editing existing distribution config files.
- Makes per-run backups under `/var/lib/ubuntu-hardening-toolkit/backups/` and logs privileged runs to `/var/log/ubuntu-hardening-toolkit/`.
- Restore only handles toolkit-managed config files; it does not revert installed packages, firewall settings, or GNOME dconf settings.
- `--dry-run` previews actions but cannot simulate their effects. The firewall may block remote access: configure required inbound allow rules **before** enabling it.
- Kernel network forwarding changes can disrupt routers, VPN gateways, Docker/Kubernetes and other hosts. Review sysctl module before applying.
- ClamAV is on-demand only, not a continuous antivirus daemon. It does not delete files automatically.
- GNOME settings are per-user and require a running desktop session; run module 7 without sudo.
- `--yes` is intended for controlled testing, not remote deployment.
- Auditd watches may require adjustments on unusual Ubuntu configurations; audit rule load errors should be reviewed.
- No system-hardening tool guarantees compliance or absence of vulnerabilities. Verify after applying.
