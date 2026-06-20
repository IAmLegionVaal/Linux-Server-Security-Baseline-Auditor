#!/usr/bin/env bash
set -u

OUTPUT_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) OUTPUT_DIR="${2:-}"; shift 2 ;;
    -h|--help) echo "Usage: $0 [--output DIRECTORY]"; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

STAMP="$(date +%Y%m%d_%H%M%S)"
OUTPUT_DIR="${OUTPUT_DIR:-./linux-security-audit-$STAMP}"
mkdir -p "$OUTPUT_DIR"
REPORT="$OUTPUT_DIR/security-baseline.txt"
JSON="$OUTPUT_DIR/security-summary.json"
ERRORS="$OUTPUT_DIR/command-errors.log"
: > "$REPORT"; : > "$ERRORS"

section() {
  local title="$1"; shift
  {
    printf '\n===== %s =====\n' "$title"
    "$@"
  } >> "$REPORT" 2>> "$ERRORS" || true
}

have() { command -v "$1" >/dev/null 2>&1; }

[[ $EUID -ne 0 ]] && echo "WARNING: Run as root for complete evidence." | tee -a "$REPORT"
section "Collection metadata" bash -c 'date -Is; hostname -f 2>/dev/null || hostname; id'
section "Operating system" bash -c 'cat /etc/os-release 2>/dev/null || true; uname -a'

SSHD_CONFIG="/etc/ssh/sshd_config"
if [[ -r "$SSHD_CONFIG" ]]; then
  section "Effective SSH settings" bash -c 'sshd -T 2>/dev/null | grep -Ei "^(permitrootlogin|passwordauthentication|permitemptypasswords|pubkeyauthentication|maxauthtries|allowusers|allowgroups)" || grep -Ei "^[[:space:]]*(PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords|PubkeyAuthentication|MaxAuthTries|AllowUsers|AllowGroups)" /etc/ssh/sshd_config'
else
  echo -e "\n===== SSH =====\nOpenSSH server configuration not found." >> "$REPORT"
fi

if have ufw; then
  section "Firewall" ufw status verbose
elif have firewall-cmd; then
  section "Firewall" bash -c 'firewall-cmd --state; firewall-cmd --get-active-zones; firewall-cmd --list-all'
elif have nft; then
  section "Firewall" nft list ruleset
else
  echo -e "\n===== Firewall =====\nNo supported firewall management command detected." >> "$REPORT"
fi

if have getenforce; then section "SELinux" bash -c 'getenforce; sestatus 2>/dev/null || true'; fi
if have aa-status; then section "AppArmor" aa-status; fi
section "Privileged groups" bash -c 'getent group sudo 2>/dev/null || true; getent group wheel 2>/dev/null || true; getent group adm 2>/dev/null || true'
section "Sudo policy files" bash -c 'ls -la /etc/sudoers /etc/sudoers.d 2>/dev/null || true; visudo -c 2>/dev/null || true'
section "Listening sockets" bash -c 'ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null || true'
section "Authentication failures" bash -c 'journalctl --since "24 hours ago" --no-pager 2>/dev/null | grep -Ei "failed password|authentication failure|invalid user" | tail -n 200 || true'
section "Security services" bash -c 'for s in auditd fail2ban chronyd systemd-timesyncd; do systemctl is-enabled "$s" 2>/dev/null | sed "s/^/$s enabled: /"; systemctl is-active "$s" 2>/dev/null | sed "s/^/$s active: /"; done'
section "World-writable system files" bash -c 'find /etc /usr/local/bin /usr/local/sbin -xdev -type f -perm -0002 -print 2>/dev/null | head -n 200'
section "Automatic updates" bash -c 'systemctl status unattended-upgrades 2>/dev/null --no-pager || true; systemctl list-timers --all 2>/dev/null | grep -Ei "apt|dnf|yum|update" || true'

ROOT_LOGIN="unknown"
PASSWORD_AUTH="unknown"
if have sshd; then
  ROOT_LOGIN="$(sshd -T 2>/dev/null | awk '/^permitrootlogin / {print $2; exit}')"
  PASSWORD_AUTH="$(sshd -T 2>/dev/null | awk '/^passwordauthentication / {print $2; exit}')"
fi
FIREWALL="unknown"
if have ufw; then FIREWALL="$(ufw status 2>/dev/null | awk -F': ' '/Status/ {print $2}')";
elif have firewall-cmd; then FIREWALL="$(firewall-cmd --state 2>/dev/null || echo inactive)";
elif have nft; then FIREWALL="present"; fi

cat > "$JSON" <<EOF
{
  "collected_at": "$(date -Is)",
  "hostname": "$(hostname -f 2>/dev/null || hostname)",
  "ssh_permit_root_login": "${ROOT_LOGIN:-unknown}",
  "ssh_password_authentication": "${PASSWORD_AUTH:-unknown}",
  "firewall_status": "${FIREWALL:-unknown}",
  "note": "Findings require technician review against approved policy."
}
EOF

printf '\nAudit completed. Output: %s\n' "$OUTPUT_DIR" | tee -a "$REPORT"
