#!/usr/bin/env bash
set -u

FIX_PERMISSIONS=false
ENABLE_AUDIT=false
ENABLE_TIME=false
SSH_ROOT_LOGIN=""
SSH_PASSWORD_AUTH=""
DRY_RUN=false
ASSUME_YES=false
OUTPUT_DIR=""
FAILURES=0
ACTIONS=0

usage() {
  cat <<'EOF'
Usage: linux_security_baseline_repair.sh [options]

  --fix-permissions              Correct standard permissions on SSH and sudo configuration.
  --enable-audit                 Enable and start auditd when installed.
  --enable-time-sync             Enable an installed time synchronisation service.
  --ssh-root-login VALUE         Set PermitRootLogin in a managed SSH drop-in.
  --ssh-password-auth yes|no     Set PasswordAuthentication in the same drop-in.
  --dry-run                      Show commands without changing the system.
  --yes                          Skip confirmation prompts.
  --output DIR                   Save logs, backups and verification output in DIR.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --fix-permissions) FIX_PERMISSIONS=true; shift ;;
    --enable-audit) ENABLE_AUDIT=true; shift ;;
    --enable-time-sync) ENABLE_TIME=true; shift ;;
    --ssh-root-login) SSH_ROOT_LOGIN="${2:-}"; shift 2 ;;
    --ssh-password-auth) SSH_PASSWORD_AUTH="${2:-}"; shift 2 ;;
    --dry-run) DRY_RUN=true; shift ;;
    --yes) ASSUME_YES=true; shift ;;
    --output) OUTPUT_DIR="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

if ! $FIX_PERMISSIONS && ! $ENABLE_AUDIT && ! $ENABLE_TIME && [ -z "$SSH_ROOT_LOGIN" ] && [ -z "$SSH_PASSWORD_AUTH" ]; then echo "Choose at least one repair action." >&2; exit 2; fi
case "$SSH_PASSWORD_AUTH" in ''|yes|no) : ;; *) echo "SSH password authentication must be yes or no." >&2; exit 2 ;; esac
case "$SSH_ROOT_LOGIN" in ''|yes|no|prohibit-password|forced-commands-only) : ;; *) echo "Unsupported PermitRootLogin value." >&2; exit 2 ;; esac

STAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="${OUTPUT_DIR:-./security-baseline-repair-$STAMP}"
BACKUP_DIR="$OUTPUT_DIR/backup"
mkdir -p "$OUTPUT_DIR" "$BACKUP_DIR"
LOG="$OUTPUT_DIR/repair.log"
VERIFY="$OUTPUT_DIR/verification.txt"
: > "$LOG"

log() { printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" | tee -a "$LOG"; }
confirm() { $ASSUME_YES && return 0; read -r -p "$1 [y/N]: " answer; case "$answer" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac; }
run_action() {
  local description="$1"; shift
  ACTIONS=$((ACTIONS + 1)); log "$description"
  if $DRY_RUN; then printf 'DRY-RUN:' >> "$LOG"; printf ' %q' "$@" >> "$LOG"; printf '\n' >> "$LOG"; return 0; fi
  if "$@" >> "$LOG" 2>&1; then log "SUCCESS: $description"; return 0; fi
  FAILURES=$((FAILURES + 1)); log "WARNING: $description failed"; return 1
}
run_root() { local description="$1"; shift; if [ "$(id -u)" -eq 0 ]; then run_action "$description" "$@"; else run_action "$description" sudo "$@"; fi; }
verify() {
  {
    echo "Collected: $(date -Is)"
    echo "SSH effective settings:"
    if command -v sshd >/dev/null 2>&1; then sshd -T 2>&1 | grep -E '^(permitrootlogin|passwordauthentication|permitemptypasswords) '; else echo "sshd not installed"; fi
    echo
    echo "Configuration permissions:"
    stat -c '%a %U:%G %n' /etc/ssh/sshd_config /etc/sudoers 2>/dev/null || true
    find /etc/sudoers.d -maxdepth 1 -type f -printf '%m %u:%g %p\n' 2>/dev/null || true
    echo
    systemctl status auditd --no-pager -l 2>/dev/null || true
    echo
    timedatectl status 2>/dev/null || true
  } > "$VERIFY"
}

verify
confirm "Apply the selected security baseline repairs? Verify remote access before changing SSH settings." || { log "Repair cancelled."; exit 10; }

if $FIX_PERMISSIONS; then
  [ -f /etc/ssh/sshd_config ] && run_root "Setting SSH configuration permissions" chmod 600 /etc/ssh/sshd_config || true
  [ -f /etc/sudoers ] && run_root "Setting sudoers permissions" chmod 440 /etc/sudoers || true
  if [ -d /etc/sudoers.d ]; then
    while IFS= read -r file; do run_root "Setting sudoers include permissions on $file" chmod 440 "$file" || true; done < <(find /etc/sudoers.d -maxdepth 1 -type f 2>/dev/null)
  fi
  command -v visudo >/dev/null 2>&1 && run_root "Validating sudo configuration" visudo -c || true
fi

if [ -n "$SSH_ROOT_LOGIN" ] || [ -n "$SSH_PASSWORD_AUTH" ]; then
  command -v sshd >/dev/null 2>&1 || { FAILURES=$((FAILURES + 1)); log "WARNING: sshd is not installed."; }
  DROPIN_DIR=/etc/ssh/sshd_config.d
  DROPIN="$DROPIN_DIR/99-support-baseline.conf"
  if [ "$FAILURES" -eq 0 ]; then
    if ! $DRY_RUN; then
      run_root "Creating SSH drop-in directory" mkdir -p "$DROPIN_DIR" || true
      [ -f "$DROPIN" ] && run_root "Backing up existing SSH baseline drop-in" cp -a "$DROPIN" "$BACKUP_DIR/" || true
      TEMP_FILE=$(mktemp)
      { [ -n "$SSH_ROOT_LOGIN" ] && echo "PermitRootLogin $SSH_ROOT_LOGIN"; [ -n "$SSH_PASSWORD_AUTH" ] && echo "PasswordAuthentication $SSH_PASSWORD_AUTH"; } > "$TEMP_FILE"
      run_root "Installing managed SSH baseline drop-in" install -o root -g root -m 600 "$TEMP_FILE" "$DROPIN" || true
      rm -f "$TEMP_FILE"
      if run_root "Validating SSH configuration" sshd -t; then
        if systemctl list-unit-files sshd.service >/dev/null 2>&1; then run_root "Reloading sshd" systemctl reload sshd || true; else run_root "Reloading ssh" systemctl reload ssh || true; fi
      else
        FAILURES=$((FAILURES + 1)); log "WARNING: SSH validation failed; restore the backup before reloading."
      fi
    else
      log "DRY-RUN: create $DROPIN and validate with sshd -t"
    fi
  fi
fi

if $ENABLE_AUDIT; then
  if systemctl list-unit-files auditd.service >/dev/null 2>&1; then run_root "Enabling auditd" systemctl enable --now auditd || true; else FAILURES=$((FAILURES + 1)); log "WARNING: auditd is not installed."; fi
fi

if $ENABLE_TIME; then
  TIME_UNIT=""
  for unit in chronyd.service chrony.service systemd-timesyncd.service ntpd.service; do systemctl list-unit-files "$unit" >/dev/null 2>&1 && { TIME_UNIT="$unit"; break; }; done
  if [ -n "$TIME_UNIT" ]; then run_root "Enabling time synchronisation service $TIME_UNIT" systemctl enable --now "$TIME_UNIT" || true; else FAILURES=$((FAILURES + 1)); log "WARNING: no supported time service is installed."; fi
fi

$DRY_RUN || sleep 2
verify
if [ "$FAILURES" -gt 0 ]; then exit 20; fi
log "Repair completed successfully. Actions performed: $ACTIONS"
exit 0
