#!/usr/bin/env bash
#
# linux_checklist.sh
#
# Debian / Linux Mint audit + hardening helper, based on the
# "Ultimate Linux Checklist" (CyberPatriot-style) document,
# plus an Ubuntu-specific checklist (section 24), FTP removal (25) and
# Mint Update Manager / full-upgrade steps (26).
#
# USAGE:
#   sudo ./linux_checklist.sh                 # audit only (safe, read-only)
#   sudo ./linux_checklist.sh --harden        # audit, then prompt before each
#                                              # change-making step
#   sudo ./linux_checklist.sh --harden --yes  # audit + apply changes with no
#                                              # per-step prompts (use with care)
#
# All output is also written to a timestamped log file in the current
# directory so you can review / backtrack what was done.
#
# NOTE: This script is written to be READ THE CODE BEFORE YOU RUN IT.
# Some "harden" actions are opinionated (e.g. SSH/password policy values,
# securetty edits) and back up every file they touch to *.bak-<timestamp>
# before changing it.

set -u

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

TS="$(date +%Y%m%d-%H%M%S)"
LOGFILE="./linux_checklist-${TS}.log"
HARDEN=0
ASSUME_YES=0

for arg in "$@"; do
  case "$arg" in
    --harden) HARDEN=1 ;;
    --yes|-y) ASSUME_YES=1 ;;
    --help|-h)
      echo "Usage: $0 [--harden] [--yes]"
      exit 0
      ;;
  esac
done

# Colors
C_RESET="\033[0m"; C_BOLD="\033[1m"; C_RED="\033[31m"
C_GREEN="\033[32m"; C_YELLOW="\033[33m"; C_CYAN="\033[36m"

log()   { echo -e "$*" | tee -a "$LOGFILE"; }
hdr()   { log "\n${C_BOLD}${C_CYAN}== $* ==${C_RESET}"; }
ok()    { log "${C_GREEN}[OK]${C_RESET}   $*"; }
warn()  { log "${C_YELLOW}[WARN]${C_RESET} $*"; }
bad()   { log "${C_RED}[FLAG]${C_RESET} $*"; }
info()  { log "${C_BOLD}[INFO]${C_RESET} $*"; }

backup_file() {
  # backup_file <path>
  local f="$1"
  if [ -f "$f" ]; then
    cp -p "$f" "${f}.bak-${TS}"
    info "Backed up $f -> ${f}.bak-${TS}"
  fi
}

confirm() {
  # confirm "question" -> 0 if yes
  local prompt="$1"
  if [ "$ASSUME_YES" -eq 1 ]; then
    return 0
  fi
  read -r -p "$(echo -e "${C_YELLOW}?${C_RESET} ${prompt} [y/N] ")" reply
  [[ "$reply" =~ ^[Yy]$ ]]
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root (sudo)." >&2
    exit 1
  fi
}

require_root

log "${C_BOLD}Linux Checklist Audit — started ${TS}${C_RESET}"
log "Mode: $([ "$HARDEN" -eq 1 ] && echo 'AUDIT + HARDEN' || echo 'AUDIT ONLY (read-only)')"
log "Log file: $LOGFILE"

# ---------------------------------------------------------------------------
# 1. Distro check (Debian vs Mint)
# ---------------------------------------------------------------------------
hdr "1. Distro Detection"

DISTRO_ID=""
DISTRO_NAME=""
DISTRO_VERSION=""

if [ -f /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  DISTRO_ID="${ID:-unknown}"
  DISTRO_NAME="${NAME:-unknown}"
  DISTRO_VERSION="${VERSION:-unknown}"
fi

case "$DISTRO_ID" in
  debian)
    ok "Detected Debian ($DISTRO_NAME $DISTRO_VERSION)"
    ;;
  linuxmint)
    ok "Detected Linux Mint ($DISTRO_NAME $DISTRO_VERSION)"
    ;;
  ubuntu)
    # Mint older releases sometimes report ID=ubuntu via ID_LIKE; note it
    warn "Detected Ubuntu-based system ($DISTRO_NAME $DISTRO_VERSION) — treating as Debian-family (apt-based)."
    ;;
  *)
    warn "Distro ID='$DISTRO_ID' NAME='$DISTRO_NAME' — not explicitly Debian or Mint. Script uses apt, so it should still work on Debian-family systems, but double check."
    ;;
esac

if ! command -v apt-get >/dev/null 2>&1; then
  bad "apt-get not found. This script targets Debian/Mint (apt-based) systems — aborting further apt-based checks."
  exit 1
fi

# ---------------------------------------------------------------------------
# 1b. System updates
# ---------------------------------------------------------------------------
hdr "1b. System Updates"

info "Checking for available updates (apt-get update)..."
apt-get update 2>&1 | tee -a "$LOGFILE"

UPGRADABLE="$(apt list --upgradable 2>/dev/null | grep -vc '^Listing')"
if [ "$UPGRADABLE" -gt 0 ]; then
  warn "$UPGRADABLE package(s) have updates available."
  apt list --upgradable 2>/dev/null | tee -a "$LOGFILE"
else
  ok "System is up to date."
fi

if [ "$HARDEN" -eq 1 ] && [ "$UPGRADABLE" -gt 0 ]; then
  if confirm "Run apt-get upgrade && apt-get dist-upgrade now? (can take a while, may prompt for config file choices)"; then
    apt-get upgrade -y 2>&1 | tee -a "$LOGFILE"
    apt-get dist-upgrade -y 2>&1 | tee -a "$LOGFILE"
    ok "Updates applied."
  fi
fi

# ---------------------------------------------------------------------------
# 2. System log files
# ---------------------------------------------------------------------------
hdr "2. System Logs"

info "Recent /var/log entries (top-level listing):"
ls -lat /var/log 2>/dev/null | head -n 20 | tee -a "$LOGFILE"

info "Last 20 auth log failures (if present):"
if [ -f /var/log/auth.log ]; then
  grep -i "fail" /var/log/auth.log 2>/dev/null | tail -n 20 | tee -a "$LOGFILE"
else
  warn "/var/log/auth.log not found (may be journald-only; try 'journalctl -u ssh')."
fi

info "Checking for shell history files under /home/*/ :"
found_hist=0
for f in /home/*/.bash_history /home/*/.sh_history /root/.bash_history; do
  if [ -f "$f" ]; then
    found_hist=1
    log "  Found: $f ($(wc -l < "$f" 2>/dev/null) lines) — review manually for suspicious commands."
  fi
done
[ "$found_hist" -eq 0 ] && ok "No shell history files found in home directories."

# ---------------------------------------------------------------------------
# 3. Installed software / common hacking tools
# ---------------------------------------------------------------------------
hdr "3. Installed Software Audit"

info "Package count: $(dpkg -l 2>/dev/null | grep -c '^ii')"

SUSPECT_TOOLS=(netcat netcat-traditional ncat nmap john hydra metasploit-framework wireshark tshark aircrack-ng nikto sqlmap hashcat medusa ophcrack kismet ettercap-common tcpdump)

log "Checking for commonly-flagged security/hacking tools:"
any_flagged=0
for pkg in "${SUSPECT_TOOLS[@]}"; do
  if dpkg -l 2>/dev/null | grep -qiE "^ii\s+${pkg}\b"; then
    bad "Installed: $pkg  (remove if not explicitly required: sudo apt-get purge -y $pkg)"
    any_flagged=1
  fi
done
[ "$any_flagged" -eq 0 ] && ok "None of the commonly-flagged tools were found installed."

if [ "$HARDEN" -eq 1 ]; then
  for pkg in "${SUSPECT_TOOLS[@]}"; do
    if dpkg -l 2>/dev/null | grep -qiE "^ii\s+${pkg}\b"; then
      if confirm "Purge package '$pkg'?"; then
        apt-get purge -y "$pkg" 2>&1 | tee -a "$LOGFILE"
      fi
    fi
  done
fi

info "For a full interactive review, install Synaptic: sudo apt-get install synaptic && sudo synaptic"

# --- Samba ---
info "Checking for Samba packages (often unneeded, exposes file-sharing services):"
if dpkg -l 2>/dev/null | grep -qiE '^ii\s+samba'; then
  bad "Samba is installed."
  dpkg -l 2>/dev/null | grep -iE '^ii\s+samba' | tee -a "$LOGFILE"
  if [ "$HARDEN" -eq 1 ] && confirm "Remove all samba* packages?"; then
    apt-get remove -y 'samba*' 2>&1 | tee -a "$LOGFILE"
    ok "Samba removed."
  fi
else
  ok "Samba is not installed."
fi

# --- Media / archive files in home dirs ---
hdr "3b. Media & Archive Files in Home Directories"

info "Media files (mp3/mp4) under /home — often against contest/policy rules, review manually:"
find /home/ -type f \( -name "*.mp3" -o -name "*.mp4" \) 2>/dev/null | tee -a "$LOGFILE"

info "Archive/package files under /home (tar.gz, tgz, zip, deb) — check for downloaded 'hacking tools':"
find /home/ -type f \( -name "*.tar.gz" -o -name "*.tgz" -o -name "*.zip" -o -name "*.deb" \) 2>/dev/null | tee -a "$LOGFILE"

warn "Review the file lists above and delete anything unauthorized manually (rm -f <path>) — this script does not auto-delete user files."

# ---------------------------------------------------------------------------
# 4. Cron / scheduled tasks
# ---------------------------------------------------------------------------
hdr "4. Scheduled Tasks (cron/anacron)"

for dir in /var/spool/cron/crontabs /var/spool/anacron /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
  if [ -d "$dir" ]; then
    log "Contents of $dir:"
    ls -la "$dir" 2>/dev/null | tee -a "$LOGFILE"
  fi
done

if [ -f /etc/crontab ]; then
  log "System crontab (/etc/crontab):"
  grep -vE '^\s*(#|$)' /etc/crontab | tee -a "$LOGFILE"
fi

info "Review each entry above manually — flag anything you or the team didn't put there."

# ---------------------------------------------------------------------------
# 5. Basic user policy
# ---------------------------------------------------------------------------
hdr "5. User Accounts & Policy"

info "Users with UID 0 (should only be root):"
UID0_USERS="$(awk -F: '($3 == 0){print $1}' /etc/passwd)"
log "$UID0_USERS"
if [ "$(echo "$UID0_USERS" | wc -l)" -gt 1 ]; then
  bad "More than one UID 0 account exists! Investigate immediately."
else
  ok "Only root has UID 0."
fi

info "Ownership of /etc/passwd and /etc/shadow:"
ls -l /etc/passwd /etc/shadow 2>/dev/null | tee -a "$LOGFILE"

info "All local users (from /etc/passwd):"
cut -d: -f1,3,4 /etc/passwd | tee -a "$LOGFILE"

info "Members of sudo/admin/wheel groups:"
for g in sudo admin wheel; do
  if getent group "$g" >/dev/null 2>&1; then
    log "  $g: $(getent group "$g" | cut -d: -f4)"
  fi
done

info "Checking for a 'guest' account:"
if getent passwd guest >/dev/null 2>&1; then
  bad "A 'guest' account exists. Consider removing it: sudo deluser --remove-home guest"
else
  ok "No 'guest' account found."
fi

info "Checking for accounts with empty passwords:"
if command -v getent >/dev/null 2>&1 && [ -r /etc/shadow ]; then
  EMPTY_PW="$(awk -F: '($2==""){print $1}' /etc/shadow)"
  if [ -n "$EMPTY_PW" ]; then
    bad "Accounts with EMPTY passwords: $EMPTY_PW"
  else
    ok "No accounts with empty passwords."
  fi
fi

# --- Password policy ---
hdr "5b. Password Policy"

if [ -f /etc/login.defs ]; then
  info "Current PASS_MAX_DAYS / PASS_MIN_DAYS / PASS_WARN_AGE:"
  grep -E '^PASS_(MAX_DAYS|MIN_DAYS|WARN_AGE)' /etc/login.defs | tee -a "$LOGFILE"
fi

if [ "$HARDEN" -eq 1 ]; then
  if confirm "Apply recommended password aging (MAX=90, MIN=0, WARN=7) in /etc/login.defs?"; then
    backup_file /etc/login.defs
    sed -i -E 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
    sed -i -E 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   0/' /etc/login.defs
    sed -i -E 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs
    ok "Updated /etc/login.defs"
  fi

  if confirm "Install libpam-cracklib and enforce password complexity + reuse history (5) / minlen 8?"; then
    apt-get install -y libpam-cracklib 2>&1 | tee -a "$LOGFILE"
    backup_file /etc/pam.d/common-password
    # Add remember=5 minlen=8 to the pam_unix.so line, if not already present
    if grep -q 'pam_unix.so' /etc/pam.d/common-password && ! grep -q 'remember=5' /etc/pam.d/common-password; then
      sed -i -E '/pam_unix\.so/ s/$/ remember=5 minlen=8/' /etc/pam.d/common-password
    fi
    # Add complexity requirements to pam_cracklib.so line, if present
    if grep -q 'pam_cracklib.so' /etc/pam.d/common-password && ! grep -q 'ucredit=-1' /etc/pam.d/common-password; then
      sed -i -E '/pam_cracklib\.so/ s/$/ ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' /etc/pam.d/common-password
    fi
    ok "Updated /etc/pam.d/common-password (backup saved)"
  fi

  if confirm "Add account lockout after 5 failed attempts (30 min unlock) to /etc/pam.d/common-auth?"; then
    # pam_tally2 was removed in newer releases (Ubuntu 22.04+/Mint 21+); using a missing
    # module in a 'required' line breaks ALL authentication (sudo, su, login).
    # So: detect which module actually exists, and never touch the file otherwise.
    find_pam_mod() { find /lib /lib64 /usr/lib -name "$1" 2>/dev/null | head -n 1; }
    TALLY_MOD="$(find_pam_mod pam_tally2.so)"
    FAIL_MOD="$(find_pam_mod pam_faillock.so)"

    if [ -n "$TALLY_MOD" ]; then
      backup_file /etc/pam.d/common-auth
      if ! grep -q 'pam_tally2.so' /etc/pam.d/common-auth; then
        # Insert BEFORE the first pam_unix.so line (not appended after pam_deny/pam_permit)
        sed -i '0,/^auth.*pam_unix\.so.*$/s//auth    required                        pam_tally2.so deny=5 onerr=fail unlock_time=1800\n&/' /etc/pam.d/common-auth
        ok "Added pam_tally2 lockout rule to /etc/pam.d/common-auth"
      else
        info "pam_tally2 already configured; skipping."
      fi
    elif [ -n "$FAIL_MOD" ]; then
      backup_file /etc/pam.d/common-auth
      backup_file /etc/pam.d/common-account
      if ! grep -q 'pam_faillock.so' /etc/pam.d/common-auth; then
        warn "KEEP A ROOT SHELL OPEN in another terminal (sudo -i) until you've tested a login!"
        # preauth before pam_unix, authfail after it, authsucc after that; account check in common-account
        sed -i '0,/^auth.*pam_unix\.so.*$/s//auth    required                        pam_faillock.so preauth\n&\nauth    [default=die]                   pam_faillock.so authfail\nauth    sufficient                      pam_faillock.so authsucc/' /etc/pam.d/common-auth
        grep -q 'pam_faillock.so' /etc/pam.d/common-account || echo "account required pam_faillock.so" >> /etc/pam.d/common-account
        if [ -f /etc/security/faillock.conf ]; then
          backup_file /etc/security/faillock.conf
          sed -i -E 's/^#?\s*deny\s*=.*/deny = 5/; s/^#?\s*unlock_time\s*=.*/unlock_time = 1800/' /etc/security/faillock.conf
        fi
        ok "Added pam_faillock lockout (deny=5, unlock 30 min). TEST sudo in a NEW terminal before closing your root shell."
        info "If it breaks: cp -p /etc/pam.d/common-auth.bak-${TS} /etc/pam.d/common-auth"
      else
        info "pam_faillock already configured; skipping."
      fi
    else
      warn "Neither pam_tally2.so nor pam_faillock.so found — skipping lockout (would break authentication)."
    fi
  fi
fi

# --- Root login ---
hdr "5c. Root Login"

if [ -f /etc/securetty ]; then
  info "/etc/securetty currently allows root login on:"
  grep -vE '^\s*(#|$)' /etc/securetty | tee -a "$LOGFILE"
else
  info "/etc/securetty not present on this system (PAM may govern console root login instead)."
fi

if [ "$HARDEN" -eq 1 ] && [ -f /etc/securetty ]; then
  if confirm "Clear /etc/securetty to disable root logins on all local ttys?"; then
    backup_file /etc/securetty
    : > /etc/securetty
    ok "/etc/securetty cleared."
  fi
fi

info "Root account lock status:"
passwd -S root 2>&1 | tee -a "$LOGFILE"

if [ "$HARDEN" -eq 1 ]; then
  if confirm "Lock the root account (passwd -l root) so it cannot log in with a password at all?"; then
    passwd -l root 2>&1 | tee -a "$LOGFILE"
    ok "Root account locked."
  elif confirm "Instead, set/reset the root account password now (interactive)?"; then
    passwd root
  fi
fi

# --- SSH root login ---
hdr "5d. SSH Root Login"

if [ -f /etc/ssh/sshd_config ]; then
  info "Current PermitRootLogin setting:"
  grep -i '^\s*PermitRootLogin' /etc/ssh/sshd_config | tee -a "$LOGFILE"
  if ! grep -qi '^\s*PermitRootLogin\s*no' /etc/ssh/sshd_config; then
    warn "SSH root login is not explicitly disabled."
  else
    ok "SSH root login is disabled."
  fi

  if [ "$HARDEN" -eq 1 ]; then
    if confirm "Set 'PermitRootLogin no' in /etc/ssh/sshd_config and restart sshd?"; then
      backup_file /etc/ssh/sshd_config
      if grep -qF 'PermitRootLogin' /etc/ssh/sshd_config; then
        sed -i 's/^.*PermitRootLogin.*$/PermitRootLogin no/' /etc/ssh/sshd_config
      else
        echo 'PermitRootLogin no' >> /etc/ssh/sshd_config
      fi
      systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
      ok "PermitRootLogin set to no and sshd restarted."
    fi
  fi
else
  info "/etc/ssh/sshd_config not found — sshd not installed."
fi

# ---------------------------------------------------------------------------
# 6. Firewall (ufw)
# ---------------------------------------------------------------------------
hdr "6. Firewall (UFW)"

if ! command -v ufw >/dev/null 2>&1; then
  warn "ufw not installed."
  if [ "$HARDEN" -eq 1 ] && confirm "Install ufw?"; then
    apt-get install -y ufw 2>&1 | tee -a "$LOGFILE"
  fi
fi

if command -v ufw >/dev/null 2>&1; then
  info "Current ufw status:"
  ufw status verbose | tee -a "$LOGFILE"
  if [ "$HARDEN" -eq 1 ]; then
    if confirm "Enable ufw now?"; then
      ufw --force enable 2>&1 | tee -a "$LOGFILE"
      ufw status verbose | tee -a "$LOGFILE"
    fi
  fi
  info "Remember to allow only the services you actually need, e.g.: sudo ufw allow 443/tcp"
fi

# ---------------------------------------------------------------------------
# 7. Anti-malware / rootkits
# ---------------------------------------------------------------------------
hdr "7. Rootkit / Malware Scan"

for tool in rkhunter chkrootkit; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    warn "$tool not installed."
    if [ "$HARDEN" -eq 1 ] && confirm "Install $tool?"; then
      apt-get install -y "$tool" 2>&1 | tee -a "$LOGFILE"
    fi
  fi
done

if command -v chkrootkit >/dev/null 2>&1; then
  info "Running chkrootkit (this can take a minute)..."
  chkrootkit 2>&1 | tee -a "$LOGFILE" | tail -n 40
fi

if command -v rkhunter >/dev/null 2>&1; then
  info "Running rkhunter --check --sk (non-interactive)..."
  rkhunter --update 2>&1 | tee -a "$LOGFILE"
  rkhunter --check --sk 2>&1 | tee -a "$LOGFILE" | tail -n 40
fi

warn "Review chkrootkit/rkhunter output above manually — some hits are false positives, but every one should be investigated."

# ---------------------------------------------------------------------------
# 8. Auditing
# ---------------------------------------------------------------------------
hdr "8. Auditd"

if ! command -v auditctl >/dev/null 2>&1; then
  warn "auditd not installed."
  if [ "$HARDEN" -eq 1 ] && confirm "Install and enable auditd?"; then
    apt-get install -y auditd audispd-plugins 2>&1 | tee -a "$LOGFILE"
    systemctl enable --now auditd 2>&1 | tee -a "$LOGFILE"
    auditctl -e 1 2>&1 | tee -a "$LOGFILE"
  fi
else
  ok "auditd is installed."
  auditctl -s 2>&1 | tee -a "$LOGFILE"
fi

info "Auditd config lives at /etc/audit/auditd.conf (path may differ slightly from the checklist's /etc/audit.d/)."

info "SSH failed login attempts:"
if [ -f /var/log/auth.log ]; then
  grep -E "sshd.*Failed" /var/log/auth.log 2>/dev/null | tail -n 20 | tee -a "$LOGFILE"
elif command -v journalctl >/dev/null 2>&1; then
  journalctl -u ssh --no-pager 2>/dev/null | grep -i "Failed" | tail -n 20 | tee -a "$LOGFILE"
fi

# ---------------------------------------------------------------------------
# 8d. /etc/hosts
# ---------------------------------------------------------------------------
hdr "8d. /etc/hosts"

info "Current /etc/hosts:"
cat /etc/hosts | tee -a "$LOGFILE"
warn "Compare against the expected baseline entries manually — flag anything unexpected (e.g. redirected domains)."

# ---------------------------------------------------------------------------
# 9. Services
# ---------------------------------------------------------------------------
hdr "9. Running Services"

if command -v systemctl >/dev/null 2>&1; then
  info "Enabled services (systemd):"
  systemctl list-unit-files --type=service --state=enabled 2>/dev/null | tee -a "$LOGFILE"
else
  info "Service status (SysV):"
  service --status-all 2>&1 | tee -a "$LOGFILE"
fi
info "To stop/disable a service: sudo systemctl stop <svc> && sudo systemctl disable <svc>"

# ---------------------------------------------------------------------------
# 10. Ports
# ---------------------------------------------------------------------------
hdr "10. Listening Ports"

info "Active listening ports:"
if command -v ss >/dev/null 2>&1; then
  ss -tulnp 2>/dev/null | tee -a "$LOGFILE"
else
  netstat -tulnp 2>/dev/null | tee -a "$LOGFILE"
fi

RISKY_PORTS="20 21 23 135 411 412"
info "Checking for commonly risky ports ($RISKY_PORTS):"
for p in $RISKY_PORTS; do
  if ss -tuln 2>/dev/null | grep -q ":$p\b"; then
    bad "Port $p is open/listening — verify this is required (ftp/telnet/RDP/peer-to-peer are commonly disallowed)."
  fi
done
info "To find what's using a port: sudo lsof -i :<port>   (then stop/disable the owning service)"

# ---------------------------------------------------------------------------
# 11. Directory permissions
# ---------------------------------------------------------------------------
hdr "11. Key Directory Permissions"

check_perm() {
  local path="$1" expected="$2"
  if [ -e "$path" ]; then
    local actual
    actual="$(stat -c '%a' "$path")"
    log "  $path -> $actual (expected roughly: $expected)"
  fi
}

check_perm /tmp 1777
check_perm /var/tmp 1777
[ -d /boot/grub ] && check_perm /boot/grub 700
[ -d /boot/grub2 ] && check_perm /boot/grub2 700

info "/etc/shadow and /etc/gshadow permissions (should be 640 or stricter, owned root):"
ls -l /etc/shadow /etc/gshadow 2>/dev/null | tee -a "$LOGFILE"
if [ "$HARDEN" -eq 1 ]; then
  if confirm "Force /etc/shadow and /etc/gshadow to root:shadow 640?"; then
    chown root:shadow /etc/shadow /etc/gshadow 2>/dev/null
    chmod 640 /etc/shadow /etc/gshadow 2>/dev/null
    ok "Permissions enforced."
  fi
fi

# ---------------------------------------------------------------------------
# 12. SUID / SGID binaries
# ---------------------------------------------------------------------------
hdr "12. SUID / SGID Binaries"

info "Files with the SUID or SGID bit set (review for anything unexpected/non-standard):"
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | tee -a "$LOGFILE"
warn "Compare this list against a known-good baseline for your distro. Anything unfamiliar (esp. in /tmp, /home, /var) is a strong indicator of compromise."

# ---------------------------------------------------------------------------
# 13. World-Writable Files & Unowned Files
# ---------------------------------------------------------------------------
hdr "13. World-Writable & Unowned Files"

info "World-writable files outside /tmp,/var/tmp,/dev (excluding symlinks):"
find / -xdev -type f -perm -0002 ! -path "/tmp/*" ! -path "/var/tmp/*" ! -path "/dev/*" 2>/dev/null | tee -a "$LOGFILE"

info "Files with no owner or no group (often left by removed/rogue accounts):"
find / -xdev \( -nouser -o -nogroup \) 2>/dev/null | tee -a "$LOGFILE"

# ---------------------------------------------------------------------------
# 14. Remote Trust Files (.rhosts / hosts.equiv)
# ---------------------------------------------------------------------------
hdr "14. Remote Trust Files (rsh/rlogin-style)"

info "Checking for .rhosts files and /etc/hosts.equiv (these bypass password auth — should not exist):"
FOUND_RHOSTS="$(find /root /home -name '.rhosts' 2>/dev/null)"
[ -n "$FOUND_RHOSTS" ] && bad "Found: $FOUND_RHOSTS" || ok "No .rhosts files found."
if [ -f /etc/hosts.equiv ]; then
  bad "/etc/hosts.equiv exists — this is a legacy trust-auth bypass."
  if [ "$HARDEN" -eq 1 ] && confirm "Delete /etc/hosts.equiv?"; then
    backup_file /etc/hosts.equiv
    rm -f /etc/hosts.equiv
    ok "Removed."
  fi
else
  ok "/etc/hosts.equiv not present."
fi
if [ "$HARDEN" -eq 1 ] && [ -n "$FOUND_RHOSTS" ]; then
  if confirm "Delete all found .rhosts files?"; then
    find /root /home -name '.rhosts' -delete 2>/dev/null
    ok "Removed."
  fi
fi

# ---------------------------------------------------------------------------
# 15. Kernel Network Hardening (sysctl)
# ---------------------------------------------------------------------------
hdr "15. Kernel Network Hardening (sysctl)"

declare -A SYSCTL_CHECKS=(
  ["net.ipv4.ip_forward"]="0"
  ["net.ipv4.conf.all.send_redirects"]="0"
  ["net.ipv4.conf.all.accept_redirects"]="0"
  ["net.ipv4.conf.all.accept_source_route"]="0"
  ["net.ipv4.conf.all.log_martians"]="1"
  ["net.ipv4.icmp_echo_ignore_broadcasts"]="1"
  ["net.ipv4.tcp_syncookies"]="1"
  ["net.ipv4.conf.all.rp_filter"]="1"
)

for key in "${!SYSCTL_CHECKS[@]}"; do
  cur="$(sysctl -n "$key" 2>/dev/null || echo "unknown")"
  want="${SYSCTL_CHECKS[$key]}"
  if [ "$cur" = "$want" ]; then
    ok "$key = $cur"
  else
    bad "$key = $cur (recommended: $want)"
  fi
done

if [ "$HARDEN" -eq 1 ]; then
  if confirm "Write recommended values to /etc/sysctl.d/99-hardening.conf and apply now?"; then
    HFILE=/etc/sysctl.d/99-hardening.conf
    backup_file "$HFILE"
    {
      echo "# Added by linux_checklist.sh on $TS"
      for key in "${!SYSCTL_CHECKS[@]}"; do
        echo "$key = ${SYSCTL_CHECKS[$key]}"
      done
    } > "$HFILE"
    sysctl -p "$HFILE" 2>&1 | tee -a "$LOGFILE"
    ok "Applied and persisted in $HFILE"
  fi
fi

# ---------------------------------------------------------------------------
# 16. Additional SSH Hardening
# ---------------------------------------------------------------------------
hdr "16. Additional SSH Hardening"

if [ -f /etc/ssh/sshd_config ]; then
  info "Checking PermitEmptyPasswords, X11Forwarding, MaxAuthTries, Protocol:"
  grep -iE '^\s*(PermitEmptyPasswords|X11Forwarding|MaxAuthTries|Protocol)' /etc/ssh/sshd_config | tee -a "$LOGFILE"

  if [ "$HARDEN" -eq 1 ]; then
    if confirm "Apply hardened SSH settings (PermitEmptyPasswords no, X11Forwarding no, MaxAuthTries 3) and restart sshd?"; then
      backup_file /etc/ssh/sshd_config
      for pair in "PermitEmptyPasswords no" "X11Forwarding no" "MaxAuthTries 3"; do
        key="${pair%% *}"
        if grep -qiE "^\s*${key}\b" /etc/ssh/sshd_config; then
          sed -i -E "s/^\s*${key}\b.*/${pair}/I" /etc/ssh/sshd_config
        else
          echo "$pair" >> /etc/ssh/sshd_config
        fi
      done
      systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
      ok "SSH hardened settings applied."
    fi
  fi
else
  info "sshd not installed — skipping."
fi

# ---------------------------------------------------------------------------
# 17. Sudoers Audit
# ---------------------------------------------------------------------------
hdr "17. Sudoers Audit"

info "/etc/sudoers (comments/blank lines stripped):"
grep -vE '^\s*(#|$)' /etc/sudoers 2>/dev/null | tee -a "$LOGFILE"

if [ -d /etc/sudoers.d ]; then
  info "Files in /etc/sudoers.d/:"
  ls -la /etc/sudoers.d/ | tee -a "$LOGFILE"
  for f in /etc/sudoers.d/*; do
    [ -f "$f" ] && [ "$(basename "$f")" != "README" ] && grep -vE '^\s*(#|$)' "$f" 2>/dev/null | tee -a "$LOGFILE"
  done
fi

if command -v visudo >/dev/null 2>&1; then
  info "Syntax check (visudo -c):"
  visudo -c 2>&1 | tee -a "$LOGFILE"
fi

warn "Any user with NOPASSWD or blanket ALL=(ALL) ALL access should be justified — flag anything unexpected."

# ---------------------------------------------------------------------------
# 18. cron.allow / at.allow restriction
# ---------------------------------------------------------------------------
hdr "18. Cron/At Access Restriction"

for pair in "cron:/etc/cron.allow:/etc/cron.deny" "at:/etc/at.allow:/etc/at.deny"; do
  name="${pair%%:*}"; rest="${pair#*:}"; allow="${rest%%:*}"; deny="${rest#*:}"
  if [ -f "$allow" ]; then
    ok "$allow exists — access restricted to listed users: $(cat "$allow" | tr '\n' ' ')"
  else
    warn "$allow does not exist for $name — by default this may allow all users. Consider creating it with just 'root'."
    if [ "$HARDEN" -eq 1 ] && confirm "Create $allow containing only 'root'?"; then
      echo root > "$allow"
      chmod 600 "$allow"
      ok "Created $allow"
    fi
  fi
  [ -f "$deny" ] && info "$deny also exists: $(cat "$deny" | tr '\n' ' ')"
done

# ---------------------------------------------------------------------------
# 19. Legal Warning Banners
# ---------------------------------------------------------------------------
hdr "19. Legal Warning Banners (/etc/issue, /etc/issue.net)"

info "Current /etc/issue:"
cat /etc/issue 2>/dev/null | tee -a "$LOGFILE"
info "Current /etc/issue.net:"
cat /etc/issue.net 2>/dev/null | tee -a "$LOGFILE"

if [ "$HARDEN" -eq 1 ]; then
  if confirm "Set a generic 'Authorized use only' warning banner in /etc/issue and /etc/issue.net?"; then
    backup_file /etc/issue
    backup_file /etc/issue.net
    BANNER="Authorized access only. By accessing this system you consent to monitoring."
    echo "$BANNER" > /etc/issue
    echo "$BANNER" > /etc/issue.net
    ok "Banners set."
  fi
fi

# ---------------------------------------------------------------------------
# 20. Antivirus (ClamAV)
# ---------------------------------------------------------------------------
hdr "20. Antivirus (ClamAV)"

if ! command -v clamscan >/dev/null 2>&1; then
  warn "ClamAV not installed."
  if [ "$HARDEN" -eq 1 ] && confirm "Install ClamAV and update virus definitions?"; then
    apt-get install -y clamav clamav-daemon 2>&1 | tee -a "$LOGFILE"
    systemctl stop clamav-freshclam 2>/dev/null
    freshclam 2>&1 | tee -a "$LOGFILE"
    systemctl start clamav-freshclam 2>/dev/null
    ok "ClamAV installed and definitions updated. Run a full scan separately (it can take a long time):"
    info "  sudo clamscan -r --bell -i /home /etc /var/www 2>/dev/null | tee clamscan-results.log"
  fi
else
  ok "ClamAV is installed."
  info "Run a scan manually with: sudo clamscan -r --bell -i / 2>/dev/null (can take a long time)"
fi

# ---------------------------------------------------------------------------
# 21. AppArmor
# ---------------------------------------------------------------------------
hdr "21. AppArmor"

if command -v aa-status >/dev/null 2>&1; then
  aa-status 2>&1 | tee -a "$LOGFILE"
else
  warn "AppArmor tools not installed."
  if [ "$HARDEN" -eq 1 ] && confirm "Install apparmor + apparmor-utils and enable it?"; then
    apt-get install -y apparmor apparmor-utils 2>&1 | tee -a "$LOGFILE"
    systemctl enable --now apparmor 2>&1 | tee -a "$LOGFILE"
    ok "AppArmor installed and enabled."
  fi
fi

# ---------------------------------------------------------------------------
# 22. Time Sync (NTP)
# ---------------------------------------------------------------------------
hdr "22. Time Synchronization"

if command -v timedatectl >/dev/null 2>&1; then
  timedatectl 2>&1 | tee -a "$LOGFILE"
  if timedatectl 2>/dev/null | grep -qi "NTP service: active\|synchronized: yes"; then
    ok "Time sync appears active."
  else
    warn "Time sync does not appear active."
    if [ "$HARDEN" -eq 1 ] && confirm "Enable systemd-timesyncd?"; then
      timedatectl set-ntp true 2>&1 | tee -a "$LOGFILE"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 23. Automatic Security Updates
# ---------------------------------------------------------------------------
hdr "23. Automatic Security Updates"

if dpkg -l 2>/dev/null | grep -qi '^ii\s\+unattended-upgrades'; then
  ok "unattended-upgrades is installed."
else
  warn "unattended-upgrades not installed — system won't auto-apply security patches."
  if [ "$HARDEN" -eq 1 ] && confirm "Install and enable unattended-upgrades?"; then
    apt-get install -y unattended-upgrades 2>&1 | tee -a "$LOGFILE"
    dpkg-reconfigure -plow unattended-upgrades 2>&1 | tee -a "$LOGFILE"
    ok "unattended-upgrades installed."
  fi
fi

# ---------------------------------------------------------------------------
# 24. Ubuntu Checklist
# ---------------------------------------------------------------------------
hdr "24. Ubuntu Checklist"

if [ "${DISTRO_ID:-}" != "ubuntu" ] && ! echo "${ID_LIKE:-}" | grep -qi ubuntu; then
  info "Not an Ubuntu system — skipping Ubuntu-specific checklist."
else
  # --- FIRST: update/upgrade (already handled in 1b; reminder only) ---
  info "FIRST: sudo apt update && sudo apt upgrade   (if needed: sudo apt dist-upgrade)"
  info "       Covered by section 1b above. (Note: the command is dist-upgrade, not dist-update.)"

  # --- Forensics ---
  info "Forensics: Solve BOTH forensics questions first, in case you delete or change something you need."

  # --- Ubuntu Software Updates ---
  hdr "24a. Ubuntu Software Updates"
  info "GUI: System settings -> Software & Updates -> Updates tab:"
  info "  - Check important security updates and recommended updates."
  info "  - Automatically check for updates: Daily."
  info "  - When there are security updates: Download and Install Automatically."
  info "  - Also open 'Software Updater' from the application launcher and check for updates."

  AUTO_CONF="/etc/apt/apt.conf.d/20auto-upgrades"
  info "Current $AUTO_CONF:"
  if [ -f "$AUTO_CONF" ]; then
    tee -a "$LOGFILE" < "$AUTO_CONF"
  else
    warn "$AUTO_CONF not found."
  fi

  if [ "$HARDEN" -eq 1 ] && confirm "Set apt to check daily and auto download/install security updates ($AUTO_CONF)?"; then
    apt-get install -y unattended-upgrades 2>&1 | tee -a "$LOGFILE"
    backup_file "$AUTO_CONF"
    cat > "$AUTO_CONF" <<'AUTOEOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
AUTOEOF
    ok "Wrote $AUTO_CONF (daily check, download + install security updates)."
  fi

  # --- Program Updates ---
  hdr "24b. Program Updates"
  info "Make sure every application listed in the README is up to date."
  info "  Use Ubuntu Software and/or the terminal: sudo apt install <application>"

  # --- Firefox ---
  hdr "24c. Firefox Settings (manual — cannot be safely automated)"
  info "General: enable automatic updates; untick 'Recommend extensions as you browse' and"
  info "         'Recommend features as you browse'."
  info "Home: untick Sponsored shortcuts, Recommended by Pocket, and Snippets."
  info "Search: untick search suggestions; set DuckDuckGo as the default search engine."
  info "Privacy & Security:"
  info "  - Enhanced Tracking Protection: Strict"
  info "  - Delete cookies and site data when Firefox is closed"
  info "  - Untick everything under Address Bar suggestions"
  info "  - Block pop-up windows"
  info "  - Warn when websites try to install add-ons"
  info "  - Block dangerous and deceptive content / downloads"
  info "  - Warn about unwanted and uncommon software"
  info "  - HTTPS-Only Mode: enable in all windows"
  info "  - DNS over HTTPS: Max Protection"

  # --- Firewall ---
  hdr "24d. Firewall Defaults (ufw)"
  if ! command -v ufw >/dev/null 2>&1; then
    warn "ufw not installed (see section 6)."
  else
    info "Checklist: sudo ufw enable; sudo ufw default reject incoming; sudo ufw default allow outgoing"
    if [ "$HARDEN" -eq 1 ] && confirm "Set ufw defaults (reject incoming, allow outgoing) and enable ufw?"; then
      ufw --force enable 2>&1 | tee -a "$LOGFILE"
      ufw default reject incoming 2>&1 | tee -a "$LOGFILE"
      ufw default allow outgoing 2>&1 | tee -a "$LOGFILE"
      ufw status verbose | tee -a "$LOGFILE"
    fi
    info "Allow needed applications with: sudo ufw allow <application>"
  fi

  # --- Password policy ---
  hdr "24e. Password Policy (reminder)"
  info "Checklist: cd /etc/pam.d -> sudo apt install libpam-cracklib -> sudo nano common-password"
  info "Section 5b already automates this. On newer Ubuntu releases libpam-cracklib may be"
  info "replaced by libpam-pwquality (pam_pwquality.so) — check which line your common-password uses."

  # --- MP3/MP4 files (system-wide) ---
  hdr "24f. MP3/MP4 Files (system-wide)"
  info "Locating .mp3 and .mp4 files (updating locate database first)..."
  if command -v updatedb >/dev/null 2>&1; then
    updatedb 2>/dev/null
  fi
  if command -v locate >/dev/null 2>&1; then
    locate -i '*.mp3' '*.mp4' 2>/dev/null | tee -a "$LOGFILE"
  else
    find / -xdev -type f \( -iname '*.mp3' -o -iname '*.mp4' \) \
      -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | tee -a "$LOGFILE"
  fi
  warn "Delete any unauthorized media files manually (rm -f <path>) — this script does not auto-delete."
fi

# ---------------------------------------------------------------------------
# 25. FTP Service (disable or remove)
# ---------------------------------------------------------------------------
hdr "25. FTP Service"

FTP_PKGS="vsftpd proftpd-basic proftpd pure-ftpd pure-ftpd-common"
FTP_FOUND=""
for pkg in $FTP_PKGS; do
  if dpkg -l "$pkg" 2>/dev/null | grep -q '^ii'; then
    FTP_FOUND="$FTP_FOUND $pkg"
  fi
done

if [ -z "$FTP_FOUND" ]; then
  ok "No common FTP server packages (vsftpd, proftpd, pure-ftpd) are installed."
else
  bad "FTP server package(s) installed:$FTP_FOUND"
  for svc in vsftpd proftpd pure-ftpd; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
      warn "$svc service is RUNNING."
    fi
  done
  info "Checklist: sudo systemctl stop vsftpd && sudo apt purge vsftpd   (answer y at the prompt)"
  if [ "$HARDEN" -eq 1 ] && confirm "Stop and purge FTP server package(s):$FTP_FOUND ?"; then
    for pkg in $FTP_FOUND; do
      svc="$pkg"
      case "$pkg" in proftpd-basic) svc="proftpd" ;; pure-ftpd-common) svc="pure-ftpd" ;; esac
      systemctl stop "$svc" 2>&1 | tee -a "$LOGFILE"
      systemctl disable "$svc" 2>&1 | tee -a "$LOGFILE"
    done
    # shellcheck disable=SC2086
    apt-get purge -y $FTP_FOUND 2>&1 | tee -a "$LOGFILE"
    ok "FTP server package(s) purged."
  fi
fi

# ---------------------------------------------------------------------------
# 26. Update Manager (Linux Mint) / Install Security Updates
# ---------------------------------------------------------------------------
hdr "26. Automatic Updates & Install Security Updates"

info "Refresh the update list automatically (Mint Update Manager):"
info "  Menu -> Control Center -> Update Manager -> Edit -> Preferences -> Automation tab"
info "  -> enable 'Apply updates automatically'. (Use your account password from the README if prompted.)"

if command -v mintupdate-automation >/dev/null 2>&1; then
  info "mintupdate-automation is available."
  if [ "$HARDEN" -eq 1 ] && confirm "Enable Update Manager 'Apply updates automatically' (mintupdate-automation upgrade enable)?"; then
    if mintupdate-automation upgrade enable 2>&1 | tee -a "$LOGFILE"; then
      ok "Requested: Apply updates automatically. Verify in Update Manager -> Preferences -> Automation."
    else
      warn "mintupdate-automation failed — set it manually via the GUI steps above."
    fi
  fi
else
  info "mintupdate-automation not found (not Mint, or Update Manager not installed) — apt auto-updates are handled in sections 23/24."
fi

info "Install updates (important security updates):"
info "  GUI: Update Manager -> Refresh -> Install Updates   (auto-apply must be set in Preferences first)"
info "  CLI: sudo apt update && sudo apt full-upgrade -y"
if [ "$HARDEN" -eq 1 ] && confirm "Run apt-get update && apt-get full-upgrade -y now?"; then
  apt-get update 2>&1 | tee -a "$LOGFILE"
  apt-get full-upgrade -y 2>&1 | tee -a "$LOGFILE"
  ok "apt full-upgrade complete."
fi

# ---------------------------------------------------------------------------
# Extra: disable automount
# ---------------------------------------------------------------------------
hdr "Extra: USB Automount"

if command -v gsettings >/dev/null 2>&1; then
  info "Current automount settings (if a GUI session is active, run as the logged-in user):"
  su - "$(logname 2>/dev/null || echo "$SUDO_USER")" -c "gsettings get org.gnome.desktop.media-handling automount" 2>/dev/null | tee -a "$LOGFILE"
fi

if [ "$HARDEN" -eq 1 ] && command -v gsettings >/dev/null 2>&1; then
  target_user="$(logname 2>/dev/null || echo "${SUDO_USER:-}")"
  if [ -n "$target_user" ] && confirm "Disable automount/autorun for user '$target_user' via gsettings?"; then
    su - "$target_user" -c "gsettings set org.gnome.desktop.media-handling automount false" 2>&1 | tee -a "$LOGFILE"
    su - "$target_user" -c "gsettings set org.gnome.desktop.media-handling automount-open false" 2>&1 | tee -a "$LOGFILE"
    su - "$target_user" -c "gsettings set org.gnome.desktop.media-handling autorun-never true" 2>&1 | tee -a "$LOGFILE"
    ok "Automount disabled for $target_user."
  fi
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
hdr "Audit Complete"
log "Full log saved to: $LOGFILE"
log "Review every ${C_RED}[FLAG]${C_RESET} and ${C_YELLOW}[WARN]${C_RESET} line above."
if [ "$HARDEN" -eq 0 ]; then
  log "This was an audit-only run. Re-run with --harden to be prompted for actual changes."
fi
