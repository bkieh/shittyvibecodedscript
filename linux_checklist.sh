#!/usr/bin/env bash
#
# linux_checklist.sh
#
# Debian / Linux Mint audit + hardening helper, based on the
# "Ultimate Linux Checklist" (CyberPatriot-style) document,
# plus an Ubuntu-specific checklist (section 24), FTP removal (25) and
# Mint Update Manager / full-upgrade steps (26), an interactive user
# review/manager (5a), and a final re-verification pass.
#
# USAGE:
#   sudo ./linux_checklist.sh                 # audit only (safe, read-only)
#   sudo ./linux_checklist.sh --harden        # audit, then prompt before each
#                                              # change-making step
#   sudo ./linux_checklist.sh --harden --yes  # audit + apply changes with no
#                                              # per-step prompts (use with care;
#                                              # account deletions/demotions still ask)
#
# Before every y/N prompt the script prints a plain-English list of exactly
# what it is about to do (and why), so you can decide before answering.
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

explain() {
  # explain <step> [step...]   Prints a plain-English list of what is about to happen.
  # A step beginning with "WHY:" is printed as the reason / a warning, not numbered.
  local i=1 st
  log "${C_CYAN}  What this will do:${C_RESET}"
  for st in "$@"; do
    case "$st" in
      WHY:*) log "  ${C_BOLD}Why / note:${C_RESET} ${st#WHY:}" ;;
      *)     log "    $i. $st"; i=$((i+1)) ;;
    esac
  done
}

confirm() {
  # confirm "question" [step ...] -> 0 if yes. Extra args are shown as numbered steps first.
  local prompt="$1"; shift
  if [ "$#" -gt 0 ]; then explain "$@"; fi
  if [ "$ASSUME_YES" -eq 1 ]; then
    return 0
  fi
  read -r -p "$(echo -e "${C_YELLOW}?${C_RESET} ${prompt} [y/N] ")" reply
  [[ "$reply" =~ ^[Yy]$ ]]
}

confirm_strict() {
  # Like confirm(), but ALWAYS asks — even with --yes. Used for destructive account changes.
  local prompt="$1" reply; shift
  if [ "$#" -gt 0 ]; then explain "$@"; fi
  read -r -p "$(echo -e "${C_RED}?${C_RESET} ${prompt} [y/N] ")" reply
  [[ "$reply" =~ ^[Yy]$ ]]
}

# gsettings must run inside the logged-in user's desktop session. Under sudo there is no
# D-Bus session, which causes "dconf-WARNING: Cannot autolaunch D-Bus without X11 $DISPLAY"
# and the change is silently NOT saved. So point it at the user's existing session bus.
user_gsettings() {
  local u="$1"; shift
  local uid; uid="$(id -u "$u" 2>/dev/null)" || return 1
  [ -S "/run/user/$uid/bus" ] || return 1
  sudo -u "$u" env "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$uid/bus" \
    XDG_RUNTIME_DIR="/run/user/$uid" gsettings "$@"
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
  if confirm "Run apt-get upgrade && apt-get dist-upgrade now? (can take a while, may prompt for config file choices)" \
        "Download and install newer versions of every installed package (apt-get upgrade)" \
        "Also apply updates that add or remove packages, such as new kernels (apt-get dist-upgrade)" \
        "This can take several minutes. If it asks about a config file, keeping the current version is usually safe" \
        "WHY:Outdated software has known security holes, and updating is a commonly scored item"; then
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

SUSPECT_TOOLS=(netcat ncat nmap zenmap john hydra metasploit-framework wireshark tshark aircrack-ng nikto sqlmap hashcat medusa ophcrack kismet ettercap tcpdump dsniff fcrackzip)

# installed_matches <tool> [include-removed-with-config]
# Prints EVERY installed package whose name starts with <tool> (exactly like
# `apt purge <tool>*`, e.g. netcat -> netcat-openbsd, nmap -> nmapsi4). The old check purged only the exact name, so
# netcat-openbsd, wireshark-common, wireshark-qt, etc. were left behind.
installed_matches() {
  local tool="$1" want_rc="${2:-0}"
  dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' 2>/dev/null | awk -v t="$tool" -v rc="$want_rc" '
    { st=$1; n=$2; sub(/:.*/,"",n)
      if ((st=="ii" || st=="hi" || (rc==1 && st=="rc")) && index(n, t)==1) print n }' | sort -u
}

log "Checking for commonly-flagged security/hacking tools (matches the name AND variants like netcat-openbsd, wireshark-qt):"
any_flagged=0
for tool in "${SUSPECT_TOOLS[@]}"; do
  FOUND_PKGS="$(installed_matches "$tool" | tr '\n' ' ')"
  if [ -n "${FOUND_PKGS// /}" ]; then
    bad "Installed: $FOUND_PKGS (remove if not explicitly required: sudo apt-get purge -y $FOUND_PKGS)"
    any_flagged=1
  fi
done

# Snap / Flatpak copies are not seen by dpkg
if command -v snap >/dev/null 2>&1; then
  for tool in "${SUSPECT_TOOLS[@]}"; do
    if snap list 2>/dev/null | awk 'NR>1{print $1}' | grep -qx "$tool"; then
      bad "Snap installed: $tool (remove: sudo snap remove --purge $tool)"; any_flagged=1
    fi
  done
fi
if command -v flatpak >/dev/null 2>&1; then
  for tool in "${SUSPECT_TOOLS[@]}"; do
    if flatpak list --columns=application 2>/dev/null | grep -qi "$tool"; then
      bad "Flatpak installed matching: $tool (remove: flatpak uninstall <app-id>)"; any_flagged=1
    fi
  done
fi
[ "$any_flagged" -eq 0 ] && ok "None of the commonly-flagged tools were found installed."

if [ "$HARDEN" -eq 1 ]; then
  for tool in "${SUSPECT_TOOLS[@]}"; do
    PURGE_PKGS="$(installed_matches "$tool" 1 | tr '\n' ' ')"
    [ -z "${PURGE_PKGS// /}" ] && continue
    if confirm "Purge '$tool' and all its related packages?" \
        "Completely remove these packages and their config files (like apt purge ${tool}*): $PURGE_PKGS" \
        "Afterwards, leftover libraries are cleaned by the autoremove step in section 26" \
        "WHY:This is a tool often used for hacking or network snooping. Check the README first: if it is listed as a REQUIRED program, answer n"; then
      # shellcheck disable=SC2086
      apt-get purge -y $PURGE_PKGS 2>&1 | tee -a "$LOGFILE"
      LEFT="$(installed_matches "$tool" | tr '\n' ' ')"
      if [ -z "${LEFT// /}" ]; then ok "'$tool' packages removed."; else bad "Still installed after purge: $LEFT (see log)"; fi
    fi
  done
fi

info "For a full interactive review, install Synaptic: sudo apt-get install synaptic && sudo synaptic"

# --- Samba ---
info "Checking for Samba packages (often unneeded, exposes file-sharing services):"
if dpkg -l 2>/dev/null | grep -qiE '^ii\s+samba'; then
  bad "Samba is installed."
  dpkg -l 2>/dev/null | grep -iE '^ii\s+samba' | tee -a "$LOGFILE"
  if [ "$HARDEN" -eq 1 ] && confirm "Remove all samba* packages?" \
        "Remove every Samba package (the Windows file-sharing service)" \
        "That stops the service and closes its network ports" \
        "WHY:Unneeded services add attack surface. Answer n if the README says Samba/file sharing is required"; then
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

# ---------------------------------------------------------------------------
# 5a. User Accounts Review & Management
#
# Scans every real (human) account, shows its status (admin or standard) and password
# info, then — with --harden — walks through each user and lets you change their
# status, change their password, lock or delete them, and create new users.
# Deleting a user or removing admin rights always asks, even with --yes.
#
# NOTE: Linux only stores a one-way HASH of each password, so real passwords can never
# be displayed. The table shows whether a password is set, how it is stored, and when it
# was last changed instead.
# ---------------------------------------------------------------------------
hdr "5a. User Accounts Review & Management"

INVOKER="$(logname 2>/dev/null || true)"

list_human_users() {
  local min max
  min="$(awk '/^UID_MIN/{print $2}' /etc/login.defs 2>/dev/null)"; min="${min:-1000}"
  max="$(awk '/^UID_MAX/{print $2}' /etc/login.defs 2>/dev/null)"; max="${max:-60000}"
  getent passwd | awk -F: -v min="$min" -v max="$max" '$3>=min && $3<=max {print $1}' | sort
}

is_sudoer() {
  id -nG "$1" 2>/dev/null | tr ' ' '\n' | grep -qxE 'sudo|admin|wheel'
}

is_protected() {
  [ "$1" = "root" ] || { [ -n "$INVOKER" ] && [ "$1" = "$INVOKER" ]; } || { [ -n "${SUDO_USER:-}" ] && [ "$1" = "${SUDO_USER:-}" ]; }
}

pw_info() {
  # Describes a user's password WITHOUT revealing it (only the hash exists on disk).
  local u="$1" entry hash days algo changed="" note=""
  entry="$(getent shadow "$u" 2>/dev/null || true)"
  if [ -z "$entry" ]; then echo "unknown"; return; fi
  hash="$(echo "$entry" | cut -d: -f2)"
  days="$(echo "$entry" | cut -d: -f3)"
  case "$hash" in
    "")                echo "EMPTY - no password!"; return ;;
    "*"|"!"|"!!"|"!*") echo "no password (password login disabled)"; return ;;
  esac
  if [[ "$hash" == '!'* ]]; then note="LOCKED, "; hash="${hash#!}"; fi
  case "$hash" in
    '$1$'*) algo="md5 (WEAK)" ;;
    '$2'*)  algo="bcrypt" ;;
    '$5$'*) algo="sha256" ;;
    '$6$'*) algo="sha512" ;;
    '$y$'*) algo="yescrypt" ;;
    '$7$'*) algo="scrypt" ;;
    *)      algo="unknown hash" ;;
  esac
  if [[ "$days" =~ ^[0-9]+$ ]] && [ "$days" -gt 0 ]; then
    changed="$(date -d "@$((days*86400))" +%Y-%m-%d 2>/dev/null || true)"
  fi
  echo "${note}set, ${algo}${changed:+, changed $changed}"
}

show_user_table() {
  local u st
  {
    printf '  %-14s %-6s %-9s %-46s %s\n' "USER" "UID" "STATUS" "PASSWORD" "SHELL"
    for u in $(list_human_users); do
      if is_sudoer "$u"; then st="ADMIN"; else st="standard"; fi
      printf '  %-14s %-6s %-9s %-46s %s\n' "$u" "$(id -u "$u")" "$st" "$(pw_info "$u")" "$(getent passwd "$u" | cut -d: -f7)"
    done
  } | tee -a "$LOGFILE"
}

manage_user() {
  # manage_user <name>: menu loop for one account
  local u="$1" choice rmflag
  while true; do
    echo
    info "User '$u': $(is_sudoer "$u" && echo ADMIN || echo standard) | groups: $(id -nG "$u" 2>/dev/null) | password: $(pw_info "$u")"
    if is_protected "$u"; then info "  ('$u' is the account running this script: it can't be deleted, locked or demoted here)"; fi
    read -r -p "  [Enter]=keep as is   [s]tatus (admin<->standard)   [p]assword   [l]ock   [d]elete  > " choice || return 0
    case "$choice" in
      ""|k|K) return 0 ;;

      s|S)
        if is_sudoer "$u"; then
          if is_protected "$u"; then warn "  Not demoting '$u' (the account running this script)."; continue; fi
          if confirm_strict "  Make '$u' a STANDARD user (remove admin rights)?" \
              "Remove '$u' from the groups that give administrator rights (sudo, admin, wheel)" \
              "They keep their account and files but can no longer run commands with sudo" \
              "WHY:Only do this if the README says '$u' is not an authorized administrator"; then
            for g in sudo admin wheel; do
              if getent group "$g" >/dev/null 2>&1 && id -nG "$u" | tr ' ' '\n' | grep -qx "$g"; then
                gpasswd -d "$u" "$g" >>"$LOGFILE" 2>&1 && ok "Removed '$u' from group '$g'."
              fi
            done
            is_sudoer "$u" && warn "  '$u' still has admin rights (check /etc/sudoers.d, section 17)."
          fi
        else
          if confirm "  Make '$u' an ADMINISTRATOR (can use sudo)?" \
              "Add '$u' to the '${ADMIN_GROUP:-sudo}' group so they can use sudo" \
              "WHY:Only do this if the README says '$u' is an authorized administrator"; then
            usermod -aG "${ADMIN_GROUP:-sudo}" "$u" >>"$LOGFILE" 2>&1 && ok "Added '$u' to '${ADMIN_GROUP:-sudo}'."
          fi
        fi
        ;;

      p|P)
        if confirm "  Change the password for '$u'?" \
            "Run passwd for '$u'. You will type the new password twice (it is not shown on screen)" \
            "WHY:Use a strong password: 12+ characters mixing upper, lower, numbers and symbols"; then
          if passwd "$u"; then ok "Password changed for '$u'."; else warn "Password for '$u' was not changed."; fi
        fi
        ;;

      l|L)
        if is_protected "$u"; then warn "  Not locking '$u' (the account running this script)."; continue; fi
        if confirm_strict "  Lock '$u' so they cannot log in?" \
            "Lock their password and set their shell to nologin" \
            "The account and files stay; it can be unlocked later with: sudo usermod -U $u" \
            "WHY:Safer than deleting if you are unsure or may need their files for forensics"; then
          usermod -L -s /usr/sbin/nologin "$u" >>"$LOGFILE" 2>&1 && ok "Locked '$u'."
        fi
        ;;

      d|D)
        if is_protected "$u"; then warn "  Not deleting '$u' (the account running this script)."; continue; fi
        if confirm_strict "  Really DELETE '$u'? This cannot be undone." \
            "Kill any running programs owned by '$u'" \
            "Remove their scheduled cron jobs" \
            "Delete the account (userdel). You will be asked next whether to delete their home folder too" \
            "WHY:Only delete users the README does NOT list as authorized, and check no forensics question needs them"; then
          rmflag=""
          confirm_strict "  Also delete the home directory $(getent passwd "$u" | cut -d: -f6)?" \
              "Delete the whole home folder and everything in it (documents, downloads, settings)" \
              "WHY:Answer n to keep the files, for example if a forensics question may need them" && rmflag="-r"
          pkill -KILL -u "$u" 2>/dev/null || true
          crontab -r -u "$u" 2>/dev/null || true
          if userdel $rmflag "$u" >>"$LOGFILE" 2>&1; then ok "Deleted user '$u'."; else bad "userdel failed for '$u' (see log)."; fi
          return 0
        fi
        ;;

      *) info "  Unknown choice '$choice'." ;;
    esac
  done
}

create_users_loop() {
  local nu isadm
  while confirm_strict "Create a new user account?" \
      "You will type the new username and choose whether they are an administrator" \
      "The account is created with a home folder, then you set their password" \
      "WHY:Only create users the README lists as authorized but missing from the table above"; do
    read -r -p "  New username (lowercase letters/numbers, e.g. jsmith): " nu || return 0
    if ! [[ "$nu" =~ ^[a-z][-a-z0-9_]*$ ]]; then warn "  '$nu' is not a valid username."; continue; fi
    if getent passwd "$nu" >/dev/null 2>&1; then warn "  '$nu' already exists."; continue; fi
    read -r -p "  Make '$nu' an administrator (sudo)? [y/N] " isadm || isadm=""
    if useradd -m -s /bin/bash "$nu" >>"$LOGFILE" 2>&1 && getent passwd "$nu" >/dev/null 2>&1; then
      ok "Created user '$nu'."
      if [[ "$isadm" =~ ^[Yy]$ ]] && [ -n "$ADMIN_GROUP" ]; then
        usermod -aG "$ADMIN_GROUP" "$nu" >>"$LOGFILE" 2>&1 && ok "  '$nu' added to '$ADMIN_GROUP'."
      fi
      info "  Set a password for '$nu':"; passwd "$nu"
    else
      bad "Could not create '$nu' (see log)."
    fi
  done
}

info "Linux only stores one-way password hashes, so real passwords can't be shown."
info "The PASSWORD column shows whether one is set, how it's stored, and when it last changed."
show_user_table

EMPTY_PW_USERS=""
for u in $(list_human_users); do
  case "$(pw_info "$u")" in EMPTY*) EMPTY_PW_USERS="$EMPTY_PW_USERS $u" ;; esac
done
[ -n "$EMPTY_PW_USERS" ] && bad "Accounts with NO password:$EMPTY_PW_USERS (set one with passwd, or lock/delete them)"

OTHER_LOGIN="$(awk -F: '$3<1000 && $3!=0 && $7 !~ /(nologin|false|sync|shutdown|halt)$/ && $7!="" {print $1" ("$7")"}' /etc/passwd | tr '\n' ' ')"
if [ -n "$OTHER_LOGIN" ]; then
  warn "System accounts (UID < 1000) that can log in with a shell: $OTHER_LOGIN"
  info "  These are usually normal on some systems, but investigate any you don't recognize."
fi
info "Note: this shows sudo/admin/wheel GROUP membership. Direct entries in /etc/sudoers.d are covered by section 17."

if [ "$HARDEN" -ne 1 ]; then
  info "Audit-only run: no account changes made. Re-run with --harden to manage users one by one."
elif confirm_strict "Review each user above one at a time and optionally change them?" \
    "For each user you can: change status (admin or standard), change password, lock, or delete" \
    "Press Enter on a user to leave them unchanged" \
    "Afterwards you can create new users, and the table is shown again so you can check the result" \
    "Backs up /etc/passwd, /etc/shadow, /etc/group and /etc/gshadow first" \
    "WHY:Compare the table with the README's authorized administrators and users"; then
  for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow; do backup_file "$f"; done
  ADMIN_GROUP=""
  for g in sudo admin wheel; do
    if getent group "$g" >/dev/null 2>&1; then ADMIN_GROUP="$g"; break; fi
  done
  for u in $(list_human_users); do
    manage_user "$u"
  done
  create_users_loop
  echo
  info "Accounts after your changes:"
  show_user_table
fi

# --- Password policy ---
hdr "5b. Password Policy"

if [ -f /etc/login.defs ]; then
  info "Current PASS_MAX_DAYS / PASS_MIN_DAYS / PASS_WARN_AGE:"
  grep -E '^PASS_(MAX_DAYS|MIN_DAYS|WARN_AGE)' /etc/login.defs | tee -a "$LOGFILE"
fi

if [ "$HARDEN" -eq 1 ]; then
  if confirm "Apply recommended password aging (MAX=90, MIN=0, WARN=7) in /etc/login.defs?" \
        "Back up /etc/login.defs" \
        "Passwords expire after 90 days, warn users 7 days before, and may change at any time" \
        "WHY:Password expiration is a commonly scored item. These defaults apply to NEW accounts; existing accounts need the chage command"; then
    backup_file /etc/login.defs
    sed -i -E 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
    sed -i -E 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   0/' /etc/login.defs
    sed -i -E 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs
    ok "Updated /etc/login.defs"
  fi

  if confirm "Install libpam-cracklib and enforce password complexity + reuse history (5) / minlen 8?" \
        "Install libpam-cracklib (a password-strength checker)" \
        "Back up /etc/pam.d/common-password" \
        "Require 8+ characters with upper, lower, number and symbol, and block reusing the last 5 passwords" \
        "WHY:Weak password rules are scored. This only applies when someone CHANGES a password"; then
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

  if confirm "Add account lockout after 5 failed attempts (30 min unlock) to /etc/pam.d/common-auth?" \
        "Back up /etc/pam.d/common-auth" \
        "Check which lockout module this system has (pam_tally2 or pam_faillock). If neither exists it is skipped, so you cannot get locked out" \
        "Lock an account for 30 minutes after 5 wrong passwords" \
        "WHY:Account lockout is a scored item. Keep a second terminal open with sudo -i while you test it"; then
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
  if confirm "Clear /etc/securetty to disable root logins on all local ttys?" \
        "Back up /etc/securetty" \
        "Empty the list of terminals that root is allowed to log in on" \
        "WHY:Stops root from logging in directly at a console"; then
    backup_file /etc/securetty
    : > /etc/securetty
    ok "/etc/securetty cleared."
  fi
fi

info "Root account lock status:"
passwd -S root 2>&1 | tee -a "$LOGFILE"

if [ "$HARDEN" -eq 1 ]; then
  if confirm "Lock the root account (passwd -l root) so it cannot log in with a password at all?" \
        "Run passwd -l root, which locks the root password" \
        "Admins can still use sudo. Only logging in directly as root with a password is blocked" \
        "WHY:Make sure at least one admin user with sudo exists before you do this"; then
    passwd -l root 2>&1 | tee -a "$LOGFILE"
    ok "Root account locked."
  elif confirm "Instead, set/reset the root account password now (interactive)?" \
        "Run passwd root. You will type a new password twice" \
        "WHY:Use this if the root password is weak or blank"; then
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
    if confirm "Set 'PermitRootLogin no' in /etc/ssh/sshd_config and restart sshd?" \
        "Back up /etc/ssh/sshd_config" \
        "Set PermitRootLogin no" \
        "Restart the SSH service (this briefly drops any open SSH connections, not your desktop)" \
        "WHY:Stops anyone logging in over SSH as root"; then
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
  if [ "$HARDEN" -eq 1 ] && confirm "Install ufw?" \
        "Install ufw, the Uncomplicated Firewall" \
        "WHY:A firewall is a commonly scored item"; then
    apt-get install -y ufw 2>&1 | tee -a "$LOGFILE"
  fi
fi

if command -v ufw >/dev/null 2>&1; then
  info "Current ufw status:"
  ufw status verbose | tee -a "$LOGFILE"
  if [ "$HARDEN" -eq 1 ]; then
    if confirm "Enable ufw now?" \
        "Turn the firewall on (ufw enable). By default it blocks incoming connections" \
        "Afterwards allow anything the README requires, for example: sudo ufw allow 443/tcp" \
        "WHY:An enabled firewall is a commonly scored item"; then
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
    if [ "$HARDEN" -eq 1 ] && confirm "Install $tool?" \
        "Install $tool, a scanner that looks for rootkits (hidden malware)" \
        "WHY:Scanning only reports findings. It does not delete anything on its own"; then
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
  if [ "$HARDEN" -eq 1 ] && confirm "Install and enable auditd?" \
        "Install auditd, which records security events such as logins and file changes" \
        "Start it now and make it start at every boot"; then
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
  if confirm "Force /etc/shadow and /etc/gshadow to root:shadow 640?" \
        "Set the owner of /etc/shadow and /etc/gshadow to root, group shadow" \
        "Set permissions to 640 so only root and the shadow group can read password hashes" \
        "WHY:Loose permissions here let normal users read password hashes"; then
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
  if [ "$HARDEN" -eq 1 ] && confirm "Delete /etc/hosts.equiv?" \
        "Back up, then delete /etc/hosts.equiv" \
        "WHY:This old file lets other computers log in without a password"; then
    backup_file /etc/hosts.equiv
    rm -f /etc/hosts.equiv
    ok "Removed."
  fi
else
  ok "/etc/hosts.equiv not present."
fi
if [ "$HARDEN" -eq 1 ] && [ -n "$FOUND_RHOSTS" ]; then
  if confirm "Delete all found .rhosts files?" \
        "Delete every .rhosts file under /root and /home (no backup is made)" \
        "WHY:These old files let other computers log in without a password"; then
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
  if confirm "Write recommended values to /etc/sysctl.d/99-zz-hardening.conf and apply now?" \
        "Create /etc/sysctl.d/99-zz-hardening.conf with safer network settings (no IP forwarding, ignore redirects, SYN-flood protection, log suspicious packets)" \
        "Remove the older 99-hardening.conf if it exists (it is backed up first)" \
        "Apply the settings right now and keep them after a reboot" \
        "Then look for other config files that would undo these settings" \
        "WHY:Kernel network hardening is a commonly scored item"; then
    # Named 99-zz-* so it sorts AFTER other files (e.g. 99-sysctl.conf -> /etc/sysctl.conf).
    # With the old name (99-hardening.conf), a later file could silently override it,
    # which made the same FLAG reappear on every run / after reboot.
    HFILE=/etc/sysctl.d/99-zz-hardening.conf
    OLDFILE=/etc/sysctl.d/99-hardening.conf
    SYSCTL_DIRS="/etc/sysctl.conf /etc/sysctl.d /run/sysctl.d /usr/local/lib/sysctl.d /usr/lib/sysctl.d /lib/sysctl.d"

    if [ -f "$OLDFILE" ]; then
      backup_file "$OLDFILE"
      rm -f "$OLDFILE"
      info "Removed old $OLDFILE (superseded by $HFILE)."
    fi
    backup_file "$HFILE"
    {
      echo "# Added by linux_checklist.sh on $TS"
      for key in "${!SYSCTL_CHECKS[@]}"; do
        echo "$key = ${SYSCTL_CHECKS[$key]}"
      done
      echo "net.ipv4.conf.default.log_martians = 1"
    } > "$HFILE"

    # Find OTHER files that set the same keys to a different value (these win/lose depending on order)
    CONFLICTS=""
    for key in "${!SYSCTL_CHECKS[@]}"; do
      want="${SYSCTL_CHECKS[$key]}"
      kre="${key//./[./]}"
      while IFS= read -r line; do
        [ -z "$line" ] && continue
        f="${line%%:*}"; rest="${line#*:}"; rest="${rest#*:}"
        [ "$f" = "$HFILE" ] && continue
        val="$(echo "$rest" | sed -E 's/^[^=]*=[[:space:]]*//; s/[[:space:]]+$//')"
        if [ "$val" != "$want" ]; then
          CONFLICTS="$CONFLICTS$f|$key|$val"$'\n'
        fi
      done < <(grep -rnHE "^[[:space:]]*${kre}[[:space:]]*=" $SYSCTL_DIRS 2>/dev/null \
               | grep -v "^$HFILE:")
    done

    if [ -n "$CONFLICTS" ]; then
      warn "Other config files set these keys to different values:"
      echo "$CONFLICTS" | while IFS='|' read -r f k v; do
        [ -n "$f" ] && warn "  $f: $k = $v"
      done | tee -a "$LOGFILE"
      if confirm "Comment out those conflicting lines (backups are made first)?" \
        "Back up each file that sets one of these values differently" \
        "Put a # in front of those lines so they stop applying" \
        "WHY:Otherwise those lines override our safe values after a reboot"; then
        echo "$CONFLICTS" | cut -d'|' -f1 | sort -u | while read -r f; do
          [ -z "$f" ] && continue
          [ -L "$f" ] && f="$(readlink -f "$f")"
          backup_file "$f"
          for key in "${!SYSCTL_CHECKS[@]}"; do
            kre="${key//./[./]}"
            sed -i -E "s|^([[:space:]]*${kre}[[:space:]]*=.*)$|# disabled by linux_checklist.sh: \1|" "$f"
          done
        done
        ok "Conflicting lines commented out."
      fi
    fi

    # Apply the whole sysctl configuration in real load order, then verify the FINAL values
    sysctl --system 2>&1 | tee -a "$LOGFILE" >/dev/null
    sysctl -p "$HFILE" 2>&1 | tee -a "$LOGFILE"
    ok "Wrote and applied $HFILE"

    info "Verifying final values after apply:"
    for key in "${!SYSCTL_CHECKS[@]}"; do
      cur="$(sysctl -n "$key" 2>/dev/null || echo "unknown")"
      want="${SYSCTL_CHECKS[$key]}"
      if [ "$cur" = "$want" ]; then
        ok "$key = $cur"
      else
        bad "$key = $cur (wanted $want) — something is still overriding it. Check: grep -rn '${key##*.}' /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d"
      fi
    done
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
    if confirm "Apply hardened SSH settings (PermitEmptyPasswords no, X11Forwarding no, MaxAuthTries 3) and restart sshd?" \
        "Back up /etc/ssh/sshd_config" \
        "PermitEmptyPasswords no: no logging in over SSH with a blank password" \
        "X11Forwarding no: turn off remote graphical forwarding" \
        "MaxAuthTries 3: allow only 3 password attempts per connection" \
        "Restart the SSH service"; then
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
    if [ "$HARDEN" -eq 1 ] && confirm "Create $allow containing only 'root'?" \
        "Create $allow listing only root (permissions 600)" \
        "Only root may use this scheduler. Other users are blocked" \
        "WHY:Answer n if the README says a normal user needs scheduled jobs"; then
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
  if confirm "Set a generic 'Authorized use only' warning banner in /etc/issue and /etc/issue.net?" \
        "Back up /etc/issue and /etc/issue.net" \
        "Replace both with a short warning that only authorized users may log in"; then
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
  if [ "$HARDEN" -eq 1 ] && confirm "Install ClamAV and update virus definitions?" \
        "Install the ClamAV antivirus" \
        "Briefly stop its update service, download the newest virus definitions (freshclam), then restart it" \
        "WHY:This does NOT start a scan. A full scan takes a long time and is run separately"; then
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
  if [ "$HARDEN" -eq 1 ] && confirm "Install apparmor + apparmor-utils and enable it?" \
        "Install AppArmor and its tools" \
        "Enable it at boot and start it now" \
        "WHY:AppArmor limits what each program is allowed to do, which helps contain attacks"; then
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
    if [ "$HARDEN" -eq 1 ] && confirm "Enable systemd-timesyncd?" \
        "Turn on automatic clock synchronization (timedatectl set-ntp true)"; then
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
  if [ "$HARDEN" -eq 1 ] && confirm "Install and enable unattended-upgrades?" \
        "Install unattended-upgrades" \
        "Run its setup so security updates install on their own" \
        "WHY:Automatic security updates are a commonly scored item"; then
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

  if [ "$HARDEN" -eq 1 ] && confirm "Set apt to check daily and auto download/install security updates ($AUTO_CONF)?" \
        "Install unattended-upgrades if it is missing" \
        "Back up the current $AUTO_CONF" \
        "Check for new updates every day, download them, and install security updates automatically" \
        "WHY:Matches the Software Updates settings: check Daily, install security updates automatically"; then
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
    if [ "$HARDEN" -eq 1 ] && confirm "Set ufw defaults (reject incoming, allow outgoing) and enable ufw?" \
        "Turn the firewall on" \
        "Reject all incoming connections by default" \
        "Allow all outgoing connections" \
        "WHY:Allow any service the README needs afterwards, for example: sudo ufw allow ssh"; then
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
  if [ "$HARDEN" -eq 1 ] && confirm "Stop and purge FTP server package(s):$FTP_FOUND ?" \
        "Stop and disable each FTP service that is running" \
        "Purge the FTP package(s):$FTP_FOUND (removes the program and its config)" \
        "WHY:FTP sends passwords unencrypted. Answer n if the README says FTP is required"; then
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
  if [ "$HARDEN" -eq 1 ] && confirm "Enable Update Manager 'Apply updates automatically' (mintupdate-automation upgrade enable)?" \
        "Run mintupdate-automation upgrade enable" \
        "This is the same as turning on Apply updates automatically in Update Manager > Preferences > Automation"; then
    if mintupdate-automation upgrade enable 2>&1 | tee -a "$LOGFILE"; then
      ok "Requested: Apply updates automatically. Verify in Update Manager -> Preferences -> Automation."
    else
      warn "mintupdate-automation failed — set it manually via the GUI steps above."
    fi
  fi
else
  info "mintupdate-automation not found (not Mint, or Update Manager not installed) — apt auto-updates are handled in sections 23/24."
fi

# --- Auto refresh / automation status (read-only checks) ---
info "Update Manager -> Preferences -> Automation should show: Apply updates automatically = ON."
info "  (Also on that tab: 'Update flatpaks automatically' and 'Remove obsolete kernels and dependencies' — optional.)"

if grep -q 'Update-Package-Lists "1"' /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null; then
  ok "APT refreshes the package lists daily (/etc/apt/apt.conf.d/20auto-upgrades)."
else
  bad "APT daily list refresh is NOT set in /etc/apt/apt.conf.d/20auto-upgrades (section 24 sets it with --harden)."
fi

if ls /etc/cron.daily /etc/cron.weekly /etc/cron.d 2>/dev/null | grep -qi mintupdate; then
  ok "Mint Update Manager automation job(s) found:"
  ls -l /etc/cron.daily/*mintupdate* /etc/cron.weekly/*mintupdate* /etc/cron.d/*mintupdate* 2>/dev/null | tee -a "$LOGFILE"
else
  info "No mintupdate job found under cron.daily/weekly/d — it may be stored elsewhere on this release; verify in the GUI."
fi

AR_USER="$(logname 2>/dev/null || echo "${SUDO_USER:-}")"
if [ -n "$AR_USER" ] && [ "$AR_USER" != "root" ] && command -v gsettings >/dev/null 2>&1 \
   && gsettings list-schemas 2>/dev/null | grep -qx 'com.linuxmint.updates'; then
  info "Update Manager refresh settings for $AR_USER (com.linuxmint.updates):"
  for k in $(gsettings list-keys com.linuxmint.updates 2>/dev/null | grep -i 'refresh'); do
    v="$(user_gsettings "$AR_USER" get com.linuxmint.updates "$k" 2>/dev/null)"
    info "  $k = ${v:-unknown (no desktop session)}"
  done
else
  info "Check the auto-refresh interval in Update Manager -> Edit -> Preferences -> Options."
fi

info "Install updates (important security updates):"
info "  GUI: Update Manager -> Refresh -> Install Updates   (auto-apply must be set in Preferences first)"
info "  CLI: sudo apt update && sudo apt full-upgrade -y && sudo apt autoremove --purge -y"
if [ "$HARDEN" -eq 1 ] && confirm "Run apt-get update && apt-get full-upgrade -y now?" \
        "Refresh the list of available updates (apt-get update)" \
        "Install every available update, including ones that add or remove packages (apt-get full-upgrade -y)" \
        "This can take several minutes"; then
  apt-get update 2>&1 | tee -a "$LOGFILE"
  apt-get full-upgrade -y 2>&1 | tee -a "$LOGFILE"
  ok "apt full-upgrade complete."
  if confirm "Also remove unneeded packages and their config (apt-get autoremove --purge -y)?" \
        "Remove packages that were installed automatically and are no longer needed" \
        "--purge also deletes their leftover config files"; then
    apt-get autoremove --purge -y 2>&1 | tee -a "$LOGFILE"
    ok "apt autoremove --purge complete."
  fi
fi

# ---------------------------------------------------------------------------
# Extra: disable automount
# ---------------------------------------------------------------------------
hdr "Extra: USB Automount"

if command -v gsettings >/dev/null 2>&1; then
  target_user="$(logname 2>/dev/null || echo "${SUDO_USER:-}")"
  if [ -z "$target_user" ] || [ "$target_user" = "root" ]; then
    warn "Could not determine the logged-in desktop user — set automount off manually (see below)."
  else
    # Pick whichever media-handling schema exists on this desktop (GNOME, MATE, Cinnamon)
    AM_SCHEMA=""
    for sch in org.gnome.desktop.media-handling org.mate.media-handling org.cinnamon.desktop.media-handling; do
      if gsettings list-schemas 2>/dev/null | grep -qx "$sch"; then AM_SCHEMA="$sch"; break; fi
    done

    if [ -z "$AM_SCHEMA" ]; then
      warn "No media-handling gsettings schema found."
    else
      info "Using schema: $AM_SCHEMA (user: $target_user)"
      cur="$(user_gsettings "$target_user" get "$AM_SCHEMA" automount 2>/dev/null)"
      info "Current automount: ${cur:-unknown (no active desktop session found)}"

      if [ "$HARDEN" -eq 1 ] && confirm "Disable automount/autorun for user '$target_user'?" \
        "Turn off automatic mounting of USB drives and disks for $target_user" \
        "Turn off automatically opening removable media" \
        "Never auto-run programs from removable media" \
        "This runs inside $target_user desktop session, so it only works while they are logged in"; then
        if user_gsettings "$target_user" set "$AM_SCHEMA" automount false &&
           user_gsettings "$target_user" set "$AM_SCHEMA" automount-open false &&
           user_gsettings "$target_user" set "$AM_SCHEMA" autorun-never true; then
          ok "Automount disabled for $target_user (verified: automount=$(user_gsettings "$target_user" get "$AM_SCHEMA" automount))."
        else
          warn "Could not apply automount settings (no desktop session for $target_user?)."
          warn "Do it manually, logged in as $target_user, in a normal terminal (no sudo):"
          warn "  gsettings set $AM_SCHEMA automount false"
          warn "  gsettings set $AM_SCHEMA automount-open false"
          warn "  gsettings set $AM_SCHEMA autorun-never true"
        fi
      fi
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Final verification: re-read the REAL state of everything (like "refresh the list")
# so a step that printed [OK] but didn't actually stick shows up here.
# ---------------------------------------------------------------------------
hdr "Final Verification (re-check actual state)"

V_PASS=0; V_FAIL=0
vcheck() {
  # vcheck <label> <0|1 result: 0 = good> [detail on failure]
  if [ "$2" -eq 0 ]; then ok "$1"; V_PASS=$((V_PASS+1)); else bad "$1${3:+ — $3}"; V_FAIL=$((V_FAIL+1)); fi
}

# 1) Updates: refresh the list, then count what's still pending
if [ "$HARDEN" -eq 1 ] && confirm "Refresh the package list now (apt-get update) before counting pending updates?" \
        "Download the latest list of available package versions (apt-get update)" \
        "WHY:Installs nothing. It only makes the pending-update count below accurate"; then
  apt-get update >>"$LOGFILE" 2>&1
fi
PENDING="$(apt list --upgradable 2>/dev/null | grep -c 'upgradable')"
SEC_PENDING="$(apt list --upgradable 2>/dev/null | grep -ci 'security')"
vcheck "No pending package updates" "$([ "${PENDING:-0}" -eq 0 ] && echo 0 || echo 1)" "$PENDING pending ($SEC_PENDING security) — run: sudo apt update && sudo apt full-upgrade -y && sudo apt autoremove --purge -y"

# 2) Automatic updates configured
AU=/etc/apt/apt.conf.d/20auto-upgrades
vcheck "APT refreshes the package list daily" "$(grep -q 'Update-Package-Lists "1"' $AU 2>/dev/null && echo 0 || echo 1)" "not set in $AU"
vcheck "Unattended (automatic) upgrades enabled" "$(grep -q 'Unattended-Upgrade "1"' $AU 2>/dev/null && echo 0 || echo 1)" "not set in $AU"

# 3) Firewall
if command -v ufw >/dev/null 2>&1; then
  UFW_OUT="$(ufw status verbose 2>/dev/null)"
  vcheck "UFW is active" "$(echo "$UFW_OUT" | grep -q 'Status: active' && echo 0 || echo 1)" "run: sudo ufw enable"
  vcheck "UFW default for incoming is deny/reject" "$(echo "$UFW_OUT" | grep -Eq 'Default: (deny|reject) \(incoming\)' && echo 0 || echo 1)" "run: sudo ufw default deny incoming"
else
  vcheck "UFW installed" 1 "ufw not found"
fi

# 4) SSH effective config (if sshd exists)
if command -v sshd >/dev/null 2>&1; then
  PRL="$(sshd -T 2>/dev/null | awk '/^permitrootlogin/{print $2}')"
  vcheck "sshd PermitRootLogin = no" "$([ "$PRL" = "no" ] && echo 0 || echo 1)" "effective value: ${PRL:-unknown}"
fi

# 5) sysctl values (the same table section 15 uses) — reads the live kernel value
for key in "${!SYSCTL_CHECKS[@]}"; do
  cur="$(sysctl -n "$key" 2>/dev/null || echo unknown)"
  vcheck "sysctl $key = ${SYSCTL_CHECKS[$key]}" "$([ "$cur" = "${SYSCTL_CHECKS[$key]}" ] && echo 0 || echo 1)" "currently $cur"
done

# 6) FTP server gone
FTP_LEFT=""
for pkg in vsftpd proftpd-basic proftpd pure-ftpd pure-ftpd-common; do
  dpkg -l "$pkg" 2>/dev/null | grep -q '^ii' && FTP_LEFT="$FTP_LEFT $pkg"
done
vcheck "No FTP server installed" "$([ -z "$FTP_LEFT" ] && echo 0 || echo 1)" "still installed:$FTP_LEFT"

# 6b) Hacking/analysis tools (including variants such as netcat-openbsd, wireshark-qt)
LEFT_TOOLS=""
for tool in "${SUSPECT_TOOLS[@]}"; do
  L="$(installed_matches "$tool" | tr '\n' ' ')"
  [ -n "${L// /}" ] && LEFT_TOOLS="$LEFT_TOOLS $L"
done
vcheck "No flagged hacking/analysis tools installed" "$([ -z "${LEFT_TOOLS// /}" ] && echo 0 || echo 1)" "still installed:$LEFT_TOOLS (skip any the README says are required)"

# 7) Automount (needs the desktop session; uses values from the USB step)
if [ -n "${AM_SCHEMA:-}" ] && [ -n "${target_user:-}" ]; then
  AMV="$(user_gsettings "$target_user" get "$AM_SCHEMA" automount 2>/dev/null)"
  vcheck "USB automount is off for $target_user" "$([ "$AMV" = "false" ] && echo 0 || echo 1)" "currently: ${AMV:-unknown}"
fi

# 8) Accounts: UID 0 and empty passwords (re-read live)
UID0_NOW="$(awk -F: '($3==0 && $1!="root"){print $1}' /etc/passwd | tr '\n' ' ')"
vcheck "Only root has UID 0" "$([ -z "${UID0_NOW// /}" ] && echo 0 || echo 1)" "also UID 0: $UID0_NOW"
EMPTY_NOW=""
for u in $(list_human_users); do case "$(pw_info "$u")" in EMPTY*) EMPTY_NOW="$EMPTY_NOW $u" ;; esac; done
vcheck "No user accounts with an empty password" "$([ -z "${EMPTY_NOW// /}" ] && echo 0 || echo 1)" "empty:$EMPTY_NOW"

# 9) Safety: every PAM module referenced actually exists (a missing one locks you out of sudo/login)
mapfile -t PAM_HAVE < <(find /lib /lib64 /usr/lib -name 'pam_*.so' -printf '%f\n' 2>/dev/null | sort -u)
PAM_BAD=""
for mod in $(cat /etc/pam.d/* 2>/dev/null | grep -v '^[[:space:]]*#' | grep -oE 'pam_[A-Za-z0-9_]+\.so' | sort -u); do
  printf '%s\n' "${PAM_HAVE[@]}" | grep -qx "$mod" || PAM_BAD="$PAM_BAD $mod"
done
vcheck "All PAM modules in /etc/pam.d exist (no lockout risk)" "$([ -z "$PAM_BAD" ] && echo 0 || echo 1)" "MISSING:$PAM_BAD — fix BEFORE logging out/rebooting (restore the .bak file)"

echo
if [ "$V_FAIL" -eq 0 ]; then
  ok "Verification: all $V_PASS checks passed."
else
  bad "Verification: $V_FAIL failed, $V_PASS passed. Fix the [FLAG] lines above and re-run."
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
