#!/bin/sh
# Explicit administrator installation only. No apt, PAM edits or service restarts.
set -eu
umask 077
if [ "$(id -u)" -ne 0 ] || [ "$#" -ne 3 ]; then
    echo 'usage (root): sh install.sh NUMERIC_UID /absolute/sibling-directory gnu-tar' >&2
    exit 2
fi
ea_uid=$1
ea_destination=$2
case "$ea_uid" in ''|*[!0-9]*) exit 2;; esac
case "$ea_destination" in /*) ;; *) exit 2;; esac
[ "$3" = gnu-tar ] || exit 2
getent passwd "$ea_uid" >/dev/null
ea_source=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
[ -x "$ea_source/build/ea-native-operator" ]
[ -x /usr/bin/tar ]
[ -x /usr/bin/python3 ]
command -v chattr >/dev/null
# The supported Ubuntu profile is GNOME/GDM with the distro's PAM integration.
# Verify, do not rewrite the authentication stack or handle any password.
test -r /etc/pam.d/gdm-password
awk '$1 == "auth" && /pam_gnome_keyring[.]so/ { found=1 } END { exit !found }' /etc/pam.d/gdm-password
awk '$1 == "session" && /pam_gnome_keyring[.]so/ && /auto_start/ { found=1 } END { exit !found }' /etc/pam.d/gdm-password
# Do not adopt an existing directory/marker as a new account incarnation.
if [ -e "/var/lib/ea-native-operator/$ea_uid" ] || [ -L "/var/lib/ea-native-operator/$ea_uid" ]; then
    echo 'account directory exists; upgrades preserve it, managed administrator restore/reenrollment uses ea-native-restore' >&2
    exit 1
fi
install -d -o root -g root -m 0755 /var/lib/ea-native-operator /etc/ea-native-operator /etc/ea-native-operator/restore.d "$ea_destination" /usr/libexec /usr/share/polkit-1/actions
install -o root -g root -m 0755 "$ea_source/build/ea-native-operator" "$ea_destination/ea-native-operator"
install -o root -g root -m 0644 "$ea_source/org.einsatzarchiv.operator.policy" /usr/share/polkit-1/actions/org.einsatzarchiv.operator.policy
install -o root -g root -m 0644 "$ea_source/backup-policy" /etc/ea-native-operator/backup-policy
install -o root -g root -m 0644 "$ea_source/backup-excludes" /etc/ea-native-operator/backup-excludes
install -o root -g root -m 0755 "$ea_source/ea-native-backup" /usr/libexec/ea-native-backup
install -o root -g root -m 0755 "$ea_source/restore.py" /usr/libexec/ea-native-restore
install -d -o "$ea_uid" -m 0700 "/var/lib/ea-native-operator/$ea_uid"
chattr +d /var/lib/ea-native-operator "/var/lib/ea-native-operator/$ea_uid"
# Marker's +d flag is set and read back by the helper before atomic publication.
echo 'Installed. Use /usr/libexec/ea-native-backup for the declared backup profile; initialize from the enrolled GNOME session.'
