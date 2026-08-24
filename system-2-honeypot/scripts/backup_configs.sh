#!/usr/bin/env bash
# Group 1, Feature 6/164: Configuration Backup — System 2's half. Backs
# up docker-compose.yml and every honeypot/IDS config file that's
# meaningfully hand-tuned (Cowrie's deception credentials, Suricata's
# custom rules, Zeek's local policy, OpenCanary's config, Filebeat's
# shipping config) — the kind of thing that's tedious to reconstruct
# from memory if this box is rebuilt.
#
#   0 3 * * * /opt/honeyshield/system-2-honeypot/scripts/backup_configs.sh >> /var/log/honeyshield/backup.log 2>&1

set -euo pipefail

SYSTEM2_DIR="${SYSTEM2_DIR:-/opt/honeyshield/system-2-honeypot}"
BACKUP_ROOT="${BACKUP_ROOT:-/opt/honeyshield/backups/configs}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
DEST="${BACKUP_ROOT}/${TIMESTAMP}"

mkdir -p "$DEST"
echo "[$(date -Iseconds)] Backing up System 2 configuration -> ${DEST}"

FILES_TO_BACK_UP=(
  "docker-compose.yml"
  "cowrie/userdb.txt"
  "opencanary/opencanary.conf"
  "suricata/local.rules"
  "zeek/local.zeek"
  "filebeat/filebeat.yml"
)

for relative_path in "${FILES_TO_BACK_UP[@]}"; do
  src="${SYSTEM2_DIR}/${relative_path}"
  if [ -f "$src" ]; then
    dest_path="${DEST}/${relative_path}"
    mkdir -p "$(dirname "$dest_path")"
    cp "$src" "$dest_path"
    echo "  ${relative_path}: copied"
  else
    echo "  ${relative_path}: SKIPPED (not found)"
  fi
done

tar -czf "${DEST}.tar.gz" -C "$BACKUP_ROOT" "$TIMESTAMP"
rm -rf "$DEST"

find "$BACKUP_ROOT" -maxdepth 1 -name "*.tar.gz" -mtime "+${RETENTION_DAYS}" -delete

echo "[$(date -Iseconds)] Config backup complete: ${DEST}.tar.gz"


