#!/usr/bin/env bash
# Group 2/15: Honeypot Health Monitoring, Honeypot Service Monitoring,
# Container Health Monitoring, Service Failure Detection.
#
# Run on a cron schedule (e.g. every minute) on System 2. Checks that
# every honeypot/IDS container is running, and POSTs the result to
# System 1's /api/health/system2 endpoint so it shows up on the SOC
# dashboard's System Health panel and Honeypot Status panel.
#
#   */1 * * * * /opt/honeyshield/scripts/health_check.sh >> /var/log/honeyshield/health_check.log 2>&1

set -euo pipefail

SYSTEM1_URL="${SYSTEM1_URL:-https://192.168.1.10:8000}"
API_KEY="${HONEYSHIELD_API_KEY:?Set HONEYSHIELD_API_KEY in the environment}"

SERVICES=(hsx-cowrie hsx-opencanary hsx-dionaea hsx-zeek hsx-suricata hsx-filebeat)

status_json="{"
first=true
overall_healthy=true

for svc in "${SERVICES[@]}"; do
  if docker inspect -f '{{.State.Running}}' "$svc" >/dev/null 2>&1; then
    running=$(docker inspect -f '{{.State.Running}}' "$svc")
  else
    running="false"
  fi

  if [ "$running" != "true" ]; then
    overall_healthy=false
  fi

  if [ "$first" = true ]; then first=false; else status_json+=","; fi
  status_json+="\"${svc}\":${running}"
done
status_json+="}"

cpu_pct=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1 || echo "0")
mem_pct=$(free | awk '/Mem:/ {printf "%.1f", $3/$2*100}')
disk_pct=$(df / | awk 'NR==2 {print $5}' | tr -d '%')

payload=$(cat <<EOF
{
  "node": "system-2-honeypot",
  "healthy": ${overall_healthy},
  "services": ${status_json},
  "cpu_percent": ${cpu_pct},
  "memory_percent": ${mem_pct},
  "disk_percent": ${disk_pct}
}
EOF
)

curl -sk -X POST "${SYSTEM1_URL}/api/health/system2" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${API_KEY}" \
  -d "${payload}" \
  --max-time 10 || echo "WARNING: failed to reach System 1 health endpoint"


