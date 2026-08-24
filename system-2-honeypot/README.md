# System 2 — Honeypot / Security Sensor Server

Ubuntu Server 24.04 LTS, 8GB RAM target. Attack collection layer only —
no analysis, storage of record, or dashboard lives here (that's System 1).

## What's in this folder

```
system-2-honeypot/
├── docker-compose.yml       # Cowrie, OpenCanary, Dionaea, Zeek, Suricata, Filebeat
├── cowrie/userdb.txt        # deception credentials (Group 9)
├── opencanary/opencanary.conf
├── suricata/local.rules     # custom IDS rules on top of ET-Open
├── zeek/local.zeek
├── filebeat/filebeat.yml    # ships all 5 sources to System 1's OpenSearch
└── scripts/health_check.sh  # cron job reporting service health to System 1
```

## Setup

```bash
# 1. base packages
sudo apt update && sudo apt install -y docker.io docker-compose-plugin \
    tcpdump curl jq rsync htop net-tools

# 2. point Filebeat at System 1
export SYSTEM1_HOST=192.168.1.10   # your actual System 1 LAN IP
export OPENSEARCH_PASSWORD=<set on System 1's docker-compose.yml>
envsubst < filebeat/filebeat.yml > filebeat/filebeat.yml.tmp && \
    mv filebeat/filebeat.yml.tmp filebeat/filebeat.yml

# 3. bring everything up
docker compose up -d

# 4. verify
docker compose ps
docker compose logs -f cowrie
```

## tcpdump (Packet Capture Layer)

Runs at the host level rather than in a container, since it needs the
physical monitoring interface directly:

```bash
sudo tee /etc/systemd/system/hsx-tcpdump.service <<'EOF'
[Unit]
Description=HoneyShield X packet capture
After=network.target

[Service]
ExecStart=/usr/sbin/tcpdump -i eth0 -w /var/log/honeyshield/pcap/capture-%Y%m%d-%H%M%S.pcap -G 3600 -Z root
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo mkdir -p /var/log/honeyshield/pcap
sudo systemctl enable --now hsx-tcpdump
```

`-G 3600` rotates to a new pcap file every hour — adjust based on your
disk budget (Group 17: Automatic Log Rotation, Storage Threshold Alerts;
see System 1's `app/services/system_health.py` for the disk-usage alert
that watches this directory).

## Suricata's default ruleset

`suricata/local.rules` only contains HoneyShield-specific custom rules.
Pull the standard ET-Open ruleset alongside it:

```bash
sudo suricata-update
sudo cp suricata/local.rules /etc/suricata/rules/local.rules
echo "local.rules" | sudo tee -a /var/lib/suricata/update/enabled.rules
sudo suricata-update
sudo systemctl restart suricata
```

## Health monitoring cron

```bash
crontab -e
# add:
* * * * * HONEYSHIELD_API_KEY=<shared secret> SYSTEM1_URL=https://192.168.1.10:8000 /opt/honeyshield/scripts/health_check.sh >> /var/log/honeyshield/health_check.log 2>&1
```

## Log rotation (Feature 161)

Honeypot application logs (Cowrie/OpenCanary/Dionaea) have no rotation
of their own and grow unbounded otherwise — tcpdump's captures already
rotate hourly via the systemd unit above, but the log *files* need their
own policy:

```bash
sudo cp scripts/logrotate-honeypot.conf /etc/logrotate.d/honeyshield-honeypot
sudo logrotate -d /etc/logrotate.d/honeyshield-honeypot   # dry run first
```

See the comments in that file — it assumes the Docker log volumes are
bind-mounted to host paths rather than left as anonymous named volumes;
adjust `docker-compose.yml` if you haven't done that yet.

## Configuration backup (Feature 164)

```bash
crontab -e
# add:
0 3 * * * SYSTEM2_DIR=/opt/honeyshield/system-2-honeypot /opt/honeyshield/system-2-honeypot/scripts/backup_configs.sh >> /var/log/honeyshield/backup.log 2>&1
```

Backs up `docker-compose.yml` and every hand-tuned config file (Cowrie's
deception credentials, Suricata's custom rules, Zeek's local policy,
OpenCanary's config, Filebeat's shipping config) into a dated, compressed
archive with 30-day retention.

## Network segmentation (do this before exposing anything)

Every honeypot port in `docker-compose.yml` (2222, 2223, 8080, 21, 445,
3306, 69) must only be reachable from your isolated lab VLAN — never
bridged to a production or home network interface. See the architecture
diagram's "Network Segmentation" panel: management traffic (SSH, admin)
and the honeypot's attack-capture zone are two separate networks.


