# Testing

Maps directly onto the completion table's weakest rows — this document
exists to turn "needs validation" into something you can actually run
and get a pass/fail or a real number from.

## 1. Unit tests (logic-level — no live stack needed)

Every pure-logic service module (log normalization, threat intel
heuristics, detection rules, correlation query-building + campaign
clustering, deception canary matching, alerting rules, PCAP linking, the
evaluation harness's own metrics math) was unit-tested during
development with real assertions — not just written and assumed correct.
These don't have a single `pytest` file of their own because they were
verified interactively; if you want them as a permanent regression suite,
each service module's docstring describes exactly what was checked and
that's a straightforward port into `tests/unit/test_<module>.py`.

## 2. AI model evaluation

```bash
cd system-1-soc/backend
pip install -r requirements.txt
python scripts/train_ai_models.py --synthetic
python scripts/evaluate_ai_models.py
```

Trains on an 80/20 split and reports real precision/recall/F1 per class,
a confusion matrix, and false-positive/true-positive rates for the
anomaly detector on held-out data.

**Read the output critically, not triumphantly.** A first run of this
produces a 100% accuracy classifier — that is a synthetic-data artifact,
not evidence of a great model: `train_ai_models.py`'s five archetypes
have feature ranges that don't overlap much by construction (e.g.
brute_force always has 0 commands, exploitation always has commands
run), so a RandomForest trivially separates them. The anomaly detector's
number (typically ~60% true-positive rate on synthetic attacks) is the
more informative one here — it's pooling five very different attack
shapes into one general-purpose detector, so meaningfully-less-than-100%
recall is expected and realistic, not a bug.

The real validation only happens once you retrain on actual captured
sessions (`--from-db`, or `POST /api/ai/retrain` once you have 10+
completed sessions) and these numbers shift to reflect real attacker
behavior instead of a clean synthetic split.

## 3. Integration tests (needs a live stack)

```bash
cd system-1-soc/backend
pip install -r tests/requirements-test.txt

# against the dev environment (see ../../dev/):
BASE_URL=http://localhost:8000 \
OPENSEARCH_URL=http://localhost:9200 \
ADMIN_USERNAME=admin \
ADMIN_PASSWORD='<from bootstrap.sh output, or whatever you changed it to>' \
HONEYSHIELD_API_KEY='<same value as backend/.env>' \
pytest tests/integration/ -v
```

This is the direct answer to "End-to-end integration" and "Detection /
threat intel / correlation engine — needs validation with real events":
each test file injects crafted events straight into OpenSearch (exactly
what Filebeat does — see `tests/integration/conftest.py`'s design-choice
comment for why this is deterministic and fast, complementing rather
than replacing `../../dev/smoke_test.py`'s real-Cowrie-SSH path) and then
polls the real API until the expected result appears:

| File | Proves |
|---|---|
| `test_auth_and_rbac.py` | Login/logout, rate limiting, RBAC boundaries, token tampering rejection, no password leakage — the "Security testing" row |
| `test_detection_pipeline.py` | Brute-force threshold (both sides of it), successful-login+high-risk-command → critical, alert creation |
| `test_threat_intel.py` | Enrichment endpoint works against real public IPs |
| `test_correlation_campaigns.py` | Multi-IP campaign clustering through the real API, timeline reconstruction |
| `test_deception.py` | Canary file access → critical alert; plain directory listing → no false positive |
| `test_esp32.py` | Threshold-based hardware alerting, device API key enforcement |
| `test_reports.py` | PDF/CSV generation and download, with the same magic-bytes validation used during unit testing |

Every test that mutates shared state (creates a user, generates a
report) is written to be safely re-runnable — it either uses a fresh
random IP per test or tolerates "already exists" from a prior run.

## 4. Manual/hardware validation (no test script can fully replace this)

- **ESP32**: flash the firmware, watch the Serial Monitor's `SELF-TEST`
  block on boot — added specifically to catch wiring mistakes
  immediately rather than after weeks of silently-wrong readings. See
  `esp32/README.md`.
- **Suricata/Zeek rule tuning**: needs real or simulated attack traffic
  against System 2 to confirm the custom rules in
  `system-2-honeypot/suricata/local.rules` actually fire as expected —
  no amount of unit testing substitutes for watching `eve.json` during a
  real scan.
- **Network segmentation**: verifying the honeypot VLAN is actually
  isolated from your management network is a network configuration
  check, not something `pytest` can assert.

## Recommended order

1. `dev/bootstrap.sh` + `dev/smoke_test.sh` — prove the pipeline moves
   data at all (see `dev/README.md`)
2. `scripts/evaluate_ai_models.py` — no live stack needed, run it anytime
3. `tests/integration/` — once the dev stack (or real deployment) is up
4. ESP32 self-test on real hardware, once you have a board wired up


