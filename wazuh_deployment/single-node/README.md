# Wazuh Single-Node Docker Deployment

All-in-one Wazuh stack (manager + indexer + dashboard) used as the SIEM backend for this project's Agentic Analyst (see the repo root `CLAUDE.md` design doc). Deployed via `docker-compose.yml`: one `wazuh.manager`, one `wazuh.indexer`, one `wazuh.dashboard` container, plus two helper containers that seed synthetic demo logs (see [Demo log scenario](#demo-log-scenario)).

## Directory layout

```
single-node/
├── docker-compose.yml            # active stack (manager, indexer, dashboard, log seeding)
├── docker-compose_ori.yml        # unmodified upstream wazuh-docker compose, kept for reference/diffing
├── generate-indexer-certs.yml    # one-shot cert generator, run before first `docker compose up`
├── config/
│   ├── certs.yml                 # node list consumed by the cert generator
│   ├── wazuh_cluster/wazuh_manager.conf   # ossec.conf mounted into the manager
│   ├── wazuh_indexer/             # opensearch.yml + internal_users.yml
│   ├── wazuh_dashboard/           # opensearch_dashboards.yml + wazuh.yml
│   └── wazuh_indexer_ssl_certs/   # generated demo certs — TRACKED IN GIT, keys included (see note below)
├── decoders/local_decoder.xml    # custom decoders: ocserv VPN, Mimecast SIEM logs
├── rules/local_rules.xml         # custom rules: ocserv VPN, Mimecast (with MITRE mappings)
└── sample-logs/                  # synthetic demo logs, seeded into the manager on startup
```

## Prerequisites

- Docker with Compose v2 (`docker compose ...`, not `docker-compose ...`)
- On macOS: enough headroom for the indexer's JVM heap (`OPENSEARCH_JAVA_OPTS`, currently capped at `-Xms1g -Xmx1g` in `docker-compose.yml`) on top of whatever else is running — see the root design doc §7.1 if this stack is colocated with the local LLM.

## Quick start

1) Generate the indexer/dashboard/manager TLS certs (one-time, or whenever `config/certs.yml` changes):
```
docker compose -f generate-indexer-certs.yml run --rm generator
```
2) Start the stack:
```
docker compose up        # foreground
docker compose up -d     # background
```

First boot takes ~1 minute (depends on Docker host) since the indexer has to initialize indices and index patterns for the first time. Subsequent starts are faster since volumes persist.

3) Tear down:
```
docker compose down       # stop, keep data volumes
docker compose down -v    # stop and wipe all volumes (indexer data, manager state, seeded logs) — start clean
```

## Accessing the stack

| Service | URL | Credentials | Notes |
|---|---|---|---|
| Dashboard | `https://localhost` (mapped from container port 5601) | `admin` / `SecretPassword` (indexer-backed login) | self-signed cert — expect a browser warning |
| Indexer API | `https://localhost:9200` | `admin` / `SecretPassword` | OpenSearch REST API, `wazuh-alerts-*` indices |
| Manager API | `https://localhost:55000` | `wazuh-wui` / `MyS3cr37P450r.*-` | JWT bearer auth, see `docker-compose.yml` env vars |
| Manager agent enrollment | `localhost:1514` (tcp), `localhost:1515` (tcp), `localhost:514` (udp) | — | for real Wazuh agents / syslog forwarders, not needed for the seeded demo logs |

All credentials above are demo defaults baked into `docker-compose.yml` for this local POC — **not real secrets**, but still rotate them before pointing this stack at anything beyond a local demo.

> **The generated certificates are committed, private keys included.** `config/wazuh_indexer_ssl_certs/` tracks `root-ca.key`, `root-ca-manager.key`, `admin-key.pem` and the indexer/manager/dashboard keys; `config/wazuh_indexer/internal_users.yml` carries six bcrypt hashes. None are gitignored. They exist so the stack comes up from a clean clone without a cert-generation step. If this repository is public, treat that key material as burned: do not reuse it anywhere, and regenerate before the stack is reachable from anything but localhost (`docker compose -f generate-indexer-certs.yml run --rm generator`).

## Demo log scenario

`sample-logs/` and the matching `decoders/`/`rules/` files simulate a small, self-contained incident across multiple log sources for a fictitious `victimcorp.com`, wired for both true-positive and false-positive test cases:

| Sample log | Format | Source | Custom decoder/rules? |
|---|---|---|---|
| `auth.log` | syslog | SSH auth (successful login pattern) | uses stock Wazuh SSH rules |
| `auth-fp.log` | syslog | SSH auth (benign-looking counterpart, false-positive test case) | uses stock Wazuh SSH rules |
| `vpn.log` | syslog | `ocserv` VPN connect/MFA/NAT-assignment/disconnect | custom `ocserv` decoders + rules `100050`–`100054` |
| `windows_security.json` | json | Windows Security event log (logon events) | uses stock Wazuh Windows rules |
| `windows_security_fp.json` | json | Windows Security event log (false-positive counterpart) | uses stock Wazuh Windows rules |
| `mimecast_sample.log` | syslog (pipe-delimited) | Mimecast email security (impersonation/malicious-link/attachment events) | custom `mimecast`/`mimecast-siem-logs` decoders + rules `106000`–`106015`, each mapped to MITRE ATT&CK techniques (T1566, T1114, T1036, T1204.002, …) |
| `endpoint_alerts_sample.json` | json | Sysmon endpoint alert (file creation) | uses stock Sysmon rules |
| `dev_ai_tools.json` | json | Sysmon process creation — AI coding assistants (Cursor, VS Code, Claude Code CLI, Windows Terminal) spawning `powershell.exe -EncodedCommand` on six developer laptops | custom rule `100075` |
| `mimecast_noise.log` | syslog (pipe-delimited) | 35 benign held-for-review messages — newsletters, SaaS notifications, legitimate vendor invoices, recruiter outreach, impersonation false positives on real partner lookalikes | reuses rule `106001`, no new rules |
| `auth_noise.log` | syslog | 20 routine SSH logons from known users on documentation-range source IPs | uses stock Wazuh SSH rules |
| `windows_security_noise.json` | json | 15 routine Windows 4624 logons from internal workstations | reuses rule `100061`, no new rules |

The false-positive pairs (`*-fp.*`) exist so the Agentic Analyst's investigation logic can be exercised against near-identical alerts that should and shouldn't escalate — useful for evaluating precision, not just recall.

The three `*_noise.*` files serve a different purpose: they give the **email** and **login** use cases the benign-flood shape `dev_ai_tools.json` already gives encoded PowerShell, so all three of the talk's high-volume alert classes have a realistic signal-to-noise ratio rather than a lone incident chain. Each flood was verified through `wazuh-logtest` to fire the **same rule at the same level** as the case it surrounds — `106001`/level 5 around the phishing chain's held message, `5715`/level 3 around the `45.146.164.110` SSH success, `100061`/level 3 around the mrahman VPN false positive. That property is what makes them gradeable: the SIEM contributes no separation, so every bit of discrimination has to come from the analyst. See `docs/superpowers/specs/2026-08-14-local-model-selection-benchmark-design.md`.

`dev_ai_tools.json` is a second, independent scenario rather than part of the `victimcorp` incident: 40 benign encoded-PowerShell executions from developer tooling plus **one** that is not benign (parent `wscript.exe`, decoding to a downloader aimed at `45.146.164.110`, the same address that logs in successfully in `auth.log`). Every one of the 41 matches the same rule at the same level, so the SIEM alone cannot separate them — the only discriminating evidence is the parent image, which rule `100075` interpolates into its description on purpose. The base64 is genuine UTF-16LE, so `-EncodedCommand` payloads decode to real commands (`git status --porcelain`, `npm run build`, …).

### How the logs get into the manager

Direct bind-mounting `sample-logs/` straight into the manager container did not reliably trigger `logcollector` to pick up the files (mount ordering / inode issue), so seeding is split across two helper containers instead:

1. **`seed-sample-logs`** — runs once at startup, creates empty placeholder files (matching `sample-logs/`'s structure) inside the `sample_logs_data` volume that `wazuh.manager` mounts at `/var/ossec/logs/sample-logs`, and fixes permissions so the manager can read them.
2. **`log-pusher`** — waits for the manager to start, then appends each sample log's lines into those files one at a time (with a short delay between lines) so `logcollector` sees them as live tail growth rather than a single bulk write.

`config/wazuh_cluster/wazuh_manager.conf` has a matching `<localfile>` block per sample log path under `/var/ossec/logs/sample-logs/`, so once the lines land, they flow through the same decoder → rule → indexer pipeline as a real agent's logs.

## Adding new mock logs, decoders, or rules

1. Add the log content (syslog or JSON) to an existing file in `sample-logs/`, or as a new file — `seed-sample-logs` and `log-pusher` both enumerate the directory with `find`, so a new file is copied and tailed automatically with no compose changes. What is *not* automatic is ingestion: a new file needs a matching `<localfile>` block in `config/wazuh_cluster/wazuh_manager.conf`, plus a fresh `down -v && up` for the manager to reload its config.
2. Add rules to `rules/local_rules.xml` (reserve local rule IDs ≥ 100050 per the file's own convention; the pre-existing `106000+` range is used by the Mimecast rules).
3. Add decoders to `decoders/local_decoder.xml`.
4. Restart the stack for the manager to reload `etc/rules`/`etc/decoders` — check `docker compose logs wazuh.manager` for a decoder/rule syntax error if alerts don't appear as expected.

## `docker-compose.yml` vs `docker-compose_ori.yml`

`docker-compose_ori.yml` is the unmodified upstream `wazuh-docker` single-node compose file, kept side-by-side purely as a reference baseline — diff against it to see exactly what this project changed (the `seed-sample-logs`/`log-pusher` containers, the `sample_logs_data` volume, and the decoder/rule/manager-conf mounts). It is not meant to be run directly; `docker-compose.yml` is the one actually deployed.

## Troubleshooting

- **Dashboard/indexer refuses connection right after `up`**: the indexer is still initializing on first boot — give it the ~1 minute mentioned above and check `docker compose logs wazuh.indexer`.
- **Seeded alerts never show up in the dashboard**: confirm `log-pusher` finished (`docker compose logs log-pusher` should end with `pushed-all`), then check `docker compose logs wazuh.manager` for decoder/rule parse errors.
- **Cert errors after editing `config/certs.yml`**: re-run the cert generator step and then `docker compose down -v && docker compose up` — stale certs in the named volumes won't be replaced by just restarting.
- **Pinned image version**: all three services run `4.14.6`. Bump the tag in `docker-compose.yml` (not `docker-compose_ori.yml`) to upgrade, and re-check `config/*.yml` against the new version's defaults.
