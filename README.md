# UAG Migration Toolkit

Python toolkit for deploying and migrating **Omnissa Unified Access Gateway (UAG)** appliances on vSphere. A faithful Python port of the official `uagdeploy.ps1` / `uagdeploy.psm1` PowerShell scripts (version 25.12.1.0), plus an interactive 1:1 migration wizard.

UAG does not support in-place upgrades -- every "upgrade" is a side-by-side *deploy & migrate*: deploy a new appliance from the new OVA, transfer the configuration, and cut over. This toolkit automates the whole process.

Repository layout:

```
uag/
|-- uag_wizard.py          interactive 1:1 migration wizard (recommended)
|-- uag_deploy.py          Python port of uagdeploy.ps1 (INI -> ovftool deploy)
|-- uag_migrate.py         non-interactive export/import/migrate CLI (automation/CI)
|-- uag_api.py             shared UAG Admin REST API client (port 9443)
|-- uag-example.ini        sample deployment INI
|-- requirements.txt       Python dependencies (wizard only)
|-- ovftool/               (you) portable Broadcom OVF Tool distribution
|-- euc-unified-access-gateway-*.ova   (you) UAG OVA from the Omnissa portal
+-- *.pfx / *.pem          (you) TLS certificate
```

---

## Installation

```
py -m pip install -r requirements.txt
```

| Package       | Used for                                                       |
| ------------- | -------------------------------------------------------------- |
| `pyvmomi`     | vCenter API -- VM listing, discovery, power operations         |
| `questionary` | interactive CLI prompts -- arrow-key selection, text/passwords |
| `colorama`    | coloured output on Windows 10 cmd / PowerShell                 |

`uag_deploy.py`, `uag_migrate.py` and `uag_api.py` use **only the Python standard library** -- the packages above are needed for the wizard only. Python 3.9+ required.

**OVF Tool:** all scripts locate `ovftool` in this order:

```
1. .\ovftool\ovftool.exe        portable distribution next to the scripts
2. .\ovftool.exe                binary directly next to the scripts
3. C:\Program Files\VMware\VMware OVF Tool\ovftool.exe   (Windows install)
4. /usr/bin/ovftool             (Linux install)
5. PATH
```

---

## Workflows

Which workflow do I need?

| Scenario                                                        | Workflow | Tool / command                                   |
| --------------------------------------------------------------- | -------- | ------------------------------------------------ |
| Upgrade one UAG to a new version, keep everything as-is          | A        | `uag_wizard.py` (no arguments)                   |
| Export today, deploy later / on another machine                  | B        | `export` + `uag_wizard.py --settings`            |
| Scripted / repeatable migration, no interaction                  | C        | `uag_migrate.py migrate`                         |
| Full control, one step at a time                                 | D        | `export` -> `deploy` -> `import` -> `health`     |
| Brand-new UAG, no source appliance                               | E        | `uag_deploy.py --ini`                            |
| Several UAGs behind a load balancer                              | F        | rolling: workflow A/C per node                   |
| Disaster recovery preparation                                    | G        | scheduled `export` + workflow B when needed      |
| Fix/replace the configuration of a running appliance             | H        | `import` only                                    |

---

### A. Full interactive 1:1 migration (recommended)

One session, everything discovered and pre-filled, same IP kept -- no load balancer or DNS change needed.

```
py uag_wizard.py
```

```
vCenter login -> pick source VM -> discover (IP/nets/DS/folder) ->
export config + secrets -> shut down old VM -> pick OVA + cert ->
confirm pre-filled parameters -> deploy -> import -> services green
```

Rollback at any point: power the old VM back on (it is never deleted).

---

### B. Deferred restore (export now, deploy later)

Split the migration into two independent sessions -- e.g. export during business hours, deploy in the maintenance window; or export on one workstation and deploy from another.

```
:: session 1 - export only (prompts for the admin password and for
::             secrets the export strips; saves them into the JSON)
py uag_migrate.py export --host uag-old.example.com --out uag_settings.json

:: session 2 - interactive deploy + restore from the JSON
py uag_wizard.py --settings uag_settings.json
::   (identical: py uag_migrate.py deploy --settings uag_settings.json)
```

The restore session asks for vCenter, target cluster/host, OVA, certificate, VM name, IP and passwords -- `uagName` is pre-filled from the JSON. Network settings (IP/mask/gateway/DNS) are not part of a UAG export, so enter them manually. Power off the original appliance first if the new one reuses its IP.

---

### C. One-command non-interactive migration (automation / CI)

The whole chain with a preflight check up front; suitable for scheduled runs.

```
py uag_migrate.py migrate ^
    --old-host uag-old.example.com --new-host 10.0.0.51 ^
    --ini template.ini ^
    --set General.name=UAG-01-NEW --set General.ip0=10.0.0.51 ^
    --pfx-password "***" --vcenter-password "***" ^
    --secrets secrets.json --quiesce-old
```

```
preflight -> export -> deploy (ovftool) -> import -> services green -> quiesce old
```

Preflight verifies ovftool, the OVA, the INI, certificates (incl. PKCS#1) and the old UAG's Admin API before anything is touched; a guard aborts if the new VM name matches the old one.

---

### D. Step-by-step CLI migration (full control)

Same as C, but each stage is a separate command with room for manual checks and JSON edits in between.

```
py uag_migrate.py export  --host uag-old.example.com --out uag_settings.json
:: (review/edit uag_settings.json - thumbprints, ciphers, secrets)
py uag_migrate.py deploy  --ini template.ini --set General.name=UAG-01-NEW
py uag_migrate.py import  --host 10.0.0.51 --settings uag_settings.json
py uag_migrate.py health  --host 10.0.0.51
:: cutover, then:
py uag_migrate.py quiesce --host uag-old.example.com
```

`deploy` targets vCenter (creates the VM via ovftool); `import` targets the new UAG appliance itself (REST API on port 9443).

---

### E. Greenfield deployment (no source appliance)

Deploy a brand-new UAG purely from an INI -- the direct equivalent of the official `uagdeploy.ps1`.

```
py uag_deploy.py --ini uag1.ini --dry-run     # inspect the ovftool command first
py uag_deploy.py --ini uag1.ini
```

Put the full configuration into the INI (`[Horizon]`, `[SSLCert]`, ...), or deploy minimal and push a prepared JSON afterwards with `uag_migrate.py import`.

---

### F. Rolling migration behind a load balancer

With multiple UAGs in a pool, migrate one node at a time so capacity never drops to zero:

```
for each UAG node:
    1. disable the node on the load balancer (or quiesce it)
    2. run workflow A (wizard) or C (migrate) for that node
    3. test a client connection through the new node
    4. re-enable the node on the load balancer
    5. verify pool health before starting the next node
```

One INI template plus `--set General.name=... --set General.ip0=...` per node keeps the fleet consistent.

---

### G. Disaster recovery preparation

Schedule periodic exports; restore on demand with workflow B.

```
:: scheduled task (secrets prompting disabled for unattended runs)
py uag_migrate.py export --host uag01.example.com ^
    --password "***" --out backups\uag01_%DATE%.json --no-secret-prompt

:: DR restore later
py uag_wizard.py --settings backups\uag01_2026-08-13.json
```

Keep the matching OVA and certificate with the backups -- neither is part of the export. Secrets are stripped from unattended exports; store them in your password manager or a `--secrets` file.

---

### H. Configuration-only re-import

Push a (fixed) JSON into an already-running appliance -- no deployment involved:

```
py uag_migrate.py import --host 10.0.0.51 --settings uag_settings.json ^
    [--secrets secrets.json] [--cert-pem chain.pem --key-pem key_pkcs1.pem]
```

Useful for repairing a broken config change, syncing a lab appliance with production settings, or completing a migration whose import step failed (e.g. after fixing SHA-1 thumbprints in the JSON).

---

## `uag_wizard.py` -- Interactive 1:1 migration wizard

Run it with **no arguments** in a real terminal. The wizard walks through the whole migration in eight steps; every value is pre-filled from what it discovers, so a typical run is mostly pressing Enter.

```
py uag_wizard.py
py uag_wizard.py --plain     # classic input() for text prompts (see note below)
```

**Alt+numpad characters (e.g. Alt+64 for `@`) work in ALL inputs.** Text prompts and passwords run in the console's cooked mode (`input()` / `getpass`), where conhost handles Alt+numpad composition -- unlike prompt_toolkit, which discards it. Defaults are still pre-filled as **editable** text: on Windows the default is injected into the console input buffer via `WriteConsoleInputW`, on Linux via `readline.insert_text`, so you can edit it with Backspace as before. Arrow-key *selection* lists (VM, OVA, certificate, port groups, datastore) remain unchanged -- they only need arrows and Enter. `--plain` disables the pre-fill injection and shows defaults in `[brackets]` instead (Enter accepts); Alt codes work in both modes.

**Workflow:**

```
[1/8] Connect to vCenter          hostname, user, password (retry on failure)
[2/8] Select the source UAG VM    name filter + arrow-key list (name, state, IP)
[3/8] Discover source settings    via VMware Tools: per-NIC IP/prefix/port group,
                                  default gateway, DNS, search domains, datastore,
                                  VM folder, cluster/host, datacenter
[4/8] Export the configuration    UAG Admin REST API -> uag_settings_<vm>_<ts>.json
                                  + interactive prompts for secrets the export
                                  never contains (RADIUS shared secret, ...)
[5/8] Shut down the source VM     graceful / hard / skip -- the VM is NEVER
                                  deleted, it stays powered off as rollback
[6/8] Select OVA + certificate    arrow-key lists of *.ova and *.pfx / PEM pairs
                                  found next to the script; PKCS#1 key check;
                                  optional: same cert on the admin interface
[7/8] New appliance parameters    VM name (default <old>-new), uagName (from the
                                  exported JSON), deployment option, per-NIC
                                  port group + IP + netmask, gateway, DNS,
                                  datastore, folder, cluster -- ALL pre-filled
                                  from step 3; root/admin passwords with
                                  confirmation and UAG password-policy check
[8/8] Deploy + restore            summary table -> confirm -> ovftool deploy
                                  (certificate deployed with the appliance) ->
                                  wait for the Admin API -> re-read the JSON
                                  from disk -> 1:1 import -> edge services green
```

**Key behaviours:**

- The new appliance keeps the **same IP address** -- no load balancer or DNS change is needed. The old VM must therefore be down before the deployment starts (step 5).
- The migration JSON is **re-read from disk right before the import**. You can edit the file while ovftool is running (e.g. add a RADIUS shared secret); invalid JSON triggers a fix-and-retry prompt instead of a crash.
- The `uagName` prompt is pre-filled from `systemSettings.uagName` in the exported JSON (falls back to the VM name).
- Yes/no questions require **Enter** to confirm -- typing `y`/`n` alone does not submit.
- Root and admin passwords are validated against the UAG password policy (min 8 chars, upper + lower + digit + special) before the deployment starts.
- If the new VM name equals the source VM name, the wizard warns that `ovftool --overwrite` would **delete** the old VM and asks for explicit confirmation.
- On any failure after the source VM was powered off, roll back by simply powering the old VM back on -- it is never modified.

**Restore mode (`--settings`):** deploy a new appliance from an existing migration JSON without touching any source VM -- useful for re-deployments, DR restores, or when the export was done earlier with `uag_migrate.py export`:

```
py uag_wizard.py --settings uag_settings.json
py uag_migrate.py deploy --settings uag_settings.json     # same thing
```

The wizard then runs a shortened flow: connect to vCenter -> load and validate the JSON (prompting for any secrets the export stripped, saving them back into the file) -> pick the target datacenter/cluster/host from an arrow-key list -> pick the OVA and certificate -> answer the deployment questions (uagName pre-filled from the JSON; IP/network/datastore chosen from the target host's inventory) -> deploy, re-read the JSON from disk, import, and verify the edge services. Make sure the IP you assign is free -- the original appliance, if any, must be powered off.

**Secrets and files that can never be migrated automatically** (the UAG export does not contain them): appliance root/admin passwords, RADIUS/SAML shared secrets, the TLS server certificate, keytab files. The wizard prompts for all of them except keytabs, which must be re-uploaded in the Admin UI.

**Dependencies:** `pyvmomi`, `questionary`, `colorama`

---

## `uag_deploy.py` -- INI-based deployment (uagdeploy.ps1 port)

Deploys a UAG OVA to vSphere from an INI file in the same format the official PowerShell script and the UAG Admin UI INI export use.

```
py uag_deploy.py --ini uag1.ini
py uag_deploy.py --ini uag1.ini --dry-run
py uag_deploy.py --ini uag1.ini --root-password "..." --admin-password "..." ^
    --ceip-enabled no --vcenter-password "..." --non-interactive
```

**Fidelity to the original (25.12.1.0):**

- `settingsJSON` is passed via `--configFile` (a temporary `.cfg`, chunked into 65535-char `prop:settingsJSON-0..N` entries, 16x65535 limit). The file contains certificates and secrets and is always deleted after the run.
- Direct OVF properties 1:1: `--prop:DNS` (uppercase), `--prop:forceNetmask{n}`, `passwordPolicy*`, `adminPasswordPolicy*`, `routes0-2`, `policyRouteGateway0-2`, `forwardrules`, `ssh*`, `dsComplianceOS`, `tlsPortSharingEnabled`, `configURL`/`configKey`, `adminCsrSubject`/`SAN`, `commandsFirstBoot`/`EveryBoot`, `gatewaySpec`. `ceipEnabled=False` is sent only when CEIP is disabled (the OVF default is True).
- NIC modes per `GetNetOptions`: all 11 `ipMode` combinations (STATICV4, DHCPV4, STATICV6, STATICV4+STATICV6, ...) with default derivation from the presence of `ip{n}` / `v6ip{n}`.
- `deploymentOption` defaults to `onenic`; aliases `onenic-L` -> `onenic-large` etc.
- Certificates inside `settingsJSON`: `[SSLCert]`/`[SSLCertAdmin]` with `pemCerts`+`pemPrivKey` -> `certificateWrapper{,Admin}`, with `pfxCerts` -> `pfxCertStoreWrapper{,Admin}` (base64 + password + optional `pfxCertAlias`). **The PEM private key must be PKCS#1** (`BEGIN RSA PRIVATE KEY`); convert PKCS#8 with `openssl rsa -in key.pem -traditional -out key_pkcs1.pem`.
- Validation as in the original: `ds=` required, VM name <= 32 chars, OVA verified via `ovftool --verifyOnly` (checks for the `euc-unified-access-gateway-*.vmdk`), SHA-1 thumbprints rejected.
- `[Horizon]` -> VIEW edge service (strips `:443` from `proxyDestinationUrl`, sanitises thumbprints, `xmlSigningSwitch` default AUTO, `hostEntry1..N` -> `hostEntries`, XML API signing PEM/PFX), `[WebReverseProxy]`/`[WebReverseProxy1..99]` -> WEB_REVERSE_PROXY, `[RADIUSAuth]` -> radius-auth (shared secret prompted -- it is never present in an export).
- Sections not handled by the port (SecurID, SAML/IDP, Kerberos, SNMP, HA, DevicePolicy, JWT, ...) are reported with a warning. For those, deploy a minimal appliance and import the full JSON via `uag_migrate.py import`.

**All options:**

| Flag                     | Default   | Description                                                    |
| ------------------------ | --------- | -------------------------------------------------------------- |
| `--ini`                  | `uag.ini` | Path to the deployment INI                                     |
| `--ovftool`              | auto      | Explicit path to the ovftool binary                            |
| `--root-password`        | prompted  | Appliance root password                                        |
| `--admin-password`       | prompted  | Admin UI / REST password (empty = no admin interface)          |
| `--ceip-enabled`         | prompted  | `yes` / `no`                                                   |
| `--pfx-password`         | prompted  | Password for the PFX referenced in `[SSLCert]`                 |
| `--vcenter-password`     | --        | Injected into the `target=` vi:// URL when missing             |
| `--no-ssl-verify`        | off       | Equivalent of `-noSSLVerify`                                   |
| `--disable-verification` | off       | Equivalent of `-disableVerification`                           |
| `--non-interactive`      | off       | No prompts; missing secrets stay empty                         |
| `--dry-run`              | off       | Print the (redacted) ovftool command without running it        |

Passwords and the vi:// URL password are always masked in the printed command.

**Dependencies:** stdlib only

---

## `uag_migrate.py` -- Non-interactive migration CLI

Scriptable counterpart of the wizard for automation and CI. Subcommands:

| Subcommand | Purpose                                                             |
| ---------- | ------------------------------------------------------------------- |
| `export`   | Download the configuration from the old UAG (JSON); detects services whose secrets are stripped from the export and prompts for them interactively, saving them into the JSON (`--no-secret-prompt` disables) |
| `deploy`   | Deploy a new UAG from an INI (with preflight check)                 |
| `import`   | Import the JSON into the new UAG, patch secrets, upload the TLS cert |
| `health`   | Print `/monitor/stats` and a clear `Green: YES/NO` verdict          |
| `quiesce`  | Put the old UAG into quiesce mode (sessions drain)                  |
| `migrate`  | The whole chain: preflight -> export -> deploy -> import -> health -> quiesce |

**One-command migration:**

```
py uag_migrate.py migrate ^
    --old-host uag-old.example.com --new-host 10.0.0.51 ^
    --ini template.ini ^
    --set General.name=UAG-HZN-01-NEW --set General.ip0=10.0.0.51 ^
    --pfx-password "***" --vcenter-password "***" ^
    --secrets secrets.json --quiesce-old
```

**Preflight** runs before anything is touched: ovftool located, OVA exists and looks like a UAG image, INI has `source=`/`ds=`/`target=`, certificate files exist, PEM key is PKCS#1, and the old UAG responds on its Admin API. A safety guard aborts when the new VM name matches the old one (`ovftool --overwrite` would delete it).

**`--set Section.key=value`** overrides template INI values without modifying the template (a `*.runtime.ini` copy is created) -- one template serves all appliances and repeated migrations.

**`--secrets secrets.json`** patches secrets into the exported JSON before the import; the format is a flat map of JSON paths to values:

```
{ "authMethodSettingsList.authMethodSettingsList[0].sharedSecret": "S3cret!" }
```

**Selected options (migrate):**

| Flag                    | Default    | Description                                             |
| ----------------------- | ---------- | ------------------------------------------------------- |
| `--old-host`            | required   | Old UAG management IP/FQDN                              |
| `--new-host`            | required   | New UAG IP (ip0 from the INI)                           |
| `--ini`                 | required   | Deployment INI template                                 |
| `--set`                 | repeatable | INI override, `Section.key=value`                       |
| `--secrets`             | --         | JSON file with secrets to patch before the import       |
| `--cert-pem / --key-pem`| --         | Upload a PEM cert via REST (not needed with `[SSLCert]`) |
| `--cert-interface`      | `internet` | `internet` / `admin` / `internetAndAdmin`               |
| `--quiesce-old`         | off        | Quiesce the old UAG after a successful import           |
| `--force`               | off        | Continue despite preflight failures / empty secrets     |
| `--wait`                | `600`      | Seconds to wait for the Admin API / green services      |

**Exit codes:** `0` success; non-zero per failed stage (export `1`, deploy `2`, empty secrets `3`, import `4`, services not green `5`).

**Dependencies:** stdlib only

---

## `uag_api.py` -- UAG Admin REST API client

Shared library used by the wizard and the migrate CLI. Stdlib only.

| Method                          | Endpoint / purpose                                       |
| ------------------------------- | -------------------------------------------------------- |
| `export_settings()`             | `GET /rest/v1/config/settings`                           |
| `import_settings(dict)`         | `PUT /rest/v1/config/settings`                           |
| `upload_tls_cert_pem(...)`      | `PUT /rest/v1/config/certs/ssl/{interface}`              |
| `get_edge_status()`             | `GET /rest/v1/monitor/stats` (returns XML -- see note)   |
| `edge_status_is_green(stats)`   | Parses the XML/dict; green = RUNNING/Reachable, no ERROR/DOWN/NOT_REACHABLE/STOPPED |
| `wait_until_ready(...)`         | Polls the API after deploy/reboot                        |
| `wait_for_edge_services_green()`| Polls until the services are healthy                     |
| `set_quiesce_mode(bool)`        | `PUT /rest/v1/config/system` with `quiesceMode`          |

Note: `/monitor/stats` serves **XML only** -- requesting it with `Accept: application/json` yields `406 Not Acceptable`. The client sends `Accept: application/xml, application/json;q=0.9, */*` and parses the XML with ElementTree.

Endpoint paths may differ slightly between UAG versions; verify against `https://<UAG>:9443/rest/swagger.yaml`.

---

## What is never migrated automatically

The UAG configuration export intentionally omits sensitive material. Supply these yourself:

| Item                            | How this toolkit handles it                              |
| ------------------------------- | -------------------------------------------------------- |
| Appliance root/admin passwords  | Set at deploy time (wizard step 7 / CLI flags)           |
| TLS server certificate          | `[SSLCert]` at deploy time, or REST upload after import  |
| RADIUS/SAML shared secrets      | Wizard prompts / `--secrets` file / edit the JSON        |
| Keytab files (Kerberos)         | Re-upload manually in the Admin UI after the import      |

The wizard's secret detector skips false positives such as `radiusCustomPassphraseHint` (a login-page UI text, not a secret).

---

## Rollback

The source VM is only powered off, never modified or deleted. If anything fails at any point, power the old VM back on and you are exactly where you started. Delete it manually once the new appliance is verified.

---

## Compatibility

- Python 3.9+ -- tested on 3.12
- Omnissa UAG 25.12 (INI/OVF logic ported from uagdeploy 25.12.1.0); the REST flow works with earlier 4.x/24xx releases as well
- Broadcom OVF Tool 4.3+ (portable or installed)
- vCenter 7.0+ / ESXi 7.0+
- Windows 10/11 cmd and PowerShell, Linux, macOS
- Passwords are prompted via `getpass`/`questionary`, never echoed, and masked in printed ovftool commands

---

## Requirements summary

| Script           | Extra packages                        |
| ---------------- | ------------------------------------- |
| `uag_wizard.py`  | `pyvmomi`, `questionary`, `colorama`  |
| `uag_deploy.py`  | --                                    |
| `uag_migrate.py` | --                                    |
| `uag_api.py`     | --                                    |

---

## License

MIT
