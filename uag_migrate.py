#!/usr/bin/env python3
"""
uag_migrate.py - Orchestrates an Omnissa UAG migration to a new version
(side-by-side "deploy & migrate", because UAG does not support in-place
upgrades).

Subcommands:
    export    - downloads the configuration from the old UAG (JSON)
    deploy    - deploys a new UAG (calls uag_deploy.py / ovftool with an INI)
    import    - imports the JSON configuration into the new UAG + secrets/cert
    health    - checks Admin API availability and edge service status
    quiesce   - puts the old UAG into quiesce mode (sessions drain)
    migrate   - the whole chain: export -> deploy -> import -> health -> quiesce

Examples:
    python3 uag_migrate.py export  --host uag-old.firma.cz --out uag_settings.json
    python3 uag_migrate.py deploy  --ini uag-new.ini
    python3 uag_migrate.py import  --host 10.0.0.50 --settings uag_settings.json \
        --cert-pem cert_chain.pem --key-pem key.pem
    python3 uag_migrate.py migrate --old-host uag-old.firma.cz --ini uag-new.ini \
        --new-host 10.0.0.50 --cert-pem cert_chain.pem --key-pem key.pem

IMPORTANT (UAG export limitation):
    The JSON export DOES NOT contain: passwords, RADIUS/SAML shared secrets,
    the TLS certificate (PFX/PEM), keytab files. These must be supplied again -
    the script warns about missing items and can upload the certificate via
    the REST API.
"""

from __future__ import annotations

import argparse
import getpass
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from uag_api import UagClient, UagApiError, load_pem, load_json, save_json

SECRET_HINTS = (
    "password", "secret", "sharedsecret", "passphrase",
    "privatekey", "keytab", "clientsecret",
)

# Keys the heuristic would match but which are NOT secrets (UI texts and
# toggles) - e.g. radiusCustomPassphraseHint is the "Login page passphrase
# hint": text shown to end users in the Horizon Client, not sensitive.
NOT_SECRETS = ("hint", "label", "expiration", "policy", "enabled",
               "protected", "required")


def find_missing_secrets(settings: dict) -> list[str]:
    """Walks the exported JSON and finds keys that look like emptied secrets."""
    hits: list[str] = []

    def walk(node, path=""):
        if isinstance(node, dict):
            for k, v in node.items():
                p = f"{path}.{k}" if path else k
                kl = k.lower()
                if (any(h in kl for h in SECRET_HINTS)
                        and not any(x in kl for x in NOT_SECRETS)
                        and v in ("", None)):
                    hits.append(p)
                walk(v, p)
        elif isinstance(node, list):
            for i, item in enumerate(node):
                walk(item, f"{path}[{i}]")

    walk(settings)
    return hits


def make_client(host: str, user: str, password: str | None) -> UagClient:
    pw = password or getpass.getpass(f"Admin password for {host}: ")
    return UagClient(host=host, admin_user=user, admin_password=pw)


# ----------------------------------------------------------------- commands
def cmd_export(args) -> int:
    c = make_client(args.host, args.user, args.password)
    print(f"[..] Exporting configuration from {args.host} ...")
    settings = c.export_settings()
    out = Path(args.out or f"uag_settings_{args.host}_{datetime.now():%Y%m%d_%H%M%S}.json")
    save_json(str(out), settings)
    print(f"[OK] Saved: {out}")

    missing = find_missing_secrets(settings)
    if missing:
        print("\n[!] The source UAG has services configured whose secrets are "
              "never included in the export:")
        for m in missing:
            print(f"    - {m}")
        interactive = sys.stdin.isatty() and not getattr(args, "no_secret_prompt",
                                                         False)
        if interactive:
            print("    Enter them now so the migration JSON restores the "
                  "complete configuration (Enter = leave empty):")
            entered = 0
            for key_path in missing:
                val = getpass.getpass(f"      value for {key_path}: ")
                if val:
                    set_by_path(settings, key_path, val)
                    entered += 1
            if entered:
                save_json(str(out), settings)
                print(f"[OK] {entered} secret(s) saved into {out.name}.")
                print(f"[!] {out.name} now contains secrets - delete the file "
                      f"after the migration.")
        else:
            print("    Supply them later via a --secrets file or by editing "
                  "the JSON before the import.")
    print("[!] The export never contains the TLS certificate or keytabs - have your PEM/PFX/keytab ready.")
    return 0


def set_by_path(settings: dict, path: str, value: str) -> None:
    """Sets a value in the exported JSON by its dotted path with [n] indices
    (the same paths find_missing_secrets reports)."""
    import re as _re
    tokens = _re.findall(r"([^.\[\]]+)|\[(\d+)\]", path)
    node = settings
    flat = [t[0] if t[0] else int(t[1]) for t in tokens]
    for t in flat[:-1]:
        node = node[t]
    node[flat[-1]] = value


def apply_ini_overrides(ini_path: str, sets: list[str] | None) -> str:
    """
    Creates a runtime copy of the INI with --set Section.key=value overrides.
    Lets one template be reused for multiple UAGs / migrations
    (typically --set General.name=... --set General.ip0=... --set General.source=...).
    Returns the path to the runtime INI (the original stays untouched).
    """
    if not sets:
        return ini_path
    import configparser
    cp = configparser.ConfigParser(interpolation=None, strict=False)
    cp.optionxform = str
    with open(ini_path, encoding="utf-8-sig") as f:
        cp.read_file(f)
    for item in sets:
        if "=" not in item or "." not in item.split("=", 1)[0]:
            sys.exit(f"ERROR: --set expects the format Section.key=value (got: {item})")
        key_path, value = item.split("=", 1)
        section, key = key_path.split(".", 1)
        if section not in cp:
            cp.add_section(section)
        cp[section][key] = value
    runtime = Path(ini_path).with_suffix(".runtime.ini")
    with open(runtime, "w", encoding="utf-8") as f:
        cp.write(f)
    print(f"[OK] Runtime INI with overrides: {runtime}")
    return str(runtime)


def preflight(ini_path: str, old_host: str | None, old_client_factory=None,
              cert_pem: str | None = None, key_pem: str | None = None) -> list[str]:
    """
    Checks BEFORE the migration/deploy starts so nothing fails halfway:
      - ovftool found, INI parseable, the OVA file exists and looks like a UAG,
      - certificates (INI [SSLCert] and --cert-pem/--key-pem) exist,
      - the PEM key is PKCS#1 (required by the deploy script),
      - the old UAG responds on the Admin API (migration only).
    Returns a list of problems (empty = OK).
    """
    import configparser
    problems: list[str] = []

    # ovftool (portable ./ovftool/ next to the scripts, installation, PATH)
    try:
        import uag_deploy as _ud
        if not _ud.locate_ovftool():
            problems.append("ovftool not found (portable './ovftool/' next to "
                            "the scripts, Program Files, or PATH)")
    except ImportError:
        problems.append("uag_deploy.py is missing next to uag_migrate.py")

    # INI + OVA
    cp = configparser.ConfigParser(interpolation=None, strict=False)
    cp.optionxform = str
    try:
        with open(ini_path, encoding="utf-8-sig") as f:
            cp.read_file(f)
    except OSError:
        problems.append(f"cannot read the INI file {ini_path}")
        cp = None
    if cp:
        source = cp.get("General", "source", fallback="").strip()
        if not source:
            problems.append("[General] source= is missing in the INI")
        elif not Path(source).is_file():
            problems.append(f"OVA file does not exist: {source}")
        elif "euc-unified-access-gateway" not in Path(source).name:
            problems.append(f"OVA does not look like a UAG image: {Path(source).name}")
        if not cp.get("General", "ds", fallback="").strip():
            problems.append("[General] ds= is missing in the INI")
        if not cp.get("General", "target", fallback="").strip():
            problems.append("[General] target= is missing in the INI")
        # certificates referenced by the INI
        for section in ("SSLCert", "SSLcert", "SSLCertAdmin", "SSLcertAdmin"):
            if cp.has_section(section):
                for key in ("pfxCerts", "pemCerts", "pemPrivKey"):
                    v = cp.get(section, key, fallback="").strip()
                    if v and not Path(v).is_file():
                        problems.append(f"[{section}] {key}={v} - file does not exist")
                pem_key = cp.get(section, "pemPrivKey", fallback="").strip()
                if pem_key and Path(pem_key).is_file():
                    if "BEGIN RSA PRIVATE KEY" not in Path(pem_key).read_text(errors="replace"):
                        problems.append(
                            f"[{section}] pemPrivKey is not PKCS#1 - convert with: "
                            f"openssl rsa -in {pem_key} -traditional -out key_pkcs1.pem")

    # certificates for the REST import
    for label, path in (("--cert-pem", cert_pem), ("--key-pem", key_pem)):
        if path and not Path(path).is_file():
            problems.append(f"{label} {path} - file does not exist")

    # the old UAG is reachable
    if old_host and old_client_factory:
        try:
            old_client_factory().get_system_health()
        except Exception as e:
            from uag_api import describe_error as _de
            problems.append(f"Old UAG {old_host} does not respond on the Admin API: {_de(e)}")

    return problems


def cmd_deploy(args) -> int:
    # --settings: interactive restore mode - delegate to the wizard, which
    # asks for vCenter/network/VM name/IP/passwords with pre-filled prompts
    # and restores the configuration from the given migration JSON.
    if getattr(args, "settings", None):
        wizard = Path(__file__).parent / "uag_wizard.py"
        if not wizard.is_file():
            print("ERROR: uag_wizard.py is required for --settings restore "
                  "mode - keep it next to uag_migrate.py.", file=sys.stderr)
            return 2
        return subprocess.run(
            [sys.executable, str(wizard), "--settings", args.settings]
        ).returncode

    if not args.ini:
        print("ERROR: either --ini (INI-based deploy) or --settings "
              "(interactive restore mode) is required.", file=sys.stderr)
        return 2
    ini = apply_ini_overrides(args.ini, getattr(args, "set", None))
    problems = preflight(ini, None)
    if problems:
        print("[!] Preflight check failed:")
        for p in problems:
            print(f"    - {p}")
        if not getattr(args, "force", False):
            print("    Fix the issues, or run with --force.")
            return 2
    cmd = [sys.executable, str(Path(__file__).parent / "uag_deploy.py"),
           "--ini", ini, "--ceip-enabled", "no"]
    if args.root_password:
        cmd += ["--root-password", args.root_password]
    if args.admin_password:
        cmd += ["--admin-password", args.admin_password]
    if args.vcenter_password:
        cmd += ["--vcenter-password", args.vcenter_password]
    if getattr(args, "pfx_password", None):
        cmd += ["--pfx-password", args.pfx_password]
    if getattr(args, "no_ssl_verify", False):
        cmd += ["--no-ssl-verify"]
    return subprocess.run(cmd).returncode


def cmd_import(args) -> int:
    c = make_client(args.host, args.user, args.password)

    if not c.wait_until_ready(max_wait_s=args.wait):
        print(f"ERROR: the Admin API on {args.host} is not reachable.", file=sys.stderr)
        return 2

    settings = load_json(args.settings)

    # optional secret patching from a companion file {"path.key": "value"}
    if args.secrets:
        patches = load_json(args.secrets)
        applied = 0

        def patch(node, path=""):
            nonlocal applied
            if isinstance(node, dict):
                for k in list(node.keys()):
                    p = f"{path}.{k}" if path else k
                    if p in patches:
                        node[k] = patches[p]
                        applied += 1
                    patch(node[k], p)
            elif isinstance(node, list):
                for i, item in enumerate(node):
                    patch(item, f"{path}[{i}]")

        patch(settings)
        print(f"[OK] Patched {applied} secrets from {args.secrets}")

    missing = find_missing_secrets(settings)
    if missing and not args.force:
        print("[!] The configuration still contains empty secrets:")
        for m in missing:
            print(f"    - {m}")
        print("    Continue with --force, or supply them via a --secrets file.")
        return 3

    print(f"[..] Importing configuration into {args.host} ...")
    try:
        c.import_settings(settings)
    except UagApiError as e:
        print(f"Import ERROR: {e}", file=sys.stderr)
        print("Tip: check SHA-1 vs SHA-256 thumbprints and legacy cipher suites in the JSON.",
              file=sys.stderr)
        return 4
    print("[OK] Configuration imported.")

    if args.cert_pem and args.key_pem:
        print("[..] Uploading the TLS certificate ...")
        c.upload_tls_cert_pem(load_pem(args.key_pem), load_pem(args.cert_pem),
                              interface=args.cert_interface)
        print("[OK] Certificate uploaded.")
    else:
        print("[!] TLS certificate was not uploaded (missing --cert-pem/--key-pem) - upload it manually.")

    if c.wait_for_edge_services_green(max_wait_s=args.wait):
        return 0
    print("[!] Edge services are not green - check the Admin UI.", file=sys.stderr)
    return 5


def cmd_health(args) -> int:
    c = make_client(args.host, args.user, args.password)
    ok = c.wait_until_ready(max_wait_s=30, interval_s=5)
    if not ok:
        return 2
    stats = c.get_edge_status()
    if isinstance(stats, str):
        print(stats)   # /monitor/stats returns XML
    else:
        print(json.dumps(stats, indent=2, ensure_ascii=False))
    print("\nGreen:", "YES" if c.edge_status_is_green(stats) else "NO")
    return 0


def cmd_quiesce(args) -> int:
    c = make_client(args.host, args.user, args.password)
    c.set_quiesce_mode(True)
    print(f"[OK] {args.host} is in quiesce mode - it accepts no new sessions, "
          f"existing ones drain. Power off/delete the VM once drained.")
    return 0


def cmd_migrate(args) -> int:
    """The whole migration chain: preflight -> export -> deploy -> import -> health -> quiesce."""
    old_pw = args.old_password or getpass.getpass(f"Admin password of the OLD UAG {args.old_host}: ")

    # 0) Preflight - verify EVERYTHING before the first step (INI, OVA,
    #    ovftool, certificates, old UAG reachability) so nothing fails halfway.
    ini = apply_ini_overrides(args.ini, getattr(args, "set", None))
    problems = preflight(
        ini, args.old_host,
        old_client_factory=lambda: UagClient(host=args.old_host, admin_user=args.user,
                                             admin_password=old_pw),
        cert_pem=args.cert_pem, key_pem=args.key_pem)
    if problems:
        print("[!] Preflight check failed:")
        for p in problems:
            print(f"    - {p}")
        if not args.force:
            print("    Fix the issues, or run with --force.")
            return 2
    else:
        print("[OK] Preflight: ovftool, OVA, INI, certificates and the old UAG are all fine.")

    new_pw = args.new_password or getpass.getpass(
        "Admin password of the NEW UAG (will be set at deploy time): ")

    # Safety guard: ovftool with --overwrite deletes a VM with the same name!
    import configparser
    cpi = configparser.ConfigParser(interpolation=None, strict=False)
    cpi.optionxform = str
    with open(ini, encoding="utf-8-sig") as f:
        cpi.read_file(f)
    new_vm_name = cpi.get("General", "name", fallback="")
    if new_vm_name and new_vm_name.lower() in args.old_host.lower():
        print(f"[!] WARNING: the new VM name '{new_vm_name}' matches the old UAG "
              f"({args.old_host}). ovftool --overwrite would DELETE the old VM!")
        if not args.force:
            print("    Change [General] name= (e.g. --set General.name=...-NEW), "
                  "or confirm with --force.")
            return 2

    # 1) Export from the old appliance
    ns = argparse.Namespace(host=args.old_host, user=args.user, password=old_pw,
                            out=args.settings_out)
    if cmd_export(ns) != 0:
        return 1
    settings_file = args.settings_out or sorted(
        Path(".").glob(f"uag_settings_{args.old_host}_*.json"))[-1]

    # 2) Deploy the new one (the INI may contain [SSLCert] -> cert deployed now)
    ns = argparse.Namespace(ini=ini, set=None, force=True,  # preflight already ran
                            root_password=args.root_password,
                            admin_password=new_pw,
                            vcenter_password=args.vcenter_password,
                            pfx_password=args.pfx_password,
                            no_ssl_verify=args.no_ssl_verify)
    if cmd_deploy(ns) != 0:
        print("ERROR: deploy failed, migration stopped. The old UAG is untouched.",
              file=sys.stderr)
        return 2

    # 3) Import into the new one. If the cert went in at deploy time via
    #    [SSLCert], --cert-pem/--key-pem are not needed.
    cert_in_ini = bool(cpi.get("SSLCert", "pfxCerts", fallback="")
                       or cpi.get("SSLCert", "pemCerts", fallback="")
                       or cpi.get("SSLcert", "pfxCerts", fallback="")
                       or cpi.get("SSLcert", "pemCerts", fallback=""))
    if cert_in_ini and not (args.cert_pem and args.key_pem):
        print("[i] The TLS certificate was deployed at deploy time ([SSLCert] in the INI).")
    ns = argparse.Namespace(host=args.new_host, user=args.user, password=new_pw,
                            settings=str(settings_file), secrets=args.secrets,
                            cert_pem=args.cert_pem, key_pem=args.key_pem,
                            cert_interface=args.cert_interface,
                            force=args.force or cert_in_ini, wait=args.wait)
    rc = cmd_import(ns)
    if rc != 0:
        return rc

    # 4) Quiesce the old one (optional)
    if args.quiesce_old:
        ns = argparse.Namespace(host=args.old_host, user=args.user, password=old_pw)
        cmd_quiesce(ns)

    print("\n[DONE] Migration finished. Next steps:")
    print("  1. Test client logins through the new UAG (Blast/PCoIP/tunnel).")
    print("  2. Switch the load balancer / DNS over to the new UAG.")
    print("  3. Once sessions have drained, power off and delete the old UAG.")
    return 0


# --------------------------------------------------------------------- CLI
def main() -> int:
    ap = argparse.ArgumentParser(description="Omnissa UAG migration to a new version")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p, host_flag="--host"):
        p.add_argument(host_flag, required=True)
        p.add_argument("--user", default="admin")
        p.add_argument("--password", default=None)

    p = sub.add_parser("export", help="Export the configuration from the old UAG")
    common(p)
    p.add_argument("--out", default=None)
    p.add_argument("--no-secret-prompt", action="store_true",
                   help="Do not prompt interactively for missing secrets")
    p.set_defaults(func=cmd_export)

    p = sub.add_parser("deploy", help="Deploy a new UAG from an INI (with preflight check) "
                                      "or interactively from a migration JSON")
    p.add_argument("--ini", default=None,
                   help="INI-based non-interactive deploy")
    p.add_argument("--settings", metavar="FILE", default=None,
                   help="Interactive restore mode: launches the wizard, which "
                        "asks for vCenter/network/VM parameters and restores "
                        "the configuration from this migration JSON")
    p.add_argument("--set", action="append", metavar="Section.key=value",
                   help="Override an INI value, repeatable "
                        "(e.g. --set General.name=UAG-02 --set General.ip0=10.0.0.51)")
    p.add_argument("--root-password", default=None)
    p.add_argument("--admin-password", default=None)
    p.add_argument("--vcenter-password", default=None)
    p.add_argument("--pfx-password", default=None,
                   help="Password for the PFX from [SSLCert] in the INI")
    p.add_argument("--no-ssl-verify", action="store_true")
    p.add_argument("--force", action="store_true",
                   help="Continue despite preflight check failures")
    p.set_defaults(func=cmd_deploy)

    p = sub.add_parser("import", help="Import the configuration into the new UAG")
    common(p)
    p.add_argument("--settings", required=True, help="JSON from the export")
    p.add_argument("--secrets", default=None, help="JSON file with the secrets filled in")
    p.add_argument("--cert-pem", default=None, help="PEM certificate chain")
    p.add_argument("--key-pem", default=None, help="PEM private key")
    p.add_argument("--cert-interface", default="internet",
                   choices=["internet", "admin", "internetAndAdmin"])
    p.add_argument("--force", action="store_true")
    p.add_argument("--wait", type=int, default=600)
    p.set_defaults(func=cmd_import)

    p = sub.add_parser("health", help="UAG health status")
    common(p)
    p.set_defaults(func=cmd_health)

    p = sub.add_parser("quiesce", help="Put the old UAG into quiesce mode")
    common(p)
    p.set_defaults(func=cmd_quiesce)

    p = sub.add_parser("migrate", help="Complete old -> new migration")
    p.add_argument("--old-host", required=True)
    p.add_argument("--new-host", required=True, help="IP of the new UAG (ip0 from the INI)")
    p.add_argument("--ini", required=True)
    p.add_argument("--set", action="append", metavar="Section.key=value",
                   help="Override an INI value, repeatable "
                        "(e.g. --set General.name=UAG-02-NEW --set SSLCert.pfxCerts=./uag.pfx)")
    p.add_argument("--user", default="admin")
    p.add_argument("--old-password", default=None)
    p.add_argument("--new-password", default=None)
    p.add_argument("--root-password", default=None)
    p.add_argument("--vcenter-password", default=None)
    p.add_argument("--pfx-password", default=None,
                   help="Password for the PFX from [SSLCert] in the INI")
    p.add_argument("--no-ssl-verify", action="store_true")
    p.add_argument("--settings-out", default=None)
    p.add_argument("--secrets", default=None)
    p.add_argument("--cert-pem", default=None)
    p.add_argument("--key-pem", default=None)
    p.add_argument("--cert-interface", default="internet",
                   choices=["internet", "admin", "internetAndAdmin"])
    p.add_argument("--quiesce-old", action="store_true")
    p.add_argument("--force", action="store_true")
    p.add_argument("--wait", type=int, default=600)
    p.set_defaults(func=cmd_migrate)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
