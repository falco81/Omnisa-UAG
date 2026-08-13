#!/usr/bin/env python3
"""
uag_migrate.py - Orchestrace migrace Omnissa UAG na novou verzi
(side-by-side "deploy & migrate", protože UAG in-place upgrade nepodporuje).

Podpříkazy:
    export    - stáhne konfiguraci ze staré UAG (JSON) a uloží na disk
    deploy    - nasadí novou UAG (volá uag_deploy.py / ovftool s INI)
    import    - naimportuje JSON konfiguraci do nové UAG + doplní secrety/cert
    health    - ověří dostupnost Admin API a stav edge služeb
    quiesce   - přepne starou UAG do quiesce módu (dobíhání sessions)
    migrate   - celý řetězec: export -> deploy -> import -> health -> quiesce

Příklady:
    python3 uag_migrate.py export  --host uag-old.firma.cz --out uag_settings.json
    python3 uag_migrate.py deploy  --ini uag-new.ini
    python3 uag_migrate.py import  --host 10.0.0.50 --settings uag_settings.json \
        --cert-pem cert_chain.pem --key-pem key.pem
    python3 uag_migrate.py migrate --old-host uag-old.firma.cz --ini uag-new.ini \
        --new-host 10.0.0.50 --cert-pem cert_chain.pem --key-pem key.pem

DŮLEŽITÉ (omezení exportu UAG):
    Export JSON NEOBSAHUJE: hesla, RADIUS/SAML shared secrets, TLS certifikát
    (PFX/PEM), keytab soubory. Ty je nutné dodat znovu - skript na chybějící
    položky upozorní a certifikát umí nahrát přes REST API.
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

# Klíče, které heuristice padnou do sítě, ale secrety NEJSOU (jen UI texty
# a přepínače) - např. radiusCustomPassphraseHint je "Login page passphrase
# hint": text zobrazený uživateli v Horizon Clientu, žádný citlivý údaj.
NOT_SECRETS = ("hint", "label", "expiration", "policy", "enabled",
               "protected", "required")


def find_missing_secrets(settings: dict) -> list[str]:
    """Projde exportovaný JSON a najde klíče, které vypadají na vyprázdněné secrety."""
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
    pw = password or getpass.getpass(f"Admin heslo pro {host}: ")
    return UagClient(host=host, admin_user=user, admin_password=pw)


# ----------------------------------------------------------------- commands
def cmd_export(args) -> int:
    c = make_client(args.host, args.user, args.password)
    print(f"[..] Exportuji konfiguraci z {args.host} ...")
    settings = c.export_settings()
    out = Path(args.out or f"uag_settings_{args.host}_{datetime.now():%Y%m%d_%H%M%S}.json")
    save_json(str(out), settings)
    print(f"[OK] Uloženo: {out}")

    missing = find_missing_secrets(settings)
    if missing:
        print("\n[!] Export neobsahuje tyto secrety - při importu je nutné doplnit:")
        for m in missing:
            print(f"    - {m}")
    print("[!] TLS certifikát a keytaby export nikdy neobsahuje - připravte si PEM/PFX/keytab.")
    return 0


def apply_ini_overrides(ini_path: str, sets: list[str] | None) -> str:
    """
    Vytvoří runtime kopii INI s přepisy z --set Sekce.klíč=hodnota.
    Umožňuje znovupoužít jednu šablonu pro více UAG / migrací
    (typicky --set General.name=... --set General.ip0=... --set General.source=...).
    Vrací cestu k runtime INI (originál zůstává netknutý).
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
            sys.exit(f"CHYBA: --set očekává formát Sekce.klíč=hodnota (dostal: {item})")
        key_path, value = item.split("=", 1)
        section, key = key_path.split(".", 1)
        if section not in cp:
            cp.add_section(section)
        cp[section][key] = value
    runtime = Path(ini_path).with_suffix(".runtime.ini")
    with open(runtime, "w", encoding="utf-8") as f:
        cp.write(f)
    print(f"[OK] Runtime INI s přepisy: {runtime}")
    return str(runtime)


def preflight(ini_path: str, old_host: str | None, old_client_factory=None,
              cert_pem: str | None = None, key_pem: str | None = None) -> list[str]:
    """
    Kontroly PŘED zahájením migrace/deploye, ať nic nespadne v půlce:
      - ovftool nalezen, INI parsovatelné, OVA soubor existuje a vypadá jako UAG,
      - certifikáty (INI [SSLCert] i --cert-pem/--key-pem) existují,
      - PEM klíč je PKCS#1 (vyžadováno deploy skriptem),
      - stará UAG odpovídá na Admin API (jen u migrace).
    Vrací seznam chyb (prázdný = OK).
    """
    import configparser
    problems: list[str] = []

    # ovftool (portable ./ovftool/ vedle skriptů, instalace, PATH)
    try:
        import uag_deploy as _ud
        if not _ud.locate_ovftool():
            problems.append("ovftool nenalezen (portable './ovftool/' vedle "
                            "skriptů, Program Files ani PATH)")
    except ImportError:
        problems.append("uag_deploy.py chybí vedle uag_migrate.py")

    # INI + OVA
    cp = configparser.ConfigParser(interpolation=None, strict=False)
    cp.optionxform = str
    try:
        with open(ini_path, encoding="utf-8-sig") as f:
            cp.read_file(f)
    except OSError:
        problems.append(f"INI soubor {ini_path} nelze načíst")
        cp = None
    if cp:
        source = cp.get("General", "source", fallback="").strip()
        if not source:
            problems.append("[General] source= chybí v INI")
        elif not Path(source).is_file():
            problems.append(f"OVA soubor neexistuje: {source}")
        elif "euc-unified-access-gateway" not in Path(source).name:
            problems.append(f"OVA nevypadá jako UAG image: {Path(source).name}")
        if not cp.get("General", "ds", fallback="").strip():
            problems.append("[General] ds= chybí v INI")
        if not cp.get("General", "target", fallback="").strip():
            problems.append("[General] target= chybí v INI")
        # certifikáty z INI
        for section in ("SSLCert", "SSLcert", "SSLCertAdmin", "SSLcertAdmin"):
            if cp.has_section(section):
                for key in ("pfxCerts", "pemCerts", "pemPrivKey"):
                    v = cp.get(section, key, fallback="").strip()
                    if v and not Path(v).is_file():
                        problems.append(f"[{section}] {key}={v} - soubor neexistuje")
                pem_key = cp.get(section, "pemPrivKey", fallback="").strip()
                if pem_key and Path(pem_key).is_file():
                    if "BEGIN RSA PRIVATE KEY" not in Path(pem_key).read_text(errors="replace"):
                        problems.append(
                            f"[{section}] pemPrivKey není PKCS#1 - převod: "
                            f"openssl rsa -in {pem_key} -traditional -out klic_pkcs1.pem")

    # certifikáty pro REST import
    for label, path in (("--cert-pem", cert_pem), ("--key-pem", key_pem)):
        if path and not Path(path).is_file():
            problems.append(f"{label} {path} - soubor neexistuje")

    # stará UAG dostupná
    if old_host and old_client_factory:
        try:
            old_client_factory().get_system_health()
        except Exception as e:
            problems.append(f"Stará UAG {old_host} neodpovídá na Admin API: {e}")

    return problems


def cmd_deploy(args) -> int:
    ini = apply_ini_overrides(args.ini, getattr(args, "set", None))
    problems = preflight(ini, None)
    if problems:
        print("[!] Preflight kontrola selhala:")
        for p in problems:
            print(f"    - {p}")
        if not getattr(args, "force", False):
            print("    Opravte, nebo spusťte s --force.")
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
        print(f"CHYBA: Admin API na {args.host} není dostupné.", file=sys.stderr)
        return 2

    settings = load_json(args.settings)

    # volitelné patchování secretů z doprovodného souboru {"cesta.klíč": "hodnota"}
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
        print(f"[OK] Doplněno {applied} secretů ze souboru {args.secrets}")

    missing = find_missing_secrets(settings)
    if missing and not args.force:
        print("[!] V konfiguraci zůstávají prázdné secrety:")
        for m in missing:
            print(f"    - {m}")
        print("    Pokračujte s --force, nebo je doplňte přes --secrets soubor.")
        return 3

    print(f"[..] Importuji konfiguraci do {args.host} ...")
    try:
        c.import_settings(settings)
    except UagApiError as e:
        print(f"CHYBA importu: {e}", file=sys.stderr)
        print("Tip: zkontrolujte SHA-1 vs SHA-256 thumbprinty a zastaralé cipher suites v JSON.",
              file=sys.stderr)
        return 4
    print("[OK] Konfigurace naimportována.")

    if args.cert_pem and args.key_pem:
        print("[..] Nahrávám TLS certifikát ...")
        c.upload_tls_cert_pem(load_pem(args.key_pem), load_pem(args.cert_pem),
                              interface=args.cert_interface)
        print("[OK] Certifikát nahrán.")
    else:
        print("[!] TLS certifikát nebyl nahrán (chybí --cert-pem/--key-pem) - nutno doplnit ručně.")

    if c.wait_for_edge_services_green(max_wait_s=args.wait):
        return 0
    print("[!] Edge služby nejsou zelené - zkontrolujte Admin UI.", file=sys.stderr)
    return 5


def cmd_health(args) -> int:
    c = make_client(args.host, args.user, args.password)
    ok = c.wait_until_ready(max_wait_s=30, interval_s=5)
    if not ok:
        return 2
    stats = c.get_edge_status()
    if isinstance(stats, str):
        print(stats)   # /monitor/stats vrací XML
    else:
        print(json.dumps(stats, indent=2, ensure_ascii=False))
    print("\nZelené:", "ANO" if c.edge_status_is_green(stats) else "NE")
    return 0


def cmd_quiesce(args) -> int:
    c = make_client(args.host, args.user, args.password)
    c.set_quiesce_mode(True)
    print(f"[OK] {args.host} je v quiesce módu - nové session nepřijímá, "
          f"stávající dobíhají. Po vyprázdnění VM vypněte/smažte.")
    return 0


def cmd_migrate(args) -> int:
    """Celý řetězec migrace: preflight -> export -> deploy -> import -> health -> quiesce."""
    old_pw = args.old_password or getpass.getpass(f"Admin heslo STARÉ UAG {args.old_host}: ")

    # 0) Preflight - ověřit VŠECHNO před prvním krokem (INI, OVA, ovftool,
    #    certifikáty, dostupnost staré UAG), ať migrace nespadne v půlce.
    ini = apply_ini_overrides(args.ini, getattr(args, "set", None))
    problems = preflight(
        ini, args.old_host,
        old_client_factory=lambda: UagClient(host=args.old_host, admin_user=args.user,
                                             admin_password=old_pw),
        cert_pem=args.cert_pem, key_pem=args.key_pem)
    if problems:
        print("[!] Preflight kontrola selhala:")
        for p in problems:
            print(f"    - {p}")
        if not args.force:
            print("    Opravte, nebo spusťte s --force.")
            return 2
    else:
        print("[OK] Preflight: ovftool, OVA, INI, certifikáty i stará UAG v pořádku.")

    new_pw = args.new_password or getpass.getpass(
        "Admin heslo NOVÉ UAG (bude nastaveno při deployi): ")

    # Bezpečnostní pojistka: ovftool s --overwrite smaže VM se stejným jménem!
    import configparser
    cpi = configparser.ConfigParser(interpolation=None, strict=False)
    cpi.optionxform = str
    with open(ini, encoding="utf-8-sig") as f:
        cpi.read_file(f)
    new_vm_name = cpi.get("General", "name", fallback="")
    if new_vm_name and new_vm_name.lower() in args.old_host.lower():
        print(f"[!] VAROVÁNÍ: jméno nové VM '{new_vm_name}' se shoduje se starou UAG "
              f"({args.old_host}). ovftool --overwrite by starou VM SMAZAL!")
        if not args.force:
            print("    Změňte [General] name= (např. --set General.name=...-NEW), "
                  "nebo potvrďte --force.")
            return 2

    # 1) Export ze staré
    ns = argparse.Namespace(host=args.old_host, user=args.user, password=old_pw,
                            out=args.settings_out)
    if cmd_export(ns) != 0:
        return 1
    settings_file = args.settings_out or sorted(
        Path(".").glob(f"uag_settings_{args.old_host}_*.json"))[-1]

    # 2) Deploy nové (INI může obsahovat [SSLCert] -> cert se nasadí už teď)
    ns = argparse.Namespace(ini=ini, set=None, force=True,  # preflight už proběhl
                            root_password=args.root_password,
                            admin_password=new_pw,
                            vcenter_password=args.vcenter_password,
                            pfx_password=args.pfx_password,
                            no_ssl_verify=args.no_ssl_verify)
    if cmd_deploy(ns) != 0:
        print("CHYBA: deploy selhal, migrace zastavena. Stará UAG je netknutá.",
              file=sys.stderr)
        return 2

    # 3) Import do nové. Pokud cert šel už při deployi přes [SSLCert],
    #    --cert-pem/--key-pem nejsou potřeba.
    cert_in_ini = bool(cpi.get("SSLCert", "pfxCerts", fallback="")
                       or cpi.get("SSLCert", "pemCerts", fallback="")
                       or cpi.get("SSLcert", "pfxCerts", fallback="")
                       or cpi.get("SSLcert", "pemCerts", fallback=""))
    if cert_in_ini and not (args.cert_pem and args.key_pem):
        print("[i] TLS certifikát byl nasazen už při deployi ([SSLCert] v INI).")
    ns = argparse.Namespace(host=args.new_host, user=args.user, password=new_pw,
                            settings=str(settings_file), secrets=args.secrets,
                            cert_pem=args.cert_pem, key_pem=args.key_pem,
                            cert_interface=args.cert_interface,
                            force=args.force or cert_in_ini, wait=args.wait)
    rc = cmd_import(ns)
    if rc != 0:
        return rc

    # 4) Quiesce staré (volitelně)
    if args.quiesce_old:
        ns = argparse.Namespace(host=args.old_host, user=args.user, password=old_pw)
        cmd_quiesce(ns)

    print("\n[HOTOVO] Migrace dokončena. Další kroky:")
    print("  1. Otestujte přihlášení klientů přes novou UAG (Blast/PCoIP/tunnel).")
    print("  2. Přepněte load balancer / DNS na novou UAG.")
    print("  3. Po vyprázdnění sessions starou UAG vypněte a smažte.")
    return 0


# --------------------------------------------------------------------- CLI
def main() -> int:
    ap = argparse.ArgumentParser(description="Migrace Omnissa UAG na novou verzi")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p, host_flag="--host"):
        p.add_argument(host_flag, required=True)
        p.add_argument("--user", default="admin")
        p.add_argument("--password", default=None)

    p = sub.add_parser("export", help="Export konfigurace ze staré UAG")
    common(p)
    p.add_argument("--out", default=None)
    p.set_defaults(func=cmd_export)

    p = sub.add_parser("deploy", help="Deploy nové UAG z INI (s preflight kontrolou)")
    p.add_argument("--ini", required=True)
    p.add_argument("--set", action="append", metavar="Sekce.klíč=hodnota",
                   help="Přepis INI hodnoty, lze opakovat "
                        "(např. --set General.name=UAG-02 --set General.ip0=10.0.0.51)")
    p.add_argument("--root-password", default=None)
    p.add_argument("--admin-password", default=None)
    p.add_argument("--vcenter-password", default=None)
    p.add_argument("--pfx-password", default=None,
                   help="Heslo k PFX z [SSLCert] v INI")
    p.add_argument("--no-ssl-verify", action="store_true")
    p.add_argument("--force", action="store_true",
                   help="Pokračovat i přes chyby preflight kontroly")
    p.set_defaults(func=cmd_deploy)

    p = sub.add_parser("import", help="Import konfigurace do nové UAG")
    common(p)
    p.add_argument("--settings", required=True, help="JSON z exportu")
    p.add_argument("--secrets", default=None, help="JSON s doplněnými secrety")
    p.add_argument("--cert-pem", default=None, help="PEM řetěz certifikátů")
    p.add_argument("--key-pem", default=None, help="PEM privátní klíč")
    p.add_argument("--cert-interface", default="internet",
                   choices=["internet", "admin", "internetAndAdmin"])
    p.add_argument("--force", action="store_true")
    p.add_argument("--wait", type=int, default=600)
    p.set_defaults(func=cmd_import)

    p = sub.add_parser("health", help="Stav UAG")
    common(p)
    p.set_defaults(func=cmd_health)

    p = sub.add_parser("quiesce", help="Quiesce mód staré UAG")
    common(p)
    p.set_defaults(func=cmd_quiesce)

    p = sub.add_parser("migrate", help="Kompletní migrace old -> new")
    p.add_argument("--old-host", required=True)
    p.add_argument("--new-host", required=True, help="IP nové UAG (ip0 z INI)")
    p.add_argument("--ini", required=True)
    p.add_argument("--set", action="append", metavar="Sekce.klíč=hodnota",
                   help="Přepis INI hodnoty, lze opakovat "
                        "(např. --set General.name=UAG-02-NEW --set SSLCert.pfxCerts=./uag.pfx)")
    p.add_argument("--user", default="admin")
    p.add_argument("--old-password", default=None)
    p.add_argument("--new-password", default=None)
    p.add_argument("--root-password", default=None)
    p.add_argument("--vcenter-password", default=None)
    p.add_argument("--pfx-password", default=None,
                   help="Heslo k PFX z [SSLCert] v INI")
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
