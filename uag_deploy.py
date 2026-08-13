#!/usr/bin/env python3
"""
uag_deploy.py - Python port of the official Omnissa uagdeploy.ps1 /
uagdeploy.psm1 (version 25.12.1.0, vSphere/ovftool variant).

Faithfully replicates the mechanics of the original:
  * settingsJSON is written to a temporary .cfg file (65535-char chunks,
    keys settingsJSON / settingsJSON-0..N, max 16x65535) and passed to
    ovftool via --configFile - exactly like the original (no long CLI args).
  * Direct OVF properties 1:1 per uagdeploy.ps1 (--prop:DNS uppercase,
    --prop:forceNetmask{n}, passwordPolicy*, adminPasswordPolicy*, ssh*,
    ceipEnabled=False only when disabled, dsComplianceOS, routes,
    policyRouteGateway, configURL/configKey, adminCsrSubject/SAN, ...).
  * NIC options per GetNetOptions (11 ipMode combinations, default
    derivation of STATICV4/STATICV6/DHCPV4).
  * deploymentOption defaults to "onenic", aliases onenic-L -> onenic-large.
  * [SSLcert]/[SSLcertAdmin]: PEM -> certificateWrapper{,Admin},
    PFX -> pfxCertStoreWrapper{,Admin} (base64 + password + optional alias)
    inside settingsJSON.
  * [Horizon] -> VIEW edge service, [WebReverseProxy], [WebReverseProxy1..99]
    -> WEB_REVERSE_PROXY, [RADIUSAuth] -> radius-auth (prompts for the
    shared secret, which is never present in an exported INI).
  * Validation: ds required, VM name <= 32 chars, OVA verified via
    ovftool --verifyOnly, 'euc-unified-access-gateway' vmdk check.

Usage:
    python3 uag_deploy.py --ini uag1.ini
    python3 uag_deploy.py --ini uag1.ini --root-password '...' --admin-password '...'
    python3 uag_deploy.py --ini uag1.ini --no-ssl-verify --dry-run
"""

from __future__ import annotations

import argparse
import base64
import configparser
import getpass
import json
import re
import shlex
import subprocess
import sys
import tempfile
import urllib.parse
from pathlib import Path

WIN_OVFTOOL = r"C:\Program Files\VMware\VMware OVF Tool\ovftool.exe"
UNIX_OVFTOOL = "/usr/bin/ovftool"

SCRIPT_DIR = Path(__file__).resolve().parent


def locate_ovftool() -> str | None:
    """
    Locates ovftool in this order:
      1. portable distribution in an 'ovftool' folder next to the scripts
         (ovftool\\ovftool.exe / ovftool/ovftool)
      2. ovftool.exe directly next to the scripts
      3. standard installation (Program Files / /usr/bin)
      4. PATH
    """
    import shutil as _shutil
    candidates = [
        SCRIPT_DIR / "ovftool" / "ovftool.exe",
        SCRIPT_DIR / "ovftool" / "ovftool",
        SCRIPT_DIR / "ovftool.exe",
        Path(WIN_OVFTOOL),
        Path(UNIX_OVFTOOL),
    ]
    for c in candidates:
        if c.is_file():
            return str(c)
    return _shutil.which("ovftool")

SETTINGS_CHUNK = 65535
SETTINGS_MAX = 16 * SETTINGS_CHUNK

# ---------------------------------------------------------------------------
# INI (ekvivalent ImportIni)
# ---------------------------------------------------------------------------

def read_ini(path: Path) -> configparser.ConfigParser:
    cp = configparser.ConfigParser(interpolation=None, strict=False)
    cp.optionxform = str  # keep key case (the original writes keys case-sensitively)
    try:
        with open(path, encoding="utf-8-sig") as f:
            cp.read_file(f)
    except OSError:
        err(f"Configuration file ({path}) not found.")
    if "General" not in cp:
        err(f"[General] section missing in {path}.")
    return cp


def err(msg: str) -> None:
    print(f"Error: {msg}", file=sys.stderr)
    sys.exit(1)


def get(cp, section: str, key: str, default: str = "") -> str:
    """Case-insensitive key lookup (PowerShell hashtables are case-insensitive)."""
    if section not in cp:
        return default
    for k, v in cp[section].items():
        if k.lower() == key.lower():
            return v.strip()
    return default


def sec_dict(cp, section: str) -> dict[str, str]:
    return {k: v.strip() for k, v in cp[section].items()} if section in cp else {}


def find_section(cp, name: str) -> str | None:
    """Finds a section case-insensitively (SSLcert vs SSLCert...)."""
    for s in cp.sections():
        if s.lower() == name.lower():
            return s
    return None


# ---------------------------------------------------------------------------
# Helper conversions
# ---------------------------------------------------------------------------

def to_json_value(v: str):
    if v.lower() in ("true", "false"):
        return v.lower() == "true"
    return v


def sanitize_thumbprints(t: str) -> str:
    # SanitizeThumbprints: allowed chars are hex, ':', ',', space, '=' and sha prefixes
    return re.sub(r"[^0-9a-fA-F:,=\s(sha256)(sha1)]", "", t)


def read_pem_file(path: str, what: str, section: str) -> str:
    p = Path(path)
    if not p.is_file():
        err(f"{what} file in {section} not found ({path})")
    text = p.read_text(encoding="utf-8", errors="replace")
    idx = text.find("-----BEGIN")
    if idx < 0:
        err(f"Invalid PEM file ({what}) specified in {section}.")
    text = text[idx:]
    # the original requires the PKCS#1 private key format (BEGIN RSA PRIVATE KEY)
    if "privkey" in what.lower() or "privatekey" in what.lower():
        if "-----BEGIN RSA PRIVATE KEY-----" not in text:
            err(f"Invalid private key PEM file ({what}) in {section}. It must contain "
                f"an RSA private key (PKCS#1). Convert from PKCS#8 with: "
                f"openssl rsa -in {path} -traditional -out key_pkcs1.pem")
    return text


# ---------------------------------------------------------------------------
# settingsJSON buildery (ekvivalent GetJSONSettings a spol.)
# ---------------------------------------------------------------------------

def get_certificate_wrapper(cp, section_name: str, pfx_password: str | None,
                            interactive: bool) -> dict:
    """[SSLcert] / [SSLcertAdmin] -> certificateWrapper{,Admin} / pfxCertStoreWrapper{,Admin}."""
    section = find_section(cp, section_name)
    out: dict = {}
    if not section:
        return out
    suffix = "Admin" if section_name.lower() == "sslcertadmin" else ""

    pem_certs = get(cp, section, "pemCerts")
    pfx_certs = get(cp, section, "pfxCerts")

    if pem_certs:
        pem_priv = get(cp, section, "pemPrivKey")
        if not pem_priv:
            err(f"PEM RSA private key file pemPrivKey in {section} is not specified")
        certs = read_pem_file(pem_certs, "PEM Certificate", section)
        key = read_pem_file(pem_priv, "PEM RSA private key", section)
        print(f"Deployment will use the specified SSL/TLS server certificate ({section})")
        out[f"certificateWrapper{suffix}"] = {
            "privateKeyPem": key,
            "certChainPem": certs,
        }
    elif pfx_certs:
        p = Path(pfx_certs)
        if not p.is_file():
            err(f"PFX Certificate file not found ({pfx_certs})")
        if pfx_password is None:
            if interactive:
                pfx_password = getpass.getpass(
                    f"Password for PFX {p.name} [{section}] (Enter = no password): ")
            else:
                pfx_password = ""
        wrapper = {
            "pfxKeystore": base64.b64encode(p.read_bytes()).decode(),
            "password": pfx_password,
        }
        alias = get(cp, section, "pfxCertAlias")
        if alias:
            wrapper["alias"] = alias
        out[f"pfxCertStoreWrapper{suffix}"] = wrapper
    else:
        print(f"Deployment will use a self-signed SSL/TLS server certificate ({section_name})")
    return out


# [Horizon] keys that are NOT copied 1:1 (files / special handling)
HORIZON_SKIP = {
    "privatekeypem", "certchainpem", "pfxkeystore", "pfxcertalias",
    "pfxcertspassword", "trustedcert", "keytab",
}


def get_edge_view(cp, interactive: bool) -> dict | None:
    """[Horizon] -> VIEW edge service. Generic 1:1 key copy plus special logic
    per GetEdgeServiceSettingsVIEW (strip :443, thumbprint sanitization,
    xmlSigningSwitch default AUTO, XML signing certs from PEM files)."""
    section = find_section(cp, "Horizon")
    if not section:
        return None
    h = sec_dict(cp, section)

    pdu = h.get("proxyDestinationUrl", "")
    if pdu.endswith(":443"):
        pdu = pdu[: -len(":443")]

    key_urls = [pdu, h.get("pcoipExternalUrl", ""), h.get("blastExternalUrl", ""),
                h.get("blastInternalUrl", ""), h.get("tunnelExternalUrl", "")]
    if not any(key_urls):
        return None

    svc: dict = {"identifier": "VIEW", "enabled": True}
    if pdu:
        svc["proxyDestinationUrl"] = pdu

    thumb = h.get("proxyDestinationUrlThumbprints", "")
    if thumb:
        if not pdu:
            err("Cannot set proxyDestinationUrlThumbprints without proxy destination")
        thumb = sanitize_thumbprints(thumb)
        if "sha1" in thumb.lower():
            err("sha1 thumbprints are no longer supported - replace with sha256 in the INI.")
        svc["proxyDestinationUrlThumbprints"] = thumb

    xml_sw = h.get("xmlSigningSwitch", "AUTO").upper()
    if xml_sw not in ("AUTO", "ON", "OFF"):
        err("xmlSigningSwitch field can be set to AUTO, ON or OFF")
    svc["xmlSigningSwitch"] = xml_sw

    # XML API signing certificate (PEM variant)
    if h.get("certChainPem"):
        if not h.get("privateKeyPem"):
            err("XML API Signing PEM private key file privateKeyPem not specified")
        svc["xmlSigningPemCertSettings"] = {
            "privateKeyPem": read_pem_file(h["privateKeyPem"], "privateKeyPem", section),
            "certChainPem": read_pem_file(h["certChainPem"], "certChainPem", section),
        }
    elif h.get("pfxKeystore"):
        p = Path(h["pfxKeystore"])
        if not p.is_file():
            err(f"PFX Certificate file not found ({h['pfxKeystore']})")
        pw = getpass.getpass(f"Password for the XML signing PFX {p.name}: ") if interactive else ""
        pfx = {"pfxKeystore": base64.b64encode(p.read_bytes()).decode(), "password": pw}
        if h.get("pfxCertAlias"):
            pfx["alias"] = h["pfxCertAlias"]
        svc["xmlSigningPfxCertSettings"] = pfx

    # hostEntry1..N -> hostEntries
    host_entries = collect_numbered(h, "hostEntry")
    if host_entries:
        svc["hostEntries"] = host_entries

    # remaining keys 1:1 (bool conversion), skip already-handled and file keys
    handled = {"proxydestinationurl", "proxydestinationurlthumbprints",
               "xmlsigningswitch"} | HORIZON_SKIP
    for k, v in h.items():
        if k.lower() in handled or re.match(r"hostentry\d*$", k, re.I) or not v:
            continue
        svc[k] = to_json_value(v)
    return svc


def collect_numbered(d: dict[str, str], prefix: str) -> list[str]:
    out = []
    for i in range(1, 100):
        for k, v in d.items():
            if k.lower() == f"{prefix.lower()}{i}":
                out.append(v)
    return out


WRP_SKIP = {"trustedcert", "keytab", "metadataxmlfile"}


def get_edge_wrps(cp) -> list[dict]:
    """[WebReverseProxy], [WebReverseProxy1..99] -> WEB_REVERSE_PROXY services."""
    out = []
    for i in range(0, 100):
        name = f"WebReverseProxy{i if i else ''}"
        section = find_section(cp, name)
        if not section:
            continue
        w = sec_dict(cp, section)
        pdu = w.get("proxyDestinationUrl", "")
        if not pdu:
            continue
        svc: dict = {"identifier": "WEB_REVERSE_PROXY", "enabled": True,
                     "proxyDestinationUrl": pdu,
                     "instanceId": w.get("instanceId", "")}
        host_entries = collect_numbered(w, "hostEntry")
        if host_entries:
            svc["hostEntries"] = host_entries
        for k, v in w.items():
            if (k.lower() in ("proxydestinationurl", "instanceid") or
                    k.lower() in WRP_SKIP or re.match(r"hostentry\d*$", k, re.I) or not v):
                continue
            if k.lower() == "proxydestinationurlthumbprints":
                v = sanitize_thumbprints(v)
            svc[k] = to_json_value(v)
        out.append(svc)
    return out


def get_radius_auth(cp, interactive: bool) -> dict | None:
    """[RADIUSAuth] -> radius-auth. The shared secret is never exported -> prompt."""
    section = find_section(cp, "RADIUSAuth")
    if not section:
        return None
    r = sec_dict(cp, section)
    auth: dict = {"name": "radius-auth", "enabled": True}
    secret = r.get("radiusSharedSecret") or (
        getpass.getpass(f"RADIUS shared secret [{section}]: ") if interactive else "")
    if secret:
        auth["sharedSecret"] = secret
    if r.get("radiusSharedSecret_2") or (r.get("hostName_2") and interactive):
        auth["sharedSecret_2"] = r.get("radiusSharedSecret_2") or getpass.getpass(
            f"RADIUS shared secret for the secondary server [{section}]: ")
    for k, v in r.items():
        if k.lower().startswith("radiussharedsecret") or not v:
            continue
        auth[k] = to_json_value(v)
    return auth


# systemSettings whitelist from GetSystemSettings ([General] keys)
SYSTEM_KEYS = [
    "headersToBeLogged", "cipherSuites", "outboundCipherSuites", "sslProvider",
    "tlsNamedGroups", "tlsSignatureSchemes", "tls11Enabled", "tls12Enabled",
    "tls13Enabled", "honorCipherOrder", "healthCheckUrl", "sessionTimeout",
    "authenticationTimeout", "requestTimeoutMsec", "bodyReceiveTimeoutMsec",
    "monitorInterval", "snmpEnabled", "ntpServers", "fallBackNtpServers",
    "hostClockSyncEnabled", "adminDisclaimerText", "dnsSearch",
    "allowedHostHeaderValues", "maxConnectionsAllowedPerSession",
    "minSHAHashSize", "uagName", "syslogUrl", "syslogAuditUrl", "sysLogType",
    "syslogSystemMessagesEnabled", "cookiesToBeCached", "clientConnectionIdleTimeout",
    "maxSystemCPUAllowed", "enableHTTPHealthMonitor",
    "unrecognizedSessionsMonitoringEnabled", "extendedServerCertValidationEnabled",
    "samlCertRolloverSupported", "samlEncryptionCertRolloverSupported",
    "adminPasswordExpirationDays", "monitoringUsersPasswordExpirationDays",
]


def get_system_settings(cp) -> dict:
    sys_s: dict = {"ssl30Enabled": "true" if get(cp, "General", "ssl30Enabled") == "true" else "false"}
    for key in SYSTEM_KEYS:
        v = get(cp, "General", key)
        if v:
            sys_s[key] = v
    return sys_s


KNOWN_SECTIONS = {"general", "sslcert", "sslcertadmin", "horizon", "radiusauth"}


def warn_unhandled_sections(cp) -> None:
    unhandled = [s for s in cp.sections()
                 if s.lower() not in KNOWN_SECTIONS
                 and not s.lower().startswith("webreverseproxy")]
    if unhandled:
        print(f"[!] Warning: sections {unhandled} are not handled by this port "
              f"(SecurID, SAML, Kerberos, SNMP, HA, DevicePolicy...). "
              f"Recommended approach: deploy a minimal appliance and import the "
              f"full configuration via the REST API (uag_migrate.py import).")


def build_settings_json(cp, pfx_password: str | None, interactive: bool) -> str:
    doc: dict = {}
    ssl_found = bool(get(cp, "SSLcert", "pemCerts") or get(cp, "SSLcert", "pfxCerts"))
    ssl1_found = bool(get(cp, "SSLcert1", "identifier"))
    if ssl_found and ssl1_found:
        err("Either 'SSLcert' or 'SSLcert1' can be present in the settings.")

    doc.update(get_certificate_wrapper(cp, "SSLcert", pfx_password, interactive))
    doc.update(get_certificate_wrapper(cp, "SSLcertAdmin", pfx_password, interactive))

    edge_list: list[dict] = []
    view = get_edge_view(cp, interactive)
    if view:
        edge_list.append(view)
    edge_list.extend(get_edge_wrps(cp))

    auth_list: list[dict] = []
    radius = get_radius_auth(cp, interactive)
    if radius:
        auth_list.append(radius)

    doc["edgeServiceSettingsList"] = {"edgeServiceSettingsList": edge_list}
    doc["systemSettings"] = get_system_settings(cp)
    doc["authMethodSettingsList"] = {"authMethodSettingsList": auth_list}

    warn_unhandled_sections(cp)
    return json.dumps(doc, separators=(", ", ": "), ensure_ascii=False)


def write_config_file(settings_json: str, ap_name: str, workdir: Path) -> Path:
    """Equivalent of GetSettingsJSONProperty + writes the .cfg for --configFile."""
    if len(settings_json) > SETTINGS_MAX:
        err("Provided settings exceeds max allowed settings that can be deployed.")
    lines = []
    if len(settings_json) <= SETTINGS_CHUNK:
        lines.append(f"prop:settingsJSON={settings_json}")
    else:
        for idx, i in enumerate(range(0, len(settings_json), SETTINGS_CHUNK)):
            lines.append(f"prop:settingsJSON-{idx}={settings_json[i:i + SETTINGS_CHUNK]}")
    cfg = workdir / f"{ap_name}.cfg"
    cfg.write_text("\r\n".join(lines), encoding="utf-8")
    return cfg


# ---------------------------------------------------------------------------
# NIC options (equivalent of GetNetOptions - 11 ipMode combinations)
# ---------------------------------------------------------------------------

DHCP_ONLY = {"DHCPV4", "DHCPV4+DHCPV6", "DHCPV4+AUTOV6", "DHCPV6", "AUTOV6"}
V6_ONLY = {"STATICV6", "DHCPV4+STATICV6"}
V4_ONLY = {"STATICV4", "STATICV4+DHCPV6", "STATICV4+AUTOV6"}


def get_net_options(cp, nic: str) -> list[str]:
    g = lambda k: get(cp, "General", k)  # noqa: E731
    ip, netmask = g(f"ip{nic}"), g(f"netmask{nic}")
    v6ip, v6prefix = g(f"v6ip{nic}"), g(f"v6ipprefix{nic}")
    ip_mode = g(f"ipMode{nic}").upper()
    custom = g(f"eth{nic}CustomConfig")

    if ip and not netmask:
        err(f"missing value netmask{nic}.")
    if v6ip and not v6prefix:
        err(f"missing value v6ipprefix{nic}.")

    if not ip_mode:
        if ip and not v6ip:
            ip_mode = "STATICV4"
        elif v6ip and not ip:
            ip_mode = "STATICV6"
        elif ip and v6ip:
            ip_mode = "STATICV4+STATICV6"
        else:
            ip_mode = "DHCPV4"

    opts: list[str] = []
    if custom:
        opts.append(f"--prop:eth{nic}CustomConfig={custom}")

    if ip_mode in DHCP_ONLY:
        opts.append(f"--prop:ipMode{nic}={ip_mode}")
    elif ip_mode in V6_ONLY:
        if not v6ip:
            err(f"missing value v6ip{nic}.")
        opts += [f"--prop:ipMode{nic}={ip_mode}", f"--prop:v6ip{nic}={v6ip}",
                 f"--prop:forceIpv6Prefix{nic}={v6prefix}"]
    elif ip_mode in V4_ONLY:
        if not ip:
            err(f"missing value ip{nic}.")
        opts += [f"--prop:ipMode{nic}={ip_mode}", f"--prop:ip{nic}={ip}",
                 f"--prop:forceNetmask{nic}={netmask}"]
    elif ip_mode == "STATICV4+STATICV6":
        if not ip:
            err(f"missing value ip{nic}.")
        if not v6ip:
            err(f"missing value v6ip{nic}.")
        opts += [f"--prop:ipMode{nic}={ip_mode}", f"--prop:ip{nic}={ip}",
                 f"--prop:forceNetmask{nic}={netmask}", f"--prop:v6ip{nic}={v6ip}",
                 f"--prop:forceIpv6Prefix{nic}={v6prefix}"]
    else:
        err(f"Invalid value (ipMode{nic}={ip_mode}).")
    return opts


# ---------------------------------------------------------------------------
# Main ovftool command construction (equivalent of the uagdeploy.ps1 body)
# ---------------------------------------------------------------------------

# Direct OVF properties read from [General] (INI key name == property name,
# added only when non-empty) - exactly per uagdeploy.ps1
PASSTHROUGH_PROPS = [
    "rootPasswordExpirationDays", "passwordPolicyMinLen", "passwordPolicyMinClass",
    "passwordPolicyDifok", "passwordPolicyUnlockTime", "passwordPolicyFailedLockout",
    "adminSessionIdleTimeoutMinutes", "defaultGateway", "v6DefaultGateway",
    "forwardrules", "routes0", "routes1", "routes2",
    "policyRouteGateway0", "policyRouteGateway1", "policyRouteGateway2",
    "enabledAdvancedFeatures", "configURL", "configKey", "configURLThumbprints",
    "configURLHttpProxy", "adminCsrSubject", "adminCsrSAN",
    "additionalDeploymentMetadata", "osMaxLoginLimit", "secureRandomSource",
    "sshLoginBannerText", "commandsFirstBoot", "commandsEveryBoot",
    "adminMaxConcurrentSessions", "rootSessionIdleTimeoutSeconds", "gatewaySpec",
]

# INI key -> differently named OVF property
RENAMED_PROPS = {
    "adminPasswordPolicyMinLen": "adminPasswordPolicyMinLen",
    "adminPasswordPolicyUnlockTime": "adminPasswordPolicyUnlockTime",
    "adminPasswordPolicyFailedLockoutCount": "adminPasswordPolicyFailedLockoutCount",
}

TRUE_FLAG_PROPS = ["dsComplianceOS", "tlsPortSharingEnabled", "sshEnabled",
                   "sshKeyAccessEnabled"]


def get_deployment_option(cp) -> str:
    dep = get(cp, "General", "deploymentOption") or "onenic"
    return {"onenic-L": "onenic-large", "twonic-L": "twonic-large",
            "threenic-L": "threenic-large"}.get(dep, dep)


def verify_source(ovftool: str, source: str, no_ssl_verify: bool) -> None:
    args = [ovftool, "--verifyOnly"]
    if no_ssl_verify:
        args.append("--noSSLVerify")
    args.append(source)
    try:
        out = subprocess.run(args, capture_output=True, text=True, timeout=300)
    except (OSError, subprocess.TimeoutExpired) as e:
        err(f"ovftool verification failed: {e}")
    combined = (out.stdout or "") + (out.stderr or "")
    if not re.search(r"File:\s+euc-unified-access-gateway-.*\.vmdk", combined):
        err("Source locator '[General] source' should point to a valid OVA image")


def build_cmd(cp, ovftool: str, root_pwd: str, admin_pwd: str, ceip: str,
              cfg_file: Path, log_file: Path, no_ssl_verify: bool,
              disable_verification: bool) -> list[str]:
    g = lambda k: get(cp, "General", k)  # noqa: E731

    ds = g("ds")
    if not ds:
        err("ds in the [General] section is missing. Set ds= followed by the data store name.")
    ap_name = g("name")
    if len(ap_name) > 32:
        err("Virtual machine name must be no more than 32 characters in length")
    source, target = g("source"), g("target")
    if not source:
        err("Source locator '[General] source' is blank")
    if not target:
        err("Target locator '[General] target' is blank")

    cmd = [
        ovftool,
        "--X:enableHiddenProperties",
        "--X:waitForIp",
        f"--X:logFile={log_file}",
        "--X:logLevel=verbose",
        "--powerOffTarget",
        "--powerOn",
        "--overwrite",
        f"--configFile={cfg_file}",
        f"-ds={ds}",
        f"--name={ap_name}",
        f"--prop:rootPassword={root_pwd}",
    ]

    os_login = g("osLoginUsername") or "root"
    if os_login != "root":
        cmd.append(f"--prop:osLoginUsername={os_login}")
    if admin_pwd:
        cmd.append(f"--prop:adminPassword={admin_pwd}")

    dep = get_deployment_option(cp)
    nics = {"onenic": ["0"], "twonic": ["0", "1"], "threenic": ["0", "1", "2"]}
    for nic in nics.get(dep.split("-")[0], ["0"]):
        cmd += get_net_options(cp, nic)
    cmd.append(f"--deploymentOption={dep}")

    if g("dns"):
        cmd.append(f"--prop:DNS={g('dns')}")   # uppercase DNS - as in the original!

    for key in PASSTHROUGH_PROPS:
        v = g(key)
        if v:
            cmd.append(f"--prop:{key}={v}")
    for ini_key, prop in RENAMED_PROPS.items():
        v = g(ini_key)
        if v:
            cmd.append(f"--prop:{prop}={v}")

    # ceipEnabled: OVF default je True -> nastavuje se jen False
    if ceip.lower() in ("no", "false"):
        cmd.append("--prop:ceipEnabled=False")

    for key in TRUE_FLAG_PROPS:
        if g(key).lower() == "true":
            cmd.append(f"--prop:{key}=True")
    if g("sshPasswordAccessEnabled").lower() == "false":
        cmd.append("--prop:sshPasswordAccessEnabled=False")
    ssh_if = g("sshInterface")
    if ssh_if:
        if ssh_if not in ("eth0", "eth1", "eth2", "all"):
            err(f"Invalid sshInterface ({ssh_if}).")
        cmd.append(f"--prop:sshInterface={ssh_if}")
    ssh_port = g("sshPort")
    if ssh_port and ssh_port.isdigit():
        cmd.append(f"--prop:sshPort={ssh_port}")

    for net_key, ovf_net in (("netInternet", "Internet"),
                             ("netManagementNetwork", "ManagementNetwork"),
                             ("netBackendNetwork", "BackendNetwork")):
        if g(net_key):
            cmd.append(f"--net:{ovf_net}={g(net_key)}")

    if g("diskMode"):
        cmd.append(f"--diskMode={g('diskMode')}")
    if disable_verification:
        cmd.append("--disableVerification")
    if no_ssl_verify:
        cmd.append("--noSSLVerify")
    if g("folder"):
        cmd.append(f"--vmFolder={g('folder')}")

    cmd += [source, target]
    return cmd


def redact(cmd: list[str]) -> str:
    out = []
    for a in cmd:
        if a.startswith(("--prop:rootPassword", "--prop:adminPassword")):
            out.append(a.split("=", 1)[0] + "=********")
        elif a.startswith("vi://") and "@" in a:
            scheme, rest = a.split("://", 1)
            creds, tail = rest.rsplit("@", 1)   # the username itself may contain @
            if ":" in creds:
                out.append(f"{scheme}://{creds.rsplit(':', 1)[0]}:********@{tail}")
            else:
                out.append(a)
        else:
            out.append(a)
    return " \\\n  ".join(shlex.quote(x) for x in out)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Deploy Omnissa UAG to vSphere (Python port of uagdeploy.ps1 25.12.1)")
    ap.add_argument("--ini", default="uag.ini", help="INI file (default uag.ini)")
    ap.add_argument("--ovftool", default=None)
    ap.add_argument("--root-password", dest="root_pwd", default=None)
    ap.add_argument("--admin-password", dest="admin_pwd", default=None)
    ap.add_argument("--ceip-enabled", dest="ceip", default=None,
                    help="yes/no (default: prompt)")
    ap.add_argument("--pfx-password", default=None,
                    help="Password for the PFX from [SSLcert]/[SSLcertAdmin]")
    ap.add_argument("--vcenter-password", default=None,
                    help="Injects the password into the target= vi:// URL when missing")
    ap.add_argument("--no-ssl-verify", action="store_true",
                    help="equivalent of -noSSLVerify")
    ap.add_argument("--disable-verification", action="store_true",
                    help="equivalent of -disableVerification")
    ap.add_argument("--non-interactive", action="store_true",
                    help="no prompts (missing secrets stay empty)")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    print("Unified Access Gateway (UAG) virtual appliance deployment script (Python port)")
    print("Note: If this INI was exported from a UAG and any URL/IP addresses "
          "were changed, review/remove OriginHeaderDetails[index] in the INI "
          "(Admin UI -> Horizon Settings -> Allowed Origins).")

    cp = read_ini(Path(args.ini))
    ap_name = get(cp, "General", "name")
    if not ap_name:
        err("name in [General] is missing.")

    if args.ovftool:
        ovftool = args.ovftool
    else:
        ovftool = locate_ovftool() or ""
    if not ovftool and not args.dry_run:
        err(f"ovftool command not found. Checked: .\\ovftool\\ovftool.exe next to "
            f"the scripts, {WIN_OVFTOOL}, {UNIX_OVFTOOL}, and PATH.")
    ovftool = ovftool or "ovftool"

    interactive = not args.non_interactive

    root_pwd = args.root_pwd or (getpass.getpass(
        f"Root password for {ap_name} (min 8 chars, upper+lower+digit+symbol): ")
        if interactive else "")
    if not root_pwd:
        err("root password is required")
    admin_pwd = args.admin_pwd
    if admin_pwd is None and interactive:
        admin_pwd = getpass.getpass(
            f"Admin password for {ap_name} (empty = no Admin UI/REST API): ")
    admin_pwd = admin_pwd or ""
    ceip = args.ceip
    if ceip is None:
        ceip = (input("Join CEIP (Customer Experience Improvement Program)? yes/no [no]: ")
                if interactive else "no") or "no"

    # inject the password into the vi:// target
    target = get(cp, "General", "target")
    if args.vcenter_password and "@" in target:
        scheme, rest = target.split("://", 1)
        creds, tail = rest.rsplit("@", 1)   # the username itself may contain @
        if ":" not in creds or creds.rindex(":") < creds.rfind("@"):
            # password not present yet -> inject it
            enc = urllib.parse.quote(args.vcenter_password, safe="")
            cp["General"]["target"] = f"{scheme}://{creds}:{enc}@{tail}"

    # OVA verification (as in the original, skipped on dry-run)
    if not args.dry_run:
        verify_source(ovftool, get(cp, "General", "source"), args.no_ssl_verify)

    settings_json = build_settings_json(cp, args.pfx_password, interactive)

    workdir = Path(tempfile.mkdtemp(prefix="uagdeploy-"))
    cfg_file = write_config_file(settings_json, ap_name, workdir)
    log_file = Path(f"log-{ap_name}.txt").resolve()
    log_file.unlink(missing_ok=True)

    cmd = build_cmd(cp, ovftool, root_pwd, admin_pwd, ceip, cfg_file, log_file,
                    args.no_ssl_verify, args.disable_verification)

    print("\n== ovftool command ==")
    print(redact(cmd))
    print(f"\n(settingsJSON: {len(settings_json)} chars -> {cfg_file})")

    try:
        if args.dry_run:
            return 0
        proc = subprocess.run(cmd)
        if proc.returncode == 0:
            if any(a.startswith("--prop:ip0=") for a in cmd):
                print("Note that the IP addresses will be set to the specified "
                      "IP addresses for each NIC")
            print(f"UAG virtual appliance {ap_name} deployed successfully")
        else:
            print(f"UAG deployment failed. Further information may be found "
                  f"in the log file {log_file}")
        return proc.returncode
    finally:
        cfg_file.unlink(missing_ok=True)   # the cfg contains certs/secrets -> always delete


if __name__ == "__main__":
    sys.exit(main())
