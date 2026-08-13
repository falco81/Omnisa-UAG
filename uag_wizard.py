#!/usr/bin/env python3
"""
uag_wizard.py - Interactive 1:1 migration wizard for Omnissa Unified Access
Gateway on vSphere.

Run it with no arguments. The wizard walks you through the whole migration:

  1. Connect to vCenter (prompted).
  2. Pick the source UAG VM from a list (arrow keys).
  3. Connect to the UAG Admin API and export the full configuration.
  4. Gracefully shut down / power off the old VM (confirmed first).
  5. Pick the new OVA and the TLS certificate from the script directory.
  6. Answer the deployment questions - everything is pre-filled with the
     values discovered from the old VM (IP, netmask, gateway, DNS, port
     groups, datastore, folder, cluster ...).
  7. The wizard deploys the new appliance with ovftool, waits for the
     Admin API, imports the exported configuration and verifies that the
     edge services come up green.

The old VM is never deleted - it stays powered off as an instant rollback.

Requirements (Windows 10 cmd / PowerShell, Linux, macOS):
    py -m pip install pyvmomi questionary colorama
plus the Broadcom OVF Tool installed, the UAG OVA and the certificate
placed next to this script. Needs uag_deploy.py and uag_api.py in the
same directory.
"""

from __future__ import annotations

import base64
import configparser
import getpass
import json
import re
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse
from datetime import datetime
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

# ---------------------------------------------------------------------------
# Dependencies (friendly failure like the other project tools)
# ---------------------------------------------------------------------------

_MISSING = []
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init()  # enables ANSI on Windows 10 cmd
except ImportError:            # colorama optional -> plain output fallback
    class _P:                  # noqa: D401
        def __getattr__(self, _): return ""
    Fore = Style = _P()
    def colorama_init(): pass  # noqa: E704

try:
    import questionary
    from questionary import Choice
except ImportError:
    _MISSING.append("questionary")

try:
    from pyVim.connect import SmartConnect, Disconnect
    from pyVmomi import vim
except ImportError:
    _MISSING.append("pyvmomi")

try:
    from uag_api import UagClient, UagApiError, describe_error
    import uag_deploy
except ImportError as e:
    print(f"Error: cannot import companion module ({e}). "
          f"Keep uag_deploy.py and uag_api.py next to this script.")
    sys.exit(1)

if _MISSING:
    print(f"Error: missing Python packages: {', '.join(_MISSING)}")
    print(f"Install them with:  py -m pip install {' '.join(_MISSING)}")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Small UI helpers
# ---------------------------------------------------------------------------

def hdr(step: str, title: str) -> None:
    print(f"\n{Fore.CYAN}{Style.BRIGHT}=== [{step}] {title} ==={Style.RESET_ALL}")


def ok(msg: str) -> None:
    print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} {msg}")


def info(msg: str) -> None:
    print(f"{Fore.YELLOW}[i]{Style.RESET_ALL} {msg}")


def warn(msg: str) -> None:
    print(f"{Fore.YELLOW}{Style.BRIGHT}[!]{Style.RESET_ALL} {msg}")


def fail(msg: str, code: int = 1) -> None:
    print(f"{Fore.RED}{Style.BRIGHT}[ERROR]{Style.RESET_ALL} {msg}")
    sys.exit(code)


# Text input mode. All text prompts use the console's cooked mode
# (classic input()), where characters composed with Alt+numpad
# (e.g. Alt+64 for @) work - unlike prompt_toolkit, which discards
# them on Windows. Defaults are pre-filled as EDITABLE text by
# injecting them into the console input buffer (WriteConsoleInputW on
# Windows, readline.insert_text on POSIX). --plain disables the
# injection and shows defaults in [brackets] instead (Enter accepts).
PLAIN_INPUT = False


def _inject_console_text(text: str) -> bool:
    """Windows: push `text` into the console input buffer so the next
    input() call shows it as editable pre-filled content."""
    try:
        import ctypes
        import ctypes.wintypes as wt

        class KEY_EVENT_RECORD(ctypes.Structure):
            _fields_ = [("bKeyDown", wt.BOOL), ("wRepeatCount", wt.WORD),
                        ("wVirtualKeyCode", wt.WORD),
                        ("wVirtualScanCode", wt.WORD),
                        ("UnicodeChar", wt.WCHAR),
                        ("dwControlKeyState", wt.DWORD)]

        class _EVENT(ctypes.Union):
            _fields_ = [("KeyEvent", KEY_EVENT_RECORD)]

        class INPUT_RECORD(ctypes.Structure):
            _fields_ = [("EventType", wt.WORD), ("Event", _EVENT)]

        handle = ctypes.windll.kernel32.GetStdHandle(-10)  # STD_INPUT_HANDLE
        records = (INPUT_RECORD * len(text))()
        for i, ch in enumerate(text):
            records[i].EventType = 0x0001  # KEY_EVENT
            ke = records[i].Event.KeyEvent
            ke.bKeyDown = True
            ke.wRepeatCount = 1
            ke.UnicodeChar = ch
        written = wt.DWORD(0)
        ok = ctypes.windll.kernel32.WriteConsoleInputW(
            handle, records, len(text), ctypes.byref(written))
        return bool(ok) and written.value == len(text)
    except Exception:
        return False


# Colour of the text the user types / edits (matches the questionary look
# the selection lists still use).
INPUT_COLOR = None   # resolved lazily so the colorama fallback works


def _wrap_invisible(seq: str) -> str:
    """On POSIX, wrap zero-width ANSI sequences in \\001..\\002 so readline
    does not count them into the cursor position. Windows (no readline)
    takes them raw."""
    if not seq:
        return ""
    if sys.platform == "win32":
        return seq
    return "\001" + seq + "\002"


# Colour of the values the user types / edits - matches the gold/amber
# answer colour questionary uses for its own prompts (e.g. the 'No' after
# a confirm question). Change here to restyle all inputs at once.
INPUT_STYLE = Style.BRIGHT + Fore.YELLOW


def _colored_prompt(message: str, suffix: str = "") -> str:
    """'[?] message: ' with a green question mark in brackets (matching the
    [i]/[!]/[OK] markers); ends with the colour that the user's typed
    (or pre-filled) text is rendered in."""
    message = message.rstrip().rstrip(":")   # avoid 'IP::' double colons
    return ("[" + _wrap_invisible(Style.BRIGHT + Fore.GREEN) + "?"
            + _wrap_invisible(Style.RESET_ALL) + "]"
            + f" {message}{suffix}: "
            + _wrap_invisible(INPUT_STYLE))


def _marker() -> str:
    """Plain (non-readline) coloured '[?]' for getpass/masked prompts."""
    return f"[{Style.BRIGHT}{Fore.GREEN}?{Style.RESET_ALL}]"


def _reset_color() -> None:
    try:
        sys.stdout.write(Style.RESET_ALL)
        sys.stdout.flush()
    except Exception:
        pass


def _edit_input(message: str, default: str) -> str:
    """Cooked-mode input with an editable pre-filled default. The prompt is
    coloured and the text being typed/edited is rendered in cyan."""
    if default and not PLAIN_INPUT:
        if sys.platform == "win32":
            if _inject_console_text(default):
                try:
                    return input(_colored_prompt(message))
                except EOFError:
                    fail("Aborted by user.", 130)
                finally:
                    _reset_color()
        else:
            try:
                import readline
                readline.set_startup_hook(
                    lambda: readline.insert_text(default))
                try:
                    return input(_colored_prompt(message))
                except EOFError:
                    fail("Aborted by user.", 130)
                finally:
                    readline.set_startup_hook(None)
                    _reset_color()
            except ImportError:
                pass
    # fallback / --plain: show the default in brackets, Enter accepts it
    suffix = f" [{default}]" if default else ""
    try:
        a = input(_colored_prompt(message, suffix))
    except EOFError:
        fail("Aborted by user.", 130)
    finally:
        _reset_color()
    return a if a.strip() else default


def ask_text(message: str, default: str = "", validate=None) -> str:
    while True:
        a = _edit_input(message, default).strip()
        if validate:
            v = validate(a)
            if v is not True:
                warn(v if isinstance(v, str) else "Invalid value, try again.")
                continue
        return a


def uag_password_issues(pwd: str) -> list[str]:
    """UAG default password policy: min 8 chars, upper + lower + digit +
    special character. Returns a list of unmet requirements."""
    issues = []
    if len(pwd) < 8:
        issues.append("at least 8 characters")
    if not re.search(r"[A-Z]", pwd):
        issues.append("an uppercase letter")
    if not re.search(r"[a-z]", pwd):
        issues.append("a lowercase letter")
    if not re.search(r"\d", pwd):
        issues.append("a digit")
    if not re.search(r"[^A-Za-z0-9]", pwd):
        issues.append("a special character")
    return issues


def _masked_input(prompt: str) -> str:
    """
    Password input that echoes '*' for every character. Reads the console
    character by character (msvcrt.getwch on Windows, raw termios on
    POSIX), so Alt+numpad composed characters (e.g. Alt+64 for @) work.
    Backspace erases; Enter confirms. Falls back to getpass when stdin
    is not a real terminal.
    """
    if not sys.stdin.isatty():
        return getpass.getpass(prompt)
    sys.stdout.write(prompt + INPUT_STYLE)
    sys.stdout.flush()
    buf: list[str] = []
    try:
        if sys.platform == "win32":
            import msvcrt
            while True:
                ch = msvcrt.getwch()
                if ch in ("\r", "\n"):
                    break
                if ch == "\x03":
                    raise KeyboardInterrupt
                if ch in ("\x00", "\xe0"):        # arrows / F-keys prefix
                    msvcrt.getwch()               # swallow the second code
                    continue
                if ch == "\x08":                  # backspace
                    if buf:
                        buf.pop()
                        sys.stdout.write("\b \b")
                        sys.stdout.flush()
                    continue
                if ch < " ":                      # other control chars
                    continue
                buf.append(ch)
                sys.stdout.write("*")
                sys.stdout.flush()
        else:
            import termios
            import tty
            fd = sys.stdin.fileno()
            old = termios.tcgetattr(fd)
            try:
                tty.setraw(fd)
                while True:
                    ch = sys.stdin.read(1)
                    if ch in ("\r", "\n"):
                        break
                    if ch == "\x03":
                        raise KeyboardInterrupt
                    if ch in ("\x7f", "\x08"):    # backspace
                        if buf:
                            buf.pop()
                            sys.stdout.write("\b \b")
                            sys.stdout.flush()
                        continue
                    if ch == "\x1b":              # swallow escape sequences
                        sys.stdin.read(1)
                        sys.stdin.read(1)
                        continue
                    if ch < " ":
                        continue
                    buf.append(ch)
                    sys.stdout.write("*")
                    sys.stdout.flush()
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old)
    finally:
        sys.stdout.write(Style.RESET_ALL + "\n")
        sys.stdout.flush()
    return "".join(buf)


def ask_password(message: str, confirm: bool = False,
                 policy: bool = False) -> str:
    """
    Password input with '*' masking. Character-by-character console reads
    (NOT questionary/prompt_toolkit), so Alt+numpad characters
    (e.g. Alt+64 for @) work on Windows.
    """
    message = message.rstrip().rstrip(":")
    while True:
        try:
            a = _masked_input(f"{_marker()} {message}: ")
        except EOFError:
            fail("Aborted by user.", 130)
        if policy:
            issues = uag_password_issues(a)
            if issues:
                warn("UAG password policy requires: " + ", ".join(issues)
                     + ". The deployment would fail - try again.")
                continue
        if not confirm:
            return a
        try:
            b = _masked_input(f"{_marker()} Confirm password: ")
        except EOFError:
            fail("Aborted by user.", 130)
        if a == b:
            return a
        warn("Passwords do not match, try again.")


def ask_select(message: str, choices, default=None):
    a = questionary.select(message, choices=choices, default=default,
                           use_indicator=True).ask()
    if a is None:
        fail("Aborted by user.", 130)
    return a


def ask_confirm(message: str, default: bool = True) -> bool:
    # auto_enter=False: typing y/n does not submit immediately -
    # the answer must be confirmed with Enter.
    a = questionary.confirm(message, default=default, auto_enter=False).ask()
    if a is None:
        fail("Aborted by user.", 130)
    return a


def non_empty(text: str):
    return True if text.strip() else "Value must not be empty"


# ---------------------------------------------------------------------------
# vCenter layer (pyvmomi)
# ---------------------------------------------------------------------------

class VCenter:
    def __init__(self, host: str, user: str, password: str):
        self.host, self.user, self.password = host, user, password
        ctx = ssl._create_unverified_context()
        try:
            self.si = SmartConnect(host=host, user=user, pwd=password,
                                   sslContext=ctx, disableSslCertValidation=True)
        except TypeError:   # older pyvmomi without disableSslCertValidation
            self.si = SmartConnect(host=host, user=user, pwd=password, sslContext=ctx)
        self.content = self.si.RetrieveContent()

    def disconnect(self):
        try:
            Disconnect(self.si)
        except Exception:
            pass

    def list_vms(self) -> list:
        view = self.content.viewManager.CreateContainerView(
            self.content.rootFolder, [vim.VirtualMachine], True)
        vms = list(view.view)
        view.Destroy()
        return vms

    def list_hosts(self) -> list:
        """All ESXi hosts in the inventory (for restore mode, where there is
        no source VM to derive the placement from)."""
        view = self.content.viewManager.CreateContainerView(
            self.content.rootFolder, [vim.HostSystem], True)
        hosts = list(view.view)
        view.Destroy()
        return hosts

    @staticmethod
    def host_placement(host) -> dict:
        """Placement info derived from a host (same shape as vm_placement)."""
        cluster = host.parent if isinstance(host.parent,
                                            vim.ClusterComputeResource) else None
        node = host.parent
        while node and not isinstance(node, vim.Datacenter):
            node = node.parent
        return {
            "datacenter": node.name if node else "",
            "cluster": cluster.name if cluster else "",
            "host": host.name,
            "vm_datastores": [],
            "host_datastores": sorted(d.name for d in host.datastore),
            "host_networks": sorted(n.name for n in host.network),
        }

    # ---------- discovery ---------------------------------------------------

    @staticmethod
    def vm_primary_ip(vm) -> str:
        return (vm.guest.ipAddress or "") if vm.guest else ""

    @staticmethod
    def vm_nics(vm) -> list[dict]:
        """[{network, mac, ips:[(addr,prefix)], connected}] in device order."""
        nics = []
        guest_by_mac = {}
        if vm.guest and vm.guest.net:
            for g in vm.guest.net:
                ips = []
                if g.ipConfig and g.ipConfig.ipAddress:
                    for ip in g.ipConfig.ipAddress:
                        ips.append((ip.ipAddress, ip.prefixLength))
                guest_by_mac[(g.macAddress or "").lower()] = {
                    "network": g.network or "", "ips": ips}
        for dev in vm.config.hardware.device if vm.config else []:
            if isinstance(dev, vim.vm.device.VirtualEthernetCard):
                mac = (dev.macAddress or "").lower()
                g = guest_by_mac.get(mac, {"network": "", "ips": []})
                net_name = g["network"]
                if not net_name and dev.backing:
                    if hasattr(dev.backing, "deviceName"):
                        net_name = dev.backing.deviceName or ""
                    elif hasattr(dev.backing, "port"):
                        # DVS portgroup -> resolve name
                        try:
                            pg_key = dev.backing.port.portgroupKey
                            for net in vm.network:
                                if getattr(net, "key", "") == pg_key:
                                    net_name = net.name
                        except Exception:
                            pass
                nics.append({"network": net_name, "mac": mac, "ips": g["ips"],
                             "connected": bool(dev.connectable and
                                               dev.connectable.connected)})
        return nics

    @staticmethod
    def vm_ipstack(vm) -> dict:
        """{gateway, v6gateway, dns:[...], search:[...]}"""
        out = {"gateway": "", "v6gateway": "", "dns": [], "search": []}
        if not (vm.guest and vm.guest.ipStack):
            return out
        st = vm.guest.ipStack[0]
        if st.dnsConfig:
            out["dns"] = list(st.dnsConfig.ipAddress or [])
            out["search"] = list(st.dnsConfig.searchDomain or [])
        if st.ipRouteConfig and st.ipRouteConfig.ipRoute:
            for r in st.ipRouteConfig.ipRoute:
                gw = r.gateway.ipAddress if r.gateway else None
                if not gw:
                    continue
                if r.network in ("0.0.0.0",) and r.prefixLength == 0:
                    out["gateway"] = gw
                if r.network in ("::",) and r.prefixLength == 0:
                    out["v6gateway"] = gw
        return out

    @staticmethod
    def vm_folder_path(vm) -> str:
        parts = []
        node = vm.parent
        while node and not isinstance(node, vim.Datacenter):
            if isinstance(node, vim.Folder) and node.name != "vm":
                parts.append(node.name)
            node = node.parent
        return "/".join(reversed(parts))

    @staticmethod
    def vm_datacenter(vm):
        node = vm.parent
        while node and not isinstance(node, vim.Datacenter):
            node = node.parent
        return node

    @staticmethod
    def vm_placement(vm) -> dict:
        """{datacenter, cluster, host, datastores:[...], networks:[...],
            host_datastores:[...], host_networks:[...]}"""
        host = vm.runtime.host
        cluster = host.parent if isinstance(host.parent,
                                            vim.ClusterComputeResource) else None
        dc = VCenter.vm_datacenter(vm)
        return {
            "datacenter": dc.name if dc else "",
            "cluster": cluster.name if cluster else "",
            "host": host.name,
            "vm_datastores": [d.name for d in vm.datastore],
            "host_datastores": sorted(d.name for d in host.datastore),
            "host_networks": sorted(n.name for n in host.network),
        }

    # ---------- power -------------------------------------------------------

    @staticmethod
    def wait_task(task, timeout: int = 300) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if task.info.state == vim.TaskInfo.State.success:
                return True
            if task.info.state == vim.TaskInfo.State.error:
                warn(f"vCenter task failed: {task.info.error}")
                return False
            time.sleep(2)
        return False

    def shutdown_vm(self, vm, graceful: bool = True, timeout: int = 180) -> bool:
        if vm.runtime.powerState == vim.VirtualMachinePowerState.poweredOff:
            return True
        if graceful:
            try:
                vm.ShutdownGuest()
                info("Guest shutdown requested, waiting for power off ...")
                deadline = time.time() + timeout
                while time.time() < deadline:
                    if vm.runtime.powerState == \
                            vim.VirtualMachinePowerState.poweredOff:
                        return True
                    time.sleep(3)
                warn("Graceful shutdown timed out, forcing power off.")
            except Exception as e:
                warn(f"Graceful shutdown not possible ({e}), forcing power off.")
        return self.wait_task(vm.PowerOffVM_Task())

# ---------------------------------------------------------------------------
# Local artifact discovery (script directory)
# ---------------------------------------------------------------------------

def scan_ovas() -> list[Path]:
    return sorted(SCRIPT_DIR.glob("*.ova"))


def scan_certs() -> dict:
    """{pfx:[Path], pem_certs:[Path], pem_keys:[Path]}"""
    pems = sorted(list(SCRIPT_DIR.glob("*.pem")) + list(SCRIPT_DIR.glob("*.crt"))
                  + list(SCRIPT_DIR.glob("*.cer")) + list(SCRIPT_DIR.glob("*.key")))
    certs, keys = [], []
    for p in pems:
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        if "PRIVATE KEY" in text:
            keys.append(p)
        elif "BEGIN CERTIFICATE" in text:
            certs.append(p)
    return {"pfx": sorted(list(SCRIPT_DIR.glob("*.pfx")) + list(SCRIPT_DIR.glob("*.p12"))),
            "pem_certs": certs, "pem_keys": keys}


def prefix_to_netmask(prefix: int) -> str:
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF if prefix else 0
    return ".".join(str((mask >> s) & 0xFF) for s in (24, 16, 8, 0))


def is_ipv4(addr: str) -> bool:
    return bool(re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", addr))


# ---------------------------------------------------------------------------
# Wizard steps
# ---------------------------------------------------------------------------

def step_vcenter() -> VCenter:
    hdr("1/8", "Connect to vCenter")
    while True:
        host = ask_text("vCenter hostname / IP:", validate=non_empty)
        user = ask_text("vCenter username:", default="administrator@vsphere.local",
                        validate=non_empty)
        pwd = ask_password(f"Password for {user}:")
        try:
            info(f"Connecting to {host} ...")
            vc = VCenter(host, user, pwd)
            about = vc.content.about
            ok(f"Connected: {about.fullName}")
            return vc
        except Exception as e:
            warn(f"Connection failed: {describe_error(e)}")
            if not ask_confirm("Try again?", default=True):
                fail("Cannot continue without vCenter.", 2)


def step_pick_source_vm(vc: VCenter):
    hdr("2/8", "Select the source UAG virtual machine")
    flt = ask_text("Filter VM names (substring, empty = show all):", default="uag")
    vms = vc.list_vms()
    matching = [v for v in vms if flt.lower() in v.name.lower()] if flt else vms
    if not matching:
        warn(f"No VM matches '{flt}', showing all {len(vms)} VMs.")
        matching = vms
    if not matching:
        fail("No virtual machines found in this vCenter.", 2)

    choices = []
    for v in sorted(matching, key=lambda x: x.name.lower()):
        state = str(v.runtime.powerState).replace("powered", "")
        ip = VCenter.vm_primary_ip(v)
        label = f"{v.name:<34} {state:<4} {ip}"
        choices.append(Choice(title=label, value=v))
    vm = ask_select("Source UAG VM (arrow keys, Enter to confirm):", choices)

    if vm.runtime.powerState != vim.VirtualMachinePowerState.poweredOn:
        fail(f"VM '{vm.name}' is not powered on - the wizard needs to reach its "
             f"Admin API to export the configuration.", 2)
    ip = VCenter.vm_primary_ip(vm)
    if not ip:
        ip = ask_text("VMware Tools did not report an IP. Enter the UAG "
                      "management IP manually:", validate=non_empty)
    ok(f"Selected '{vm.name}' ({ip})")
    return vm, ip


def step_discover(vc: VCenter, vm) -> dict:
    hdr("3/8", "Discover source VM settings")
    d = {
        "name": vm.name,
        "primary_ip": VCenter.vm_primary_ip(vm),
        "nics": VCenter.vm_nics(vm),
        "ipstack": VCenter.vm_ipstack(vm),
        "placement": VCenter.vm_placement(vm),
        "folder": VCenter.vm_folder_path(vm),
    }
    pl, st = d["placement"], d["ipstack"]
    print(f"    VM name    : {d['name']}")
    print(f"    Datacenter : {pl['datacenter']}   Cluster: {pl['cluster'] or '-'}   "
          f"Host: {pl['host']}")
    print(f"    Datastore  : {', '.join(pl['vm_datastores'])}")
    print(f"    Folder     : {d['folder'] or '(datacenter root)'}")
    for i, nic in enumerate(d["nics"]):
        ips = ", ".join(f"{a}/{p}" for a, p in nic["ips"] if is_ipv4(a)) or "-"
        print(f"    NIC{i}       : portgroup '{nic['network']}'  IP: {ips}")
    print(f"    Gateway    : {st['gateway'] or '-'}    DNS: "
          f"{' '.join(st['dns']) or '-'}    Search: {' '.join(st['search']) or '-'}")
    return d


def step_export_config(mgmt_ip: str, vm_name: str) -> tuple[dict, Path, str]:
    hdr("4/8", "Export configuration from the source UAG")
    while True:
        admin_pwd = ask_password(f"UAG admin password for https://{mgmt_ip}:9443 :")
        client = UagClient(host=mgmt_ip, admin_user="admin",
                           admin_password=admin_pwd)
        try:
            info("Exporting settings via REST API ...")
            settings = client.export_settings()
            break
        except UagApiError as e:
            if e.status in (401, 403):
                warn("Authentication failed, try again.")
                continue
            fail(f"Export failed: {e}", 3)
        except Exception as e:
            fail(f"Cannot reach the UAG Admin API on {mgmt_ip}:9443 ({describe_error(e)}).", 3)

    out = SCRIPT_DIR / f"uag_settings_{vm_name}_{datetime.now():%Y%m%d_%H%M%S}.json"
    out.write_text(json.dumps(settings, indent=2), encoding="utf-8")
    ok(f"Configuration exported -> {out.name}")

    # secrets that are never included in the export
    missing = find_missing_secrets(settings)
    if missing:
        warn("The export never contains these secrets - you can enter them now "
             "so the import restores a complete configuration:")
        entered = 0
        for key_path in missing:
            val = _masked_input(f"  {_marker()} value for {key_path} "
                                f"(Enter = leave empty): ")
            if val:
                set_by_path(settings, key_path, val)
                entered += 1
        if entered:
            out.write_text(json.dumps(settings, indent=2), encoding="utf-8")
            warn(f"{out.name} now contains the secrets you entered - "
                 f"delete the file after the migration.")
    info(f"You can still edit {out.name} manually (e.g. add a RADIUS secret) - "
         f"the file is re-read from disk right before the import step.")
    info("Note: keytab files and some binary blobs can never be migrated "
         "automatically - re-upload them in the Admin UI if you use Kerberos.")
    return settings, out, admin_pwd


SECRET_HINTS = ("password", "secret", "sharedsecret", "passphrase",
                "privatekey", "clientsecret")

# Keys the heuristic would match but which are NOT secrets - just UI texts
# or toggles. E.g. radiusCustomPassphraseHint is the "Login page passphrase
# hint" shown to end users in the Horizon Client login prompt.
NOT_SECRETS = ("hint", "label", "expiration", "policy", "enabled",
               "protected", "required")


def find_missing_secrets(settings: dict) -> list[str]:
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


def set_by_path(settings: dict, path: str, value: str) -> None:
    tokens = re.findall(r"([^.\[\]]+)|\[(\d+)\]", path)
    node = settings
    flat = [t[0] if t[0] else int(t[1]) for t in tokens]
    for t in flat[:-1]:
        node = node[t]
    node[flat[-1]] = value


def step_poweroff_old(vc: VCenter, vm) -> None:
    hdr("5/8", "Shut down the source VM")
    warn("The new appliance will reuse the same IP address, so the old VM "
         "must be down before the deployment starts.")
    mode = ask_select("How do you want to stop the old VM?", [
        Choice("Graceful guest shutdown (recommended)", value="graceful"),
        Choice("Hard power off", value="hard"),
        Choice("Skip - I will handle it myself (risk of IP conflict!)",
               value="skip"),
    ])
    if mode == "skip":
        warn("Skipping - make sure the old VM is down before continuing!")
        return
    if not vc.shutdown_vm(vm, graceful=(mode == "graceful")):
        fail("Could not power off the source VM.", 4)
    ok(f"'{vm.name}' is powered off (kept as instant rollback - never deleted).")


def step_pick_artifacts() -> dict:
    hdr("6/8", "Select the OVA image and TLS certificate")
    ovas = scan_ovas()
    if not ovas:
        fail(f"No .ova file found in {SCRIPT_DIR}. Download the UAG OVA from "
             f"the Omnissa portal and place it next to this script.", 2)
    ova = ask_select("UAG OVA image:", [Choice(p.name, value=p) for p in ovas])
    if "euc-unified-access-gateway" not in ova.name:
        warn(f"'{ova.name}' does not look like a UAG image - continuing anyway.")

    certs = scan_certs()
    cert_choices = []
    for p in certs["pfx"]:
        cert_choices.append(Choice(f"PFX  {p.name}", value=("pfx", p)))
    for c in certs["pem_certs"]:
        cert_choices.append(Choice(f"PEM  {c.name}  (+ key selected next)",
                                   value=("pem", c)))
    cert_choices.append(Choice("None - deploy with a self-signed certificate",
                               value=("none", None)))
    kind, cert_path = ask_select("TLS server certificate:", cert_choices)

    result = {"ova": ova, "cert_kind": kind, "cert": cert_path,
              "key": None, "pfx_password": "", "cert_admin_too": False}
    if kind == "pfx":
        result["pfx_password"] = ask_password(
            f"Password for {cert_path.name} (Enter = none):")
    elif kind == "pem":
        if not certs["pem_keys"]:
            fail("No PEM private key found next to the script.", 2)
        key = ask_select("PEM private key:",
                         [Choice(p.name, value=p) for p in certs["pem_keys"]])
        text = key.read_text(errors="replace")
        if "BEGIN RSA PRIVATE KEY" not in text:
            fail(f"{key.name} is not a PKCS#1 RSA key. Convert it first:\n"
                 f"        openssl rsa -in {key.name} -traditional "
                 f"-out {key.stem}_pkcs1.pem", 2)
        result["key"] = key
    if kind != "none":
        result["cert_admin_too"] = ask_confirm(
            "Apply the same certificate to the admin interface (9443) as "
            "well? (No = admin keeps a self-signed cert)", default=False)
    ok(f"OVA: {ova.name}   Certificate: "
       f"{cert_path.name if cert_path else 'self-signed'}")
    return result

# ---------------------------------------------------------------------------
# Step 7 - deployment parameters (everything pre-filled from discovery)
# ---------------------------------------------------------------------------

DEPLOYMENT_OPTIONS = ["onenic", "onenic-large", "twonic", "twonic-large",
                      "threenic", "threenic-large"]
NIC_ROLES = ["Internet", "ManagementNetwork", "BackendNetwork"]
NIC_NET_KEYS = ["netInternet", "netManagementNetwork", "netBackendNetwork"]


def step_deploy_params(vc: VCenter, disco: dict, artifacts: dict,
                       settings: dict) -> dict:
    hdr("7/8", "New appliance parameters (pre-filled from the source VM)")
    pl, st = disco["placement"], disco["ipstack"]
    p: dict = {}

    # --- identity ----------------------------------------------------------
    def name_ok(v):
        v = v.strip()
        if not v:
            return "Name must not be empty"
        if len(v) > 32:
            return "Max 32 characters (ovftool limit)"
        return True
    p["name"] = ask_text("New VM name:", default=f"{disco['name']}-new",
                         validate=name_ok)
    if p["name"] == disco["name"]:
        warn("Same name as the source VM - ovftool --overwrite would DELETE it!")
        if not ask_confirm("Really replace the old VM in place?", default=False):
            p["name"] = ask_text("New VM name:", default=f"{disco['name']}-new",
                                 validate=name_ok)
    # uagName pre-filled from the exported configuration ("uagName" in
    # systemSettings), falling back to the source VM name
    uag_name_default = ((settings.get("systemSettings") or {}).get("uagName")
                        or disco["name"])
    p["uagName"] = ask_text("UAG appliance name (uagName):",
                            default=uag_name_default)

    # --- sizing / nic count ------------------------------------------------
    nic_count = max(1, min(3, len(disco["nics"])))
    default_dep = {1: "onenic", 2: "twonic", 3: "threenic"}[nic_count]
    p["deploymentOption"] = ask_select("Deployment option:", DEPLOYMENT_OPTIONS,
                                       default=default_dep)
    want_nics = {"onenic": 1, "twonic": 2, "threenic": 3}[
        p["deploymentOption"].split("-")[0]]

    # --- networking per NIC -------------------------------------------------
    networks = pl["host_networks"] or [""]
    p["nics"] = []
    for i in range(want_nics):
        old = disco["nics"][i] if i < len(disco["nics"]) else \
            {"network": "", "ips": []}
        v4 = next(((a, pre) for a, pre in old["ips"] if is_ipv4(a)), None)
        print(f"{Fore.CYAN}  --- NIC{i} ({NIC_ROLES[i]}) ---{Style.RESET_ALL}")
        net_default = old["network"] if old["network"] in networks else networks[0]
        net = ask_select(f"  Port group for NIC{i}:", networks,
                         default=net_default)
        ip = ask_text(f"  IPv4 address for NIC{i} (empty = DHCP):",
                      default=v4[0] if v4 else "")
        mask = ""
        if ip:
            mask = ask_text(f"  Netmask for NIC{i}:",
                            default=prefix_to_netmask(v4[1]) if v4 else
                            "255.255.255.0", validate=non_empty)
        p["nics"].append({"network": net, "ip": ip, "netmask": mask})

    p["defaultGateway"] = ask_text("Default gateway:", default=st["gateway"])
    p["dns"] = ask_text("DNS servers (space separated):",
                        default=" ".join(st["dns"][:2]))
    p["dnsSearch"] = ask_text("DNS search domains (space separated):",
                              default=" ".join(st["search"][:2]))

    # --- placement ---------------------------------------------------------
    p["ds"] = ask_select("Datastore:", pl["host_datastores"] or ["datastore1"],
                         default=(pl["vm_datastores"][0]
                                  if pl["vm_datastores"] and
                                  pl["vm_datastores"][0] in pl["host_datastores"]
                                  else None))
    p["folder"] = ask_text("VM folder (empty = datacenter root):",
                           default=disco["folder"])
    p["diskMode"] = ask_select("Disk provisioning:",
                               ["thin", "thick", "eagerZeroedThick"],
                               default="thin")

    compute_default = pl["cluster"] or pl["host"]
    compute = ask_text("Target cluster or host (ovftool path element):",
                       default=compute_default, validate=non_empty)
    enc_user = urllib.parse.quote(vc.user, safe="")
    enc_pwd = urllib.parse.quote(vc.password, safe="")
    p["target"] = (f"vi://{enc_user}:{enc_pwd}@{vc.host}/"
                   f"{pl['datacenter']}/host/{compute}")
    p["target_display"] = (f"vi://{vc.user}:********@{vc.host}/"
                           f"{pl['datacenter']}/host/{compute}")

    # --- appliance credentials ---------------------------------------------
    p["root_pwd"] = ask_password("Root password for the new appliance:",
                                 confirm=True, policy=True)
    p["admin_pwd"] = ask_password("Admin password for the new appliance "
                                  "(Admin UI / REST):", confirm=True,
                                  policy=True)
    p["ceip"] = "yes" if ask_confirm("Join CEIP (Customer Experience "
                                     "Improvement Program)?", default=False) \
        else "no"
    p["ssh"] = ask_confirm("Enable SSH on the appliance?", default=False)
    return p


def build_ini(disco: dict, artifacts: dict, p: dict) -> configparser.ConfigParser:
    cp = configparser.ConfigParser(interpolation=None, strict=False)
    cp.optionxform = str
    cp.add_section("General")
    g = cp["General"]
    g["name"] = p["name"]
    g["uagName"] = p["uagName"]
    g["source"] = str(artifacts["ova"])
    g["target"] = p["target"]
    g["ds"] = p["ds"]
    if p["folder"]:
        g["folder"] = p["folder"]
    g["diskMode"] = p["diskMode"]
    g["deploymentOption"] = p["deploymentOption"]
    for i, nic in enumerate(p["nics"]):
        g[NIC_NET_KEYS[i]] = nic["network"]
        if nic["ip"]:
            g[f"ip{i}"] = nic["ip"]
            g[f"netmask{i}"] = nic["netmask"]
    if p["defaultGateway"]:
        g["defaultGateway"] = p["defaultGateway"]
    if p["dns"]:
        g["dns"] = p["dns"]
    if p["dnsSearch"]:
        g["dnsSearch"] = p["dnsSearch"]
    if p["ssh"]:
        g["sshEnabled"] = "true"

    if artifacts["cert_kind"] == "pfx":
        cp.add_section("SSLCert")
        cp["SSLCert"]["pfxCerts"] = str(artifacts["cert"])
        if artifacts.get("cert_admin_too"):
            cp.add_section("SSLCertAdmin")
            cp["SSLCertAdmin"]["pfxCerts"] = str(artifacts["cert"])
    elif artifacts["cert_kind"] == "pem":
        cp.add_section("SSLCert")
        cp["SSLCert"]["pemCerts"] = str(artifacts["cert"])
        cp["SSLCert"]["pemPrivKey"] = str(artifacts["key"])
        if artifacts.get("cert_admin_too"):
            cp.add_section("SSLCertAdmin")
            cp["SSLCertAdmin"]["pemCerts"] = str(artifacts["cert"])
            cp["SSLCertAdmin"]["pemPrivKey"] = str(artifacts["key"])
    return cp


# ---------------------------------------------------------------------------
# Step 8 - deploy + restore
# ---------------------------------------------------------------------------

def find_ovftool() -> str:
    found = uag_deploy.locate_ovftool()
    if not found:
        fail("ovftool not found. Place the portable OVF Tool in an 'ovftool' "
             "folder next to this script, or install it to "
             f"{uag_deploy.WIN_OVFTOOL}.", 2)
    info(f"Using ovftool: {found}")
    return found


def step_deploy_and_restore(cp: configparser.ConfigParser, artifacts: dict,
                            p: dict, settings_file: Path) -> int:
    hdr("8/8", "Deploy the new appliance and restore the configuration")

    # summary --------------------------------------------------------------
    print(f"{Style.BRIGHT}  Deployment summary{Style.RESET_ALL}")
    print(f"    VM name    : {p['name']}   ({p['deploymentOption']}, "
          f"{p['diskMode']})")
    print(f"    OVA        : {artifacts['ova'].name}")
    print(f"    Target     : {p['target_display']}")
    print(f"    Datastore  : {p['ds']}    Folder: {p['folder'] or '-'}")
    for i, nic in enumerate(p["nics"]):
        addr = f"{nic['ip']}/{nic['netmask']}" if nic["ip"] else "DHCP"
        print(f"    NIC{i}       : {nic['network']}  {addr}")
    print(f"    Gateway    : {p['defaultGateway'] or '-'}    "
          f"DNS: {p['dns'] or '-'}")
    cert_name = artifacts["cert"].name if artifacts["cert"] else "self-signed"
    print(f"    Certificate: {cert_name}")
    if not ask_confirm("Proceed with the deployment?", default=True):
        fail("Aborted by user.", 130)

    ovftool = find_ovftool()
    info("Verifying the OVA image with ovftool --verifyOnly ...")
    uag_deploy.verify_source(ovftool, str(artifacts["ova"]), no_ssl_verify=True)

    settings_json = uag_deploy.build_settings_json(
        cp, artifacts["pfx_password"], interactive=False)
    workdir = Path(tempfile.mkdtemp(prefix="uag-wizard-"))
    cfg_file = uag_deploy.write_config_file(settings_json, p["name"], workdir)
    log_file = SCRIPT_DIR / f"log-{p['name']}.txt"
    log_file.unlink(missing_ok=True)

    cmd = uag_deploy.build_cmd(cp, ovftool, p["root_pwd"], p["admin_pwd"],
                               p["ceip"], cfg_file, log_file,
                               no_ssl_verify=True, disable_verification=False)
    info("Starting ovftool deployment (this typically takes 5-15 minutes) ...")
    try:
        rc = subprocess.run(cmd).returncode
    finally:
        cfg_file.unlink(missing_ok=True)   # contains certificates / secrets
    if rc != 0:
        fail(f"ovftool failed (exit {rc}). See {log_file.name} for details. "
             f"The old VM is untouched - power it back on to roll back.", 5)
    ok(f"Appliance '{p['name']}' deployed and powered on.")

    # restore --------------------------------------------------------------
    new_ip = next((n["ip"] for n in p["nics"] if n["ip"]), "")
    if not new_ip:
        new_ip = ask_text("DHCP was used - enter the IP the new appliance "
                          "received:", validate=non_empty)
    client = UagClient(host=new_ip, admin_user="admin",
                       admin_password=p["admin_pwd"])
    info(f"Waiting for the Admin API on https://{new_ip}:9443 ...")
    if not client.wait_until_ready(max_wait_s=900, interval_s=15, log=info):
        fail("The new appliance did not come up in time.", 6)

    # Re-read the migration JSON from disk right before the import - this
    # picks up any manual edits made while the deployment was running
    # (e.g. a RADIUS shared secret added to the file).
    info(f"Re-reading {settings_file.name} from disk "
         f"(picks up any manual edits made during the deployment) ...")
    while True:
        try:
            settings = json.loads(settings_file.read_text(encoding="utf-8-sig"))
            break
        except FileNotFoundError:
            warn(f"{settings_file} no longer exists!")
            if not ask_confirm("Restore the file and retry?", default=True):
                fail("Aborted - the new appliance is deployed but has no "
                     "configuration imported yet.", 7)
        except json.JSONDecodeError as e:
            warn(f"{settings_file.name} is not valid JSON: {e}")
            if not ask_confirm("Fix the file and retry?", default=True):
                fail("Aborted - the new appliance is deployed but has no "
                     "configuration imported yet.", 7)

    info("Importing the exported configuration (1:1 restore) ...")
    try:
        client.import_settings(settings)
    except UagApiError as e:
        warn(f"Import failed: {e}")
        warn("Common causes: sha1 thumbprints (replace with sha256) or legacy "
             "cipher suites in the exported JSON. Fix the JSON and re-run the "
             "import with:  python uag_migrate.py import --host "
             f"{new_ip} --settings <file> --force")
        return 7
    ok("Configuration imported.")

    info("Waiting for edge services to turn green ...")
    if client.wait_for_edge_services_green(max_wait_s=420, interval_s=15,
                                           log=info):
        ok("All edge services report healthy.")
    else:
        warn("Edge services are not green yet - check the Admin UI "
             f"(https://{new_ip}:9443/admin/).")

    print(f"\n{Fore.GREEN}{Style.BRIGHT}Migration finished.{Style.RESET_ALL}")
    print("  Next steps:")
    print("    1. Test a real client connection through the new appliance "
          "(Blast / PCoIP / tunnel).")
    print("    2. If a load balancer or NAT points at this UAG, no change is "
          "needed - the IP was kept.")
    print("    3. The old VM is powered off, not deleted - it is your instant "
          "rollback. Delete it once you are happy.")
    return 0


# ---------------------------------------------------------------------------
# Restore mode (--settings): deploy a new appliance from an existing
# migration JSON without touching any source VM
# ---------------------------------------------------------------------------

def step_load_settings(path: Path) -> dict:
    hdr("2/6", "Load the migration JSON")
    while True:
        try:
            settings = json.loads(path.read_text(encoding="utf-8-sig"))
            break
        except FileNotFoundError:
            fail(f"Settings file not found: {path}", 2)
        except json.JSONDecodeError as e:
            warn(f"{path.name} is not valid JSON: {e}")
            if not ask_confirm("Fix the file and retry?", default=True):
                fail("Aborted by user.", 130)
    uag_name = (settings.get("systemSettings") or {}).get("uagName", "")
    svc_count = len(((settings.get("edgeServiceSettingsList") or {})
                     .get("edgeServiceSettingsList")) or [])
    ok(f"Loaded {path.name}  (uagName: {uag_name or '-'}, "
       f"edge services: {svc_count})")

    # the export never contains secrets - offer to enter them now
    missing = find_missing_secrets(settings)
    if missing:
        warn("The JSON contains services whose secrets are empty (the UAG "
             "export never includes them). Enter them now (Enter = skip):")
        entered = 0
        for key_path in missing:
            val = _masked_input(f"  {_marker()} value for {key_path}: ")
            if val:
                set_by_path(settings, key_path, val)
                entered += 1
        if entered:
            path.write_text(json.dumps(settings, indent=2), encoding="utf-8")
            warn(f"{path.name} now contains the secrets you entered - "
                 f"delete the file after the migration.")
    return settings


def step_pick_target(vc: VCenter) -> dict:
    hdr("3/6", "Select the deployment target (cluster / host)")
    hosts = vc.list_hosts()
    if not hosts:
        fail("No ESXi hosts found in this vCenter.", 2)
    choices = []
    for h in sorted(hosts, key=lambda x: x.name.lower()):
        pl = VCenter.host_placement(h)
        label = (f"{pl['datacenter']} / "
                 f"{pl['cluster'] + ' / ' if pl['cluster'] else ''}{pl['host']}")
        choices.append(Choice(title=label, value=h))
    host = ask_select("Target host (arrow keys, Enter to confirm):", choices)
    pl = VCenter.host_placement(host)
    ok(f"Target: datacenter '{pl['datacenter']}', "
       f"cluster '{pl['cluster'] or '-'}', host '{pl['host']}'")
    return pl


def run_restore_mode(settings_path: Path) -> int:
    print("  Restore mode: deploying a new appliance from an existing")
    print("  migration JSON - no source VM is touched.")
    warn("Make sure the IP address you assign is free (the original "
         "appliance, if any, must be powered off).")

    vc = step_vcenter()
    try:
        settings = step_load_settings(settings_path)
        placement = step_pick_target(vc)
        artifacts = step_pick_artifacts()

        uag_name = (settings.get("systemSettings") or {}).get("uagName", "")
        disco = {
            "name": uag_name or settings_path.stem,
            "primary_ip": "",
            "nics": [],
            "ipstack": {"gateway": "", "v6gateway": "", "dns": [], "search": []},
            "placement": placement,
            "folder": "",
        }
        params = step_deploy_params(vc, disco, artifacts, settings)
        cp = build_ini(disco, artifacts, params)
        return step_deploy_and_restore(cp, artifacts, params, settings_path)
    finally:
        vc.disconnect()


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> int:
    global PLAIN_INPUT
    import argparse
    ap = argparse.ArgumentParser(
        description="Omnissa UAG 1:1 Migration Wizard (vSphere)")
    ap.add_argument("--plain", action="store_true",
                    help="Do not pre-fill text prompts as editable text; "
                         "show defaults in [brackets] instead (Enter "
                         "accepts). Alt+numpad characters work in all "
                         "inputs in both modes.")
    ap.add_argument("--settings", metavar="FILE", default=None,
                    help="Restore mode: skip the source-VM steps and deploy "
                         "a new appliance restoring the configuration from "
                         "this migration JSON (exported earlier via the "
                         "wizard or 'uag_migrate.py export').")
    args = ap.parse_args()
    PLAIN_INPUT = args.plain

    print(f"{Fore.CYAN}{Style.BRIGHT}")
    print("  Omnissa UAG 1:1 Migration Wizard  (vSphere)")
    print(f"  {'-' * 44}{Style.RESET_ALL}")
    if not args.settings:
        print("  Exports the configuration from an existing UAG, shuts it down,")
        print("  deploys a new appliance from an OVA in this directory and")
        print("  restores the configuration - keeping the same IP address.")
    if PLAIN_INPUT:
        info("Plain input mode: defaults are shown in [brackets]; press "
             "Enter to accept them.")

    if not sys.stdin.isatty():
        fail("This wizard is interactive - run it in a real terminal.", 2)

    if args.settings:
        return run_restore_mode(Path(args.settings))

    vc = step_vcenter()
    try:
        vm, mgmt_ip = step_pick_source_vm(vc)
        disco = step_discover(vc, vm)
        settings, settings_file, _ = step_export_config(mgmt_ip, vm.name)
        step_poweroff_old(vc, vm)
        artifacts = step_pick_artifacts()
        params = step_deploy_params(vc, disco, artifacts, settings)
        cp = build_ini(disco, artifacts, params)
        return step_deploy_and_restore(cp, artifacts, params, settings_file)
    finally:
        vc.disconnect()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nAborted by user.")
        sys.exit(130)
