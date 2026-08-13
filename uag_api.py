#!/usr/bin/env python3
"""
uag_api.py - Client for the Omnissa UAG Admin REST API (port 9443).

Covers the operations needed for deployment and migration:
  - configuration export / import (GET/PUT /rest/v1/config/settings)
  - TLS certificate upload (PEM)
  - health check / edge service status
  - quiesce mode (controlled drain of the old appliance)

Note: exact endpoint paths may differ slightly between versions -
verify against your version's swagger: https://<UAG>:9443/rest/swagger.yaml
"""

from __future__ import annotations

import json
import ssl
import time
import base64
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Any, Optional


class UagApiError(RuntimeError):
    def __init__(self, status: int, url: str, body: str):
        super().__init__(f"HTTP {status} {url}: {body[:500]}")
        self.status = status
        self.url = url
        self.body = body


@dataclass
class UagClient:
    host: str                       # IP/FQDN of the management interface
    admin_user: str = "admin"
    admin_password: str = ""
    port: int = 9443
    verify_tls: bool = False        # UAG typically has a self-signed cert on 9443
    timeout: int = 60
    _ctx: ssl.SSLContext = field(init=False, repr=False, default=None)

    def __post_init__(self):
        self._ctx = ssl.create_default_context()
        if not self.verify_tls:
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE

    # ------------------------------------------------------------------ core
    @property
    def base_url(self) -> str:
        return f"https://{self.host}:{self.port}/rest/v1"

    def _request(self, method: str, path: str,
                 payload: Any = None,
                 raw_body: Optional[bytes] = None,
                 content_type: str = "application/json",
                 accept: str = "application/json") -> Any:
        url = f"{self.base_url}{path}"
        headers = {
            "Authorization": "Basic " + base64.b64encode(
                f"{self.admin_user}:{self.admin_password}".encode()).decode(),
            "Accept": accept,
        }
        data = None
        if raw_body is not None:
            data = raw_body
            headers["Content-Type"] = content_type
        elif payload is not None:
            data = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx) as resp:
                body = resp.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            raise UagApiError(e.code, url, e.read().decode(errors="replace")) from None

        if not body:
            return None
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return body

    # -------------------------------------------------------------- settings
    def export_settings(self) -> dict:
        """Full UAG configuration as JSON (without passwords/secrets/certificates!)."""
        return self._request("GET", "/config/settings")

    def import_settings(self, settings: dict) -> Any:
        """Imports a previously exported configuration into a (new) appliance."""
        return self._request("PUT", "/config/settings", payload=settings)

    # ----------------------------------------------------------------- certs
    def upload_tls_cert_pem(self, private_key_pem: str, cert_chain_pem: str,
                            interface: str = "internet") -> Any:
        """
        Uploads the TLS server certificate (PEM private key + cert chain).
        interface: 'internet' | 'admin' | 'internetAndAdmin' (per UAG version).
        """
        payload = {
            "privateKeyPem": private_key_pem,
            "certChainPem": cert_chain_pem,
        }
        return self._request("PUT", f"/config/certs/ssl/{interface}", payload=payload)

    # ---------------------------------------------------------------- health
    def get_edge_status(self):
        """
        Edge service status from /monitor/stats. The endpoint returns XML
        (it cannot produce JSON; with Accept: application/json it responds
        406) - we return the XML string, or a dict should a future version
        support JSON.
        """
        return self._request(
            "GET", "/monitor/stats",
            accept="application/xml, application/json;q=0.9, */*;q=0.8")

    @staticmethod
    def edge_status_is_green(stats) -> bool:
        """
        Evaluates the /monitor/stats response (XML string or dict).
        Green = overAllStatus/edge statuses report RUNNING/Reachable
        and none reports ERROR/DOWN/NOT_REACHABLE/STOPPED.
        """
        bad_tokens = ("error", "down", "not_reachable", "unreachable", "stopped")
        if isinstance(stats, str):
            try:
                import xml.etree.ElementTree as ET
                root = ET.fromstring(stats)
            except Exception:
                low = stats.lower()
                return ("running" in low
                        and not any(b in low for b in bad_tokens))
            values = [ (e.text or "").strip().lower()
                       for e in root.iter()
                       if e.tag in ("status", "reason") and e.text
                       and (e.text or "").strip() ]
            if not values:
                return False
            if any(any(b in v for b in bad_tokens) for v in values):
                return False
            return any(v == "running" for v in values)
        # dict / JSON variant
        text = json.dumps(stats).lower()
        return ("running" in text or "reachable" in text) \
            and not any(b in text for b in bad_tokens)

    def get_system_health(self) -> dict:
        return self._request("GET", "/config/system")

    def wait_until_ready(self, max_wait_s: int = 600, interval_s: int = 15,
                         log=print) -> bool:
        """Waits until the Admin API responds (after deploy / reboot)."""
        deadline = time.time() + max_wait_s
        while time.time() < deadline:
            try:
                self.get_system_health()
                log(f"[OK] UAG {self.host} - Admin API is reachable.")
                return True
            except (UagApiError, urllib.error.URLError, TimeoutError, OSError) as e:
                log(f"[..] UAG {self.host} not responding yet ({e.__class__.__name__}), waiting {interval_s}s")
                time.sleep(interval_s)
        return False

    def wait_for_edge_services_green(self, max_wait_s: int = 300,
                                     interval_s: int = 10, log=print) -> bool:
        """Waits until the edge services report RUNNING/Reachable."""
        deadline = time.time() + max_wait_s
        while time.time() < deadline:
            try:
                stats = self.get_edge_status()
                if self.edge_status_is_green(stats):
                    log(f"[OK] UAG {self.host} - edge services report RUNNING/Reachable.")
                    return True
                log(f"[..] Edge services are not green yet, waiting {interval_s}s")
            except Exception as e:
                log(f"[..] Cannot read the status ({e}), waiting {interval_s}s")
            time.sleep(interval_s)
        return False

    # --------------------------------------------------------------- quiesce
    def set_quiesce_mode(self, enabled: bool) -> Any:
        """
        Quiesce mode: the appliance stops accepting new sessions and lets
        existing ones drain - ideal before powering off the old UAG.
        """
        system = self.get_system_health() or {}
        system["quiesceMode"] = enabled
        return self._request("PUT", "/config/system", payload=system)


# ------------------------------------------------------------------ helpers
def load_pem(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def save_json(path: str, data: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
