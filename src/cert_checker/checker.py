"""
AWS Lambda friendly implementation of the OCSPDocker certificate checker.

The implementation mirrors the logic from https://github.com/jgoodloe/OCSPDocker
but removes the long-running scheduler so that a Lambda invocation can process
one or more certificate configurations at a time.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import boto3
import botocore
import requests
import urllib.parse
import urllib3
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.ocsp import OCSPRequestBuilder

# Disable SSL warnings for CRL downloads (CRLs may use HTTP)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


DEFAULT_CONFIG_PATH = "config.yaml"


@dataclass
class CertificateSource:
    """Represents a certificate input."""

    path: Optional[str] = None
    pem: Optional[str] = None
    pem_base64: Optional[str] = None
    s3: Optional[Dict[str, str]] = None


@dataclass
class NotificationConfig:
    http_push: Optional[Dict[str, Any]] = None
    webhook: Optional[Dict[str, Any]] = None
    teams: Optional[Dict[str, Any]] = None
    google_chat: Optional[Dict[str, Any]] = None
    sms: Optional[Dict[str, Any]] = None


@dataclass
class CheckConfig:
    certificate: CertificateSource
    certificate_chain: Optional[CertificateSource] = None
    cert_expiry_warning_hours: int = 24
    cert_expiry_warning_days: int = 30
    crl_expiry_warning_hours: int = 24
    crl_expiry_warning_minutes: int = 60
    notifications: NotificationConfig = field(default_factory=NotificationConfig)
    metadata: Dict[str, Any] = field(default_factory=dict)


def _load_yaml_if_exists(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {}
    import yaml

    with open(path, "r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def _resolve_source(source: CertificateSource) -> Tuple[bytes, Optional[str]]:
    """Return raw certificate bytes and an error if one occurs."""

    if source.path:
        try:
            return Path(source.path).read_bytes(), None
        except Exception as exc:  # pragma: no cover - direct IO error path
            return b"", f"Failed to read certificate file {source.path}: {exc}"

    if source.pem:
        return source.pem.encode("utf-8"), None

    if source.pem_base64:
        try:
            return base64.b64decode(source.pem_base64), None
        except Exception as exc:
            return b"", f"Failed to decode base64 certificate: {exc}"

    if source.s3:
        bucket = source.s3.get("bucket")
        key = source.s3.get("key")
        version_id = source.s3.get("version_id")
        if not bucket or not key:
            return b"", "S3 certificate source missing bucket/key"
        try:
            s3 = boto3.client("s3")
            get_kwargs = {"Bucket": bucket, "Key": key}
            if version_id:
                get_kwargs["VersionId"] = version_id
            obj = s3.get_object(**get_kwargs)
            return obj["Body"].read(), None
        except botocore.exceptions.BotoCoreError as exc:
            return b"", f"Failed to fetch certificate from S3: {exc}"
        except botocore.exceptions.ClientError as exc:  # pragma: no cover - AWS error path
            return b"", f"Failed to fetch certificate from S3: {exc}"

    return b"", "No certificate source defined"


def _split_pem_chain(chain_bytes: bytes) -> List[x509.Certificate]:
    certs = []
    for pem_cert in chain_bytes.split(b"-----BEGIN CERTIFICATE-----"):
        if pem_cert.strip():
            pem_cert = b"-----BEGIN CERTIFICATE-----" + pem_cert
            try:
                certs.append(x509.load_pem_x509_certificate(pem_cert, default_backend()))
            except Exception:
                continue
    return certs


def load_config_from_event(event: Dict[str, Any], env: Optional[Dict[str, str]] = None) -> Tuple[List[CheckConfig], Dict[str, Any]]:
    """
    Merge Lambda event payload with environment defaults (or config file)
    and return a list of CheckConfig objects.
    """

    env = env or os.environ
    config_path = env.get("CONFIG_PATH", DEFAULT_CONFIG_PATH)
    base_config = _load_yaml_if_exists(config_path)

    if not base_config and env.get("CERTIFICATE_PATH"):
        base_config = {
            "certificate": env.get("CERTIFICATE_PATH"),
            "cert_expiry_warning_hours": int(env.get("CERT_EXPIRY_WARNING_HOURS", 24)),
            "cert_expiry_warning_days": int(env.get("CERT_EXPIRY_WARNING_DAYS", 30)),
            "crl_expiry_warning_hours": int(env.get("CRL_EXPIRY_WARNING_HOURS", 24)),
            "crl_expiry_warning_minutes": int(env.get("CRL_EXPIRY_WARNING_MINUTES", 60)),
        }

    defaults = event.get("defaults", base_config)
    requests_payload = event.get("certificates") or [event]

    configs: List[CheckConfig] = []

    for payload in requests_payload:
        merged = {**defaults, **payload}
        cert_source = CertificateSource(
            path=merged.get("certificate") or merged.get("certificate_path"),
            pem=merged.get("certificate_pem"),
            pem_base64=merged.get("certificate_pem_base64"),
            s3=merged.get("certificate_s3"),
        )

        chain_conf = merged.get("certificate_chain") or merged.get("certificate_chain_source")
        chain_source = None
        if chain_conf:
            if isinstance(chain_conf, dict):
                chain_source = CertificateSource(
                    path=chain_conf.get("path"),
                    pem=chain_conf.get("pem"),
                    pem_base64=chain_conf.get("pem_base64"),
                    s3=chain_conf.get("s3"),
                )
            else:
                chain_source = CertificateSource(path=chain_conf)

        notifications = NotificationConfig(
            http_push=merged.get("notifications", {}).get("http_push") or _maybe_url("HTTP_PUSH_URL", env),
            webhook=merged.get("notifications", {}).get("webhook") or _maybe_url("WEBHOOK_URL", env),
            teams=merged.get("notifications", {}).get("teams") or _maybe_url("TEAMS_WEBHOOK_URL", env),
            google_chat=merged.get("notifications", {}).get("google_chat") or _maybe_url("GOOGLE_CHAT_WEBHOOK_URL", env),
            sms=merged.get("notifications", {}).get("sms") or _maybe_sms(env),
        )

        configs.append(
            CheckConfig(
                certificate=cert_source,
                certificate_chain=chain_source,
                cert_expiry_warning_hours=int(merged.get("cert_expiry_warning_hours", 24)),
                cert_expiry_warning_days=int(merged.get("cert_expiry_warning_days", 30)),
                crl_expiry_warning_hours=int(merged.get("crl_expiry_warning_hours", 24)),
                crl_expiry_warning_minutes=int(merged.get("crl_expiry_warning_minutes", 60)),
                notifications=notifications,
                metadata=merged.get("metadata", {}),
            )
        )

    return configs, defaults


def _maybe_url(key: str, env: Dict[str, str]) -> Optional[Dict[str, Any]]:
    value = env.get(key)
    if not value:
        return None
    return {"url": value}


def _maybe_sms(env: Dict[str, str]) -> Optional[Dict[str, Any]]:
    sid = env.get("TWILIO_ACCOUNT_SID")
    token = env.get("TWILIO_AUTH_TOKEN")
    from_ = env.get("TWILIO_FROM")
    to = env.get("TWILIO_TO")
    if not (sid and token and from_ and to):
        return None
    return {"account_sid": sid, "auth_token": token, "from": from_, "to": to}


class CertificateChecker:
    """Single-run certificate checker that mirrors OCSPDocker behaviours."""

    def __init__(self, config: CheckConfig):
        self.config = config
        self.warnings: List[str] = []

    def _load_certificate(self, source: CertificateSource) -> Tuple[Optional[x509.Certificate], Optional[str]]:
        raw_bytes, error = _resolve_source(source)
        if error:
            return None, error

        # Try PEM, then DER
        try:
            return x509.load_pem_x509_certificate(raw_bytes, default_backend()), None
        except Exception:
            try:
                return x509.load_der_x509_certificate(raw_bytes, default_backend()), None
            except Exception as exc:
                return None, f"Failed to parse certificate: {exc}"

    def _load_chain(self) -> Tuple[List[x509.Certificate], Optional[str]]:
        if not self.config.certificate_chain:
            return [], None
        raw_bytes, error = _resolve_source(self.config.certificate_chain)
        if error:
            return [], error
        certs = _split_pem_chain(raw_bytes)
        if not certs:
            return [], "Could not parse certificate chain"
        return certs, None

    def _check_certificate_expiry(self, cert: x509.Certificate, label: str) -> Dict[str, Any]:
        now = datetime.utcnow()
        not_after = cert.not_valid_after.replace(tzinfo=None)
        time_until_expiry = not_after - now
        hours_until_expiry = time_until_expiry.total_seconds() / 3600
        days_until_expiry = time_until_expiry.days

        warning = None
        if time_until_expiry.total_seconds() <= 0:
            warning = f"{label} has EXPIRED"
        elif hours_until_expiry <= self.config.cert_expiry_warning_hours:
            warning = f"{label} expires in {hours_until_expiry:.1f} hours ({time_until_expiry})"
        elif days_until_expiry <= self.config.cert_expiry_warning_days:
            warning = f"{label} expires in {days_until_expiry} days ({time_until_expiry})"

        if warning:
            self.warnings.append(warning)

        return {
            "valid_until": not_after.isoformat(),
            "time_until_expiry": str(time_until_expiry),
            "hours_until_expiry": hours_until_expiry,
            "days_until_expiry": days_until_expiry,
            "warning": warning,
        }

    def _get_crl_distribution_points(self, cert: x509.Certificate) -> List[str]:
        urls = []
        try:
            crl_dps = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.CRL_DISTRIBUTION_POINTS
            ).value
            for dp in crl_dps:
                for name in dp.full_name:
                    if isinstance(name, x509.UniformResourceIdentifier):
                        urls.append(name.value)
        except x509.ExtensionNotFound:
            pass
        return urls

    def _check_crl(self, url: str) -> Dict[str, Any]:
        result = {
            "url": url,
            "error": None,
            "next_update": None,
            "time_until_expiry": None,
            "hours_until_expiry": None,
            "minutes_until_expiry": None,
            "warning": None,
        }

        try:
            response = requests.get(url, timeout=10, verify=False)
            response.raise_for_status()
            crl_data = response.content

            try:
                crl = x509.load_der_x509_crl(crl_data, default_backend())
            except Exception:
                crl = x509.load_pem_x509_crl(crl_data, default_backend())

            next_update = crl.next_update.replace(tzinfo=None)
            now = datetime.utcnow()
            time_until_expiry = next_update - now
            hours_until = time_until_expiry.total_seconds() / 3600
            minutes_until = time_until_expiry.total_seconds() / 60

            result.update(
                {
                    "next_update": next_update.isoformat(),
                    "time_until_expiry": str(time_until_expiry),
                    "hours_until_expiry": hours_until,
                    "minutes_until_expiry": minutes_until,
                }
            )

            if time_until_expiry.total_seconds() <= 0:
                warning = f"CRL at {url} has EXPIRED"
            elif minutes_until <= self.config.crl_expiry_warning_minutes:
                warning = f"CRL at {url} expires in {minutes_until:.1f} minutes ({time_until_expiry})"
            elif hours_until <= self.config.crl_expiry_warning_hours:
                warning = f"CRL at {url} expires in {hours_until:.1f} hours ({time_until_expiry})"
            else:
                warning = None

            if warning:
                self.warnings.append(warning)
                result["warning"] = warning

        except requests.exceptions.RequestException as exc:
            result["error"] = f"Failed to download CRL: {exc}"
        except Exception as exc:
            result["error"] = f"Error checking CRL: {exc}"

        return result

    def _send_http_push(self, results: Dict[str, Any]) -> bool:
        config = self.config.notifications.http_push
        if not config or not config.get("url"):
            return False
        try:
            status = results.get("status", "unknown")
            msg = "OK" if status == "ok" else "WARNING" if status == "warning" else "ERROR"
            url = config["url"]
            params = {"status": status, "msg": msg, "OCSP": "OK"}
            if self.warnings:
                params["warnings"] = "; ".join(self.warnings)
            parsed = urllib.parse.urlparse(url)
            query = urllib.parse.parse_qs(parsed.query)
            query.update(params)
            new_query = urllib.parse.urlencode(query, doseq=True)
            final_url = urllib.parse.urlunparse(
                (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
            )
            response = requests.get(final_url, timeout=10)
            response.raise_for_status()
            return True
        except Exception:
            return False

    def _send_webhook(self, results: Dict[str, Any]) -> bool:
        config = self.config.notifications.webhook
        if not config or not config.get("url"):
            return False
        try:
            payload = config.get("payload", results)
            if isinstance(payload, str):
                payload = json.loads(payload)
            if isinstance(payload, dict):
                payload.update(results)
            else:
                payload = results
            response = requests.post(
                config["url"],
                json=payload,
                headers=config.get("headers", {"Content-Type": "application/json"}),
                timeout=10,
            )
            response.raise_for_status()
            return True
        except Exception:
            return False

    def _send_teams(self, results: Dict[str, Any]) -> bool:
        config = self.config.notifications.teams
        if not config or not config.get("url"):
            return False
        try:
            status = results.get("status", "unknown")
            color = "28a745" if status == "ok" else "ffc107" if status == "warning" else "dc3545"
            facts = [
                {"name": "Status", "value": status.upper()},
                {"name": "Certificate", "value": results.get("certificate_descriptor", "N/A")},
                {"name": "Timestamp", "value": results.get("timestamp", "N/A")},
            ]
            if results.get("certificates"):
                facts.append({"name": "Valid Until", "value": results["certificates"][0].get("valid_until", "N/A")})
            if self.warnings:
                facts.append({"name": "Warnings", "value": "; ".join(self.warnings)})
            card = {
                "@type": "MessageCard",
                "@context": "https://schema.org/extensions",
                "summary": f"Certificate Check: {status.upper()}",
                "themeColor": color,
                "title": "Certificate Check Results",
                "sections": [
                    {
                        "activityTitle": f"Certificate Status: {status.upper()}",
                        "facts": facts,
                        "markdown": True,
                    }
                ],
            }
            response = requests.post(config["url"], json=card, timeout=10)
            response.raise_for_status()
            return True
        except Exception:
            return False

    def _send_google_chat(self, results: Dict[str, Any]) -> bool:
        config = self.config.notifications.google_chat
        if not config or not config.get("url"):
            return False
        try:
            status = results.get("status", "unknown")
            emoji = "✅" if status == "ok" else "⚠️" if status == "warning" else "❌"
            message = f"{emoji} *Certificate Check Results*\n\n"
            message += f"*Status:* {status.upper()}\n"
            message += f"*Certificate:* {results.get('certificate_descriptor', 'N/A')}\n"
            message += f"*Timestamp:* {results.get('timestamp', 'N/A')}\n"
            if results.get("certificates"):
                message += f"*Valid Until:* {results['certificates'][0].get('valid_until', 'N/A')}\n"
            if self.warnings:
                message += "\n*Warnings:*\n" + "\n".join([f"• {w}" for w in self.warnings])
            payload = {"text": message}
            response = requests.post(config["url"], json=payload, timeout=10)
            response.raise_for_status()
            return True
        except Exception:
            return False

    def _send_sms(self, results: Dict[str, Any]) -> bool:
        config = self.config.notifications.sms
        if not config:
            return False
        try:
            from twilio.rest import Client

            client = Client(config["account_sid"], config["auth_token"])
            status = results.get("status", "unknown")
            message = f"Cert Check: {status.upper()}\nCert: {results.get('certificate_descriptor', 'N/A')}\n"
            if self.warnings:
                message += f"Warnings: {', '.join(self.warnings[:3])}"
            client.messages.create(body=message, from_=config["from"], to=config["to"])
            return True
        except Exception:
            return False

    def _send_notifications(self, results: Dict[str, Any]) -> List[str]:
        sent = []
        if self._send_http_push(results):
            sent.append("http_push")
        if self._send_webhook(results):
            sent.append("webhook")
        if self._send_teams(results):
            sent.append("teams")
        if self._send_google_chat(results):
            sent.append("google_chat")
        if self._send_sms(results):
            sent.append("sms")
        return sent

    def run(self) -> Dict[str, Any]:
        descriptor = self.config.metadata.get("name") or self.config.certificate.path or "inline-certificate"
        results: Dict[str, Any] = {
            "timestamp": datetime.utcnow().isoformat(),
            "certificate_descriptor": descriptor,
            "status": "ok",
            "certificates": [],
            "crls": [],
            "warnings": [],
            "metadata": self.config.metadata,
        }

        cert, error = self._load_certificate(self.config.certificate)
        if error:
            results["status"] = "error"
            results["error"] = error
            return results

        main_info = {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "serial_number": str(cert.serial_number),
            "valid_from": cert.not_valid_before.isoformat(),
            "valid_to": cert.not_valid_after.isoformat(),
        }
        main_info.update(self._check_certificate_expiry(cert, "Main Certificate"))
        results["certificates"].append(main_info)

        for crl_url in self._get_crl_distribution_points(cert):
            results["crls"].append(self._check_crl(crl_url))

        chain_certificates, chain_error = self._load_chain()
        if chain_error:
            results["warnings"].append(chain_error)
        else:
            for idx, chain_cert in enumerate(chain_certificates, start=1):
                info = {
                    "subject": chain_cert.subject.rfc4514_string(),
                    "issuer": chain_cert.issuer.rfc4514_string(),
                    "serial_number": str(chain_cert.serial_number),
                }
                info.update(self._check_certificate_expiry(chain_cert, f"Chain Certificate {idx}"))
                results["certificates"].append(info)
                for crl_url in self._get_crl_distribution_points(chain_cert):
                    results["crls"].append(self._check_crl(crl_url))

        if self.warnings:
            results["warnings"] = self.warnings
            if results["status"] == "ok":
                results["status"] = "warning"

        notifications_sent = self._send_notifications(results)
        if notifications_sent:
            results["notifications_sent"] = notifications_sent

        return results


