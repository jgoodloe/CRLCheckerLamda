import json
from cert_checker import load_config_from_event


def test_load_single_certificate(tmp_path, monkeypatch):
    cert_file = tmp_path / "cert.pem"
    cert_file.write_text("-----BEGIN CERTIFICATE-----\nMIIB...==\n-----END CERTIFICATE-----\n")

    event = {
        "certificate": str(cert_file),
        "cert_expiry_warning_hours": 12,
    }

    configs, defaults = load_config_from_event(event)

    assert len(configs) == 1
    cfg = configs[0]
    assert cfg.certificate.path == str(cert_file)
    assert cfg.cert_expiry_warning_hours == 12
    assert defaults["certificate"] == str(cert_file)


def test_multiple_certificates_in_event(monkeypatch):
    event = {
        "defaults": {"cert_expiry_warning_hours": 48},
        "certificates": [
            {"certificate": "/tmp/a.pem"},
            {"certificate_pem": "-----BEGIN CERTIFICATE-----..."}
        ],
    }

    configs, _ = load_config_from_event(event)
    assert len(configs) == 2
    assert configs[0].certificate.path == "/tmp/a.pem"
    assert configs[1].certificate.pem.startswith("-----BEGIN")

