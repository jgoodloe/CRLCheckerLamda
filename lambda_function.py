"""AWS Lambda handler for certificate checks."""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List

from cert_checker import CertificateChecker, load_config_from_event


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Entry point for AWS Lambda.

    Event structure:
    {
        "defaults": {...},      # optional base config (matches OCSP config keys)
        "certificates": [
            {
                "certificate": "/tmp/cert.pem",    # or certificate_pem|certificate_s3
                "certificate_chain": {...},        # optional chain definition
                "cert_expiry_warning_hours": 24,
                "crl_expiry_warning_minutes": 60,
                "notifications": {...},            # same layout as OCSPDocker
                "metadata": {"name": "my-cert"}
            }
        ]
    }
    """

    configs, defaults = load_config_from_event(event, os.environ)
    results: List[Dict[str, Any]] = []

    for cfg in configs:
        checker = CertificateChecker(cfg)
        results.append(checker.run())

    return {
        "defaults": defaults,
        "result_count": len(results),
        "results": results,
    }


if __name__ == "__main__":
    # Allow local execution for debugging
    sample_event = json.loads(os.environ.get("SAMPLE_EVENT", "{}") or "{}")
    print(json.dumps(lambda_handler(sample_event, None), indent=2))

