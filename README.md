## Lambda Certificate Checker

This project ports the functionality of the [OCSPDocker](https://github.com/jgoodloe/OCSPDocker) service into AWS Lambda so that certificate, chain, and CRL checks can be triggered by CloudWatch Events, EventBridge, or any custom invocation. The logic mirrors the original project: certificates are analysed, CRL distribution points are downloaded, warning thresholds are applied, and optional notifications are sent to HTTP push endpoints, generic webhooks, Microsoft Teams, Google Chat, or Twilio SMS.

### Architecture

- `lambda_function.py` exposes `lambda_handler`, which accepts one or more certificate configurations in the invocation payload.
- `src/cert_checker/checker.py` contains a single-run `CertificateChecker` class derived from the OCSPDocker implementation (scheduling logic was removed; everything else remains feature-compatible).
- `requirements.txt` lists the dependencies that must be packaged with the Lambda deployment.

### Event Schema

```jsonc
{
  "defaults": {
    "cert_expiry_warning_hours": 12,
    "crl_expiry_warning_minutes": 30,
    "notifications": {
      "http_push": { "url": "https://uptime-kuma.local/api/push/..." }
    }
  },
  "certificates": [
    {
      "metadata": { "name": "example.com leaf" },
      "certificate_s3": {
        "bucket": "cert-storage",
        "key": "example/leaf.pem"
      },
      "certificate_chain": {
        "s3": { "bucket": "cert-storage", "key": "example/chain.pem" }
      },
      "cert_expiry_warning_days": 25,
      "notifications": {
        "teams": { "url": "https://outlook.office.com/webhook/..." }
      }
    },
    {
      "metadata": { "name": "inline cert" },
      "certificate_pem": "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----"
    }
  ]
}
```

- Every entry accepts the same keys used in `config.yaml` from OCSPDocker (`certificate`, `certificate_chain`, `cert_expiry_warning_hours`, etc.).
- Certificates may be supplied as absolute paths embedded in the Lambda package, inline PEM strings, base64 strings, or S3 object references.
- Notification blocks follow the same schema as the Docker service; if omitted they fall back to environment variables (`HTTP_PUSH_URL`, `WEBHOOK_URL`, `TEAMS_WEBHOOK_URL`, `GOOGLE_CHAT_WEBHOOK_URL`, `TWILIO_*`).

### Running Locally

1. Create a virtual environment and install dependencies:

```
python -m venv .venv
.venv\Scripts\activate  # Windows
pip install -r requirements.txt
```

2. Set `SAMPLE_EVENT` with the JSON payload you would like to test and run:

```
SAMPLE_EVENT="{\"certificate_pem\": \"-----BEGIN ...\"}" python lambda_function.py
```

### Deployment

1. Package the application (example using zip):

```
pip install -r requirements.txt -t build/
cp -r src build/
cp lambda_function.py build/
(cd build && zip -r ../certificate-checker.zip .)
```

2. Upload `certificate-checker.zip` to AWS Lambda and set any environment defaults (e.g., `CERTIFICATE_PATH`, notification URLs, or `CONFIG_PATH` pointing to a bundled YAML file).

3. Configure an EventBridge rule or any trigger that passes the desired payload so multiple certificates can be monitored with different thresholds.

### References

- Original feature set: [jgoodloe/OCSPDocker](https://github.com/jgoodloe/OCSPDocker)

