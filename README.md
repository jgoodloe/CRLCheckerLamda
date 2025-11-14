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

### AWS Deployment & Testing

1. **Package the Lambda bundle**
   ```
   python -m venv .venv && .\.venv\Scripts\activate
   pip install -r requirements.txt -t build/
   xcopy src build\src /E /I
   copy lambda_function.py build\
   (cd build && powershell Compress-Archive * ..\certificate-checker.zip)
   ```

2. **Prepare AWS resources**
   - Create an S3 bucket for artifacts (`aws s3 mb s3://cert-checker-artifacts-<acct>-<region>`).
   - (Optional) create an S3 bucket that stores certificate/chain files the Lambda will read.
   - Create an IAM role with `AWSLambdaBasicExecutionRole` plus `s3:GetObject` (or Secrets Manager/Twilio permissions as needed).

3. **Deploy / update the function**
   - Upload bundle: `aws s3 cp certificate-checker.zip s3://cert-checker-artifacts-.../`
   - Initial creation via CLI:
     ```
     aws lambda create-function \
       --function-name CertificateChecker \
       --runtime python3.12 \
       --handler lambda_function.lambda_handler \
       --role <lambda-execution-role-arn> \
       --code S3Bucket=cert-checker-artifacts-...,S3Key=certificate-checker.zip \
       --timeout 60 \
       --memory-size 512 \
       --environment Variables={CONFIG_PATH=/opt/config.yaml}
     ```
   - Or update existing code:
     `aws lambda update-function-code --function-name CertificateChecker --zip-file fileb://certificate-checker.zip`
   - If dependencies exceed the 50 MB zipped limit, move heavy libraries (e.g., `cryptography`) into a Lambda layer:
     ```
     aws lambda publish-layer-version \
       --layer-name certificate-checker-libs \
       --zip-file fileb://layer.zip \
       --compatible-runtimes python3.12
     aws lambda update-function-configuration \
       --function-name CertificateChecker \
       --layers arn:aws:lambda:<region>:<account>:layer:certificate-checker-libs:<version>
     ```
   - **Console (GUI) flow**:
     1. Open AWS console → Lambda → “Create function”.
     2. Choose “Author from scratch”, name the function, runtime `Python 3.12`, and select/ create the execution role with CloudWatch Logs + S3/Secrets permissions.
     3. After creation, open the “Code” tab → “Upload from” → “.zip file” → select `certificate-checker.zip`.
     4. Under “Runtime settings”, set Handler to `lambda_function.lambda_handler`.
     5. In “Configuration → Environment variables”, add `CONFIG_PATH`, `CERTIFICATE_PATH`, notification URLs, etc.
     6. (Optional) Attach a Lambda layer under “Configuration → Layers” if you published one for dependencies.
     7. Save changes, then use the “Test” button with a sample payload or wire up EventBridge/SNS triggers.

4. **Configure defaults & secrets**
   - Set environment variables such as `CERTIFICATE_PATH`, `HTTP_PUSH_URL`, `TEAMS_WEBHOOK_URL`, or `TWILIO_*`.
   - If sharing a YAML config, bundle it in the zip and point `CONFIG_PATH` to the file.
   - Store sensitive data in AWS Secrets Manager and grant the Lambda role `secretsmanager:GetSecretValue`.

5. **Create triggers**
   - EventBridge schedule that invokes the function every N minutes with the JSON payload described above.
   - API Gateway, SNS, or direct Lambda test events for ad-hoc checks.

6. **Test the deployment**
   - Invoke manually: `aws lambda invoke --function-name CertificateChecker --payload file://payload.json out.json`
   - Verify notification endpoints received the alerts.
   - Upload sample certs to S3 (if used) and ensure the Lambda role can read them.
   - For local dry runs, set `SAMPLE_EVENT` and run `python lambda_function.py`.

7. **Monitor & iterate**
   - Review CloudWatch Logs for each invocation.
   - Optionally add CloudWatch Alarms on `Errors` metrics or integrate with SNS/Slack.
   - Adjust EventBridge payloads or thresholds as certificates evolve.

### References

- Original feature set: [jgoodloe/OCSPDocker](https://github.com/jgoodloe/OCSPDocker)

