# Disposable Test Linux Target (TEST ENVIRONMENT ONLY)

> **WARNING: FOR TESTING AND DEVELOPMENT USE ONLY**
> This target contains intentionally misconfigured controls (SSH password authentication enabled, root login allowed, sudo NOPASSWD) to demonstrate the automated audit pipeline, finding generation, and safe remediation workflows.
> **DO NOT EXPOSE TO UNTRUSTED NETWORKS.**

## Running the Test Target

```bash
docker build -t psv-test-target ./deployment/test-target
docker run -d --name psv-test-target -p 2222:22 psv-test-target
```

## Adding to PSV Auditor

Using CLI:
```bash
psv host add --name "local-test-target" --hostname "127.0.0.1" --port 2222 --env development --user "auditor-test"
psv host test <HOST_ID>
psv audit run <HOST_ID> --profile cis-linux-server
```
