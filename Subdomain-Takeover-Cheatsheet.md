# Subdomain Takeover

A subdomain takeover happens when a DNS record (usually a `CNAME`, sometimes `A`/`NS`) still points to a cloud service or external provider that is no longer claimed. An attacker registers the dangling resource on that provider and serves their own content from the victim's subdomain, enabling phishing, cookie theft, OAuth redirect abuse, and bypass of domain-scoped CSP or CORS trust.

## How it happens

1. A team provisions `app.example.com -> example.s3.amazonaws.com` (or Azure, GitHub Pages, Heroku, etc.).
2. The service/bucket is later deleted, but the DNS record stays.
3. The subdomain now resolves to an unclaimed resource, which the attacker re-creates.

## How to test

```bash
# enumerate subdomains
subfinder -d example.com -all -o subs.txt
amass enum -passive -d example.com >> subs.txt

# resolve and find CNAMEs pointing at third parties
dnsx -l subs.txt -cname -resp -o cnames.txt
# or per-host:
dig CNAME app.example.com +short

# probe and look for provider "claim this" fingerprints
httpx -l subs.txt -status-code -title -o live.txt

# automated takeover detection (fingerprint database)
subzy run --targets subs.txt
nuclei -l subs.txt -t http/takeovers/
```

Confirm before claiming: check the response for a provider error like "NoSuchBucket", "There isn't a GitHub Pages site here", "no such app" (Heroku), "404 Blob Not Found" (Azure), or "Domain not found" (Fastly/Shopify). Match the fingerprint against the can-i-take-over-xyz list, then validate by claiming the resource with a harmless proof file (do not host malicious content).

## Common vulnerable fingerprints

| Provider | Tell-tale response |
|---|---|
| AWS S3 | `NoSuchBucket` |
| GitHub Pages | "There isn't a GitHub Pages site here." |
| Heroku | "No such app" / default Heroku page |
| Azure (cloudapp/trafficmanager) | "404 Web Site not found" / NXDOMAIN on app |
| Fastly | "Fastly error: unknown domain" |
| Shopify | "Sorry, this shop is currently unavailable." |

## Mitigation

- Remove DNS records the moment the backing resource is decommissioned (deprovision DNS before the service).
- Periodically audit DNS for dangling `CNAME`/`A`/`NS` records.
- Use IaC and ownership tracking so DNS and resources are torn down together.

## References

- can-i-take-over-xyz (fingerprint database): https://github.com/EdOverflow/can-i-take-over-xyz
- OWASP WSTG: Test for Subdomain Takeover: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover
- subzy: https://github.com/PentestPad/subzy
