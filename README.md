# Cloud Pentesting

Cloud penetration testing assesses the security of workloads, identities, and
configurations running on cloud providers such as **AWS**, **Azure**, and **GCP**.
Unlike traditional infrastructure testing, the biggest risks in cloud are usually
**identity and misconfiguration**, not memory-corruption exploits.

## The shared responsibility model

The provider secures the *cloud* (hardware, hypervisor, managed-service internals); the
customer secures what they put *in* the cloud (IAM, data, network rules, application code).
Most real-world cloud breaches happen on the **customer** side, public storage buckets,
over-permissive roles, and leaked keys.

## Authorization first

Cloud testing has hard rules. Before touching anything:

- Confirm written authorization **and** the cloud provider's testing policy (AWS, Azure,
  and GCP each publish what is allowed without prior approval).
- Never test resources you do not own or are not explicitly scoped to.
- Avoid denial-of-service and resource-exhaustion testing unless explicitly permitted.

## Methodology at a glance

1. **Enumerate identities**: users, roles, service accounts, and their trust policies.
2. **Review IAM**: look for wildcards (`*`), privilege-escalation paths, and unused admin
   credentials. This is where most findings are.
3. **Inspect storage**: buckets/blobs for public access, weak ACLs, and sensitive data.
4. **Map the network**: security groups / NSGs, public IPs, exposed management ports.
5. **Check the control plane**: logging (CloudTrail / Activity Log), guardrails, and
   organization policies.
6. **Look for secrets**: in instance metadata, environment variables, CI/CD, and code.

## Common high-impact issues

| Area | Typical finding |
| --- | --- |
| IAM | Role allows `iam:PassRole` + compute → privilege escalation |
| Storage | Public bucket / blob containing backups or credentials |
| Metadata | SSRF reaching the instance metadata service (IMDSv1) → temp credentials |
| Keys | Long-lived access keys committed to a repository |
| Logging | CloudTrail / audit logging disabled, hiding attacker activity |

## Where to go next

Dive into the provider-specific guides in this section, **AWS**, **Azure**, and **GCP**, and see the **References** page for downloadable checklists and cheat sheets.
