# aws-secure-foundation-pulumi

A Pulumi (Python) learning project that builds a VPC in **eu-west-1**
following the
[AWS Well-Architected security pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html),
with an internet-facing Application Load Balancer as the only way in.

Derived from
[aws-highly-secure-foundation-pulumi](https://github.com/markday1962/aws-highly-secure-foundation-pulumi),
with these changes: Network Firewall and DNS Firewall are removed; an ALB is
added (HTTP redirects to HTTPS); and the account baseline closes the Security
Hub gaps the original left open, adding alerting. **AWS WAF** rules on the ALB
are the next phase.

```
aws-secure-foundation-pulumi/
├── account-baseline/   once per account: CloudTrail, GuardDuty, Security Hub, Config, alerts, account hardening
├── network/            the three-tier VPC, the ALB, endpoints and logging
└── Makefile            install, test and lint both projects
```

Each project is its own [uv](https://docs.astral.sh/uv/) project: a
`pyproject.toml`, a `__main__.py` entry point, the components in `src/` and
pytest tests in `tests/`.

There are two projects because they have different lifecycles. The account
baseline should outlive any VPC, so `pulumi destroy` on the network must never
switch off your CloudTrail or GuardDuty.

## The network

```
                     Internet
                        │  :80 → 301 to :443
                        │  :443 TLS 1.2/1.3 (ACM certificate, app.example.com)
                ┌───────▼────────┐
                │ Internet GW    │
                └───────┬────────┘
 VPC 10.0.0.0/16        │
 ┌──────────────────────┼─────────────────────────────────────────────────────┐
 │ public /24 ×3     ALB · NAT gateway                NACL: 80, 443 + return  │
 │ 10.0.96-98.0/24        │ app_port (HTTPS)                                   │
 │ app /19 ×3        workloads · interface endpoints  NACL: from ALB, to data │
 │ 10.0.0.0/19…      → S3/DynamoDB gateway endpoints                          │
 │                        │ dataPorts only                                     │
 │ data /22 ×3       databases — no route out of the VPC  NACL: from app only │
 │ 10.0.100.0/22…                                                             │
 │                                                                            │
 │ default SG + default NACL deny all                                         │
 │ VPC flow logs → CloudWatch (KMS, 365 days) · ALB access logs → S3          │
 └────────────────────────────────────────────────────────────────────────────┘
```

**Inbound:** client → IGW → ALB. Port 80 only ever answers with a 301 to
HTTPS. Port 443 terminates TLS with `ELBSecurityPolicy-TLS13-1-2-Res-2021-06`,
adds HSTS, `nosniff` and `X-Frame-Options: DENY`, drops malformed headers, and
for now returns a fixed `200 ok`. An empty HTTPS target group on `appPort` is
ready for workloads; the ALB re-encrypts to them.

**Outbound:** workloads reach the internet only over HTTPS, through their AZ's
NAT gateway. AWS API calls skip the internet entirely through VPC endpoints.
With the firewalls gone, egress isn't filtered by destination: the security
group and NACL limit it to port 443, and nothing more.

## How it maps to the security pillar

| Best practice | What implements it |
|---|---|
| **SEC05-BP01** Create network layers | Three tiers: public, app, and isolated data. The data tier has no route outside the VPC. |
| **SEC05-BP02** Control traffic in every layer | Route tables; network ACLs per tier; security groups that reference each other (internet → ALB → app → data); both ingress and egress controlled. |
| **SEC05-BP02** Private access to services | S3 and DynamoDB gateway endpoints, plus 10 interface endpoints, with policies that admit only this account's principals (a data perimeter). |
| **SEC05-BP03** Inspection-based protection | *Next phase:* AWS WAF web ACL on the ALB (the stack exports `albArn`). |
| **SEC05-BP04** Automate network protection | All of it is code, with unit tests that check the rules. |
| **SEC09** Protect data in transit | HTTP→HTTPS redirect, TLS 1.2/1.3 only, HSTS, TLS to the targets; buckets deny non-TLS requests. |
| Lock down defaults (CIS 5.4) | Default security group and default network ACL both stripped of every rule. |
| **SEC04-BP01/02** Logging in standard places | VPC flow logs (all traffic, 1-minute, v5 fields), ALB access logs, CloudTrail (S3 and CloudWatch Logs), S3 server access logs on the audit bucket, AWS Config. |
| **SEC04** Detect unexpected behaviour | GuardDuty (with S3, EKS, EBS malware, RDS, Lambda and runtime monitoring), Security Hub (FSBP + CIS 5.0.0), IAM Access Analyzer, the 14 CIS CloudTrail metric-filter alarms. |
| **SEC04-BP03 / SEC10** Alert and respond | High-severity GuardDuty findings, new HIGH/CRITICAL Security Hub findings and the CIS alarms go to an encrypted SNS topic (optional email). |
| Protect data at rest | Customer-managed KMS keys with rotation for logs and alerts; EBS encryption by default; audit logs in an Object Lock bucket. |
| Keep people away from data | Session Manager endpoints (ssm, ssmmessages, ec2messages) instead of SSH or a bastion. Serial console disabled. |
| Strong identity foundation | IMDSv2 required by default, roles scoped by `aws:SourceAccount`/`aws:SourceArn`, a CIS password policy, and `aws:allowedAccountIds` pinning each stack to one account. |

## Before you deploy

1. **Use a sandbox account, not production.** Put its ID in both stacks'
   `aws:allowedAccountIds`; `111111111111` is a placeholder. The provider
   refuses to run against any other account.
2. **Deploy `account-baseline` first.** GuardDuty, Security Hub, AWS Config,
   the Access Analyzer and Config's service-linked role allow only one of each
   per region (the role, one per account). If the account already has any of
   them, creation fails: `pulumi import` the existing one, or remove it from
   `src/detection.py`.
3. **Set `alertEmail`** in `account-baseline/Pulumi.dev.yaml`, and confirm the
   subscription email AWS sends. Expect a burst of CIS alarms (security group,
   NACL, route table, VPC changes) while the network stack deploys.
4. **Set `domainName` and `hostedZoneName`** in `network/Pulumi.dev.yaml`.
   The hosted zone must be a public Route 53 zone in this account that holds
   `domainName`; the stack adds the ACM validation record and an alias record
   to the ALB. The first `pulumi up` waits for the certificate to validate
   (usually a few minutes).
5. **Stack names are at most 10 characters** (lowercase, digits, hyphens).
   Every physical name starts with `learning-<stack>`, so several stacks can
   share an account, and the ALB's name must fit in 32 characters.

## Running it

Needs Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```sh
make install                              # a .venv in each project
make test                                 # 37 unit tests across both projects, no AWS needed
make lint                                 # ruff and pyright

pulumi login --local                      # local state while learning
export AWS_PROFILE=<sandbox profile>

cd account-baseline && pulumi stack init dev && pulumi up
cd ../network       && pulumi stack init dev && pulumi up

curl -I http://app.example.com            # 301, Location: https://app.example.com:443/
curl https://app.example.com              # ok
```

## Cost (eu-west-1, approximate)

| Item | Monthly |
|---|---|
| Interface endpoints, 10 × 3 AZs | ~$240 + $0.01/GB |
| NAT gateways, 1 per AZ × 3 | ~$105 + $0.048/GB |
| Application Load Balancer | ~$18 + LCUs |
| Public IPv4 addresses (NAT EIPs, ALB) | ~$20 |
| GuardDuty, Security Hub, Config | usage-based; usually tens of dollars in a quiet account |
| KMS keys (2), logs, alarms (14), Route 53 zone | a few dollars |
| **Total** | **~$390+** |

To cut costs, set `natGateways: single` (saves ~$70, but an outage in that AZ
cuts every AZ's internet access) or trim `interfaceEndpoints` in
`network/Pulumi.dev.yaml`.

## Tearing down

- `network`: run `pulumi destroy`. ALB `albDeletionProtection` is off for
  learning; turn it on for anything real. The ALB access-log bucket is
  emptied and deleted with the stack.
- **GuardDuty runtime monitoring** creates its own VPC endpoint and security
  group in the VPC (`GuardDutyManagedSecurityGroup-vpc-…`), outside Pulumi.
  If `pulumi destroy` fails to delete the VPC, delete that endpoint and then
  that security group, and run `pulumi destroy` again.
- `account-baseline`: the audit bucket, its access-log bucket and the KMS key
  are `protect`ed, and the audit logs are under Object Lock (GOVERNANCE, 365
  days). Destroying the baseline stops logging but keeps the evidence, which
  is the point. To remove them anyway, `pulumi state unprotect` them, then
  delete the objects with `s3:BypassGovernanceRetention`. With
  `objectLockMode: COMPLIANCE`, not even the root user can delete them before
  they expire.

## What's deliberately not here

- **AWS WAF**: the next phase. Attach a web ACL with AWS managed rules to the
  exported `albArn`.
- **Egress filtering by destination**: Network Firewall and DNS Firewall were
  removed. To bring domain filtering back cheaply, re-add a Route 53 DNS
  Firewall allow-list.
- **Shield Advanced**: Shield Standard already protects the ALB; Advanced
  costs $3,000/month.
- **VPC Block Public Access**: an account-wide switch that would also block
  this VPC's own Internet Gateway unless you configure exclusions.
- **Organisation-level controls** (SCPs, delegated GuardDuty/Security Hub
  administrators, centralised log archive account): these need AWS
  Organizations and belong in a separate management-account project.
- **CloudTrail data events and Insights**: add these when you need them; they
  cost extra.
