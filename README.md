# aws-highly-secure-foundation-pulumi

A Pulumi (Python) learning project that builds a VPC in **eu-west-1**
following the
[AWS Well-Architected security pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html),
with every optional control switched on.

```
aws-highly-secure-foundation-pulumi/
├── account-baseline/   once per account: CloudTrail, GuardDuty, Security Hub, Config, account hardening
├── network/            the four-tier VPC, firewalls, endpoints and logging
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
                                 │
                         ┌───────▼────────┐   IGW edge route table: return traffic
                         │ Internet GW    │   for each public subnet → that AZ's firewall
                         └───────┬────────┘
 VPC 10.0.0.0/16                 │
 ┌───────────────────────────────┼───────────────────────────────────────────────┐
 │ firewall /28 ×3   ┌───────────▼────────────┐  Network Firewall: managed threat  │
 │ 10.0.99.0/28…     │  firewall endpoint/AZ  │  intel → domain allow-list → drop  │
 │                   └───────────┬────────────┘                                    │
 │ public /24 ×3     ALB · NAT gateway                      NACL: 443 + return     │
 │ 10.0.96-98.0/24               │                                                 │
 │ app /19 ×3        workloads · interface endpoints        NACL: from ALB, to data│
 │ 10.0.0.0/19…      → S3/DynamoDB gateway endpoints                               │
 │                               │ dataPorts only                                  │
 │ data /22 ×3       databases — no route out of the VPC    NACL: from app only    │
 │ 10.0.100.0/22…                                                                  │
 │                                                                                 │
 │ DNS Firewall (walled garden, fails closed) · default SG + default NACL deny all │
 │ Flow logs + firewall logs + DNS query logs → CloudWatch, KMS-encrypted, 365 days│
 └─────────────────────────────────────────────────────────────────────────────────┘
```

**Outbound path** for a workload calling an approved domain: app subnet →
NAT gateway → Network Firewall endpoint → Internet Gateway. Each hop is
filtered: the security group allows only HTTPS out, the NACL only HTTPS and
return traffic, DNS Firewall only answers for allow-listed domains, and Network
Firewall checks the TLS server name against threat intelligence and the
allow-list. AWS API calls skip the internet entirely through VPC endpoints.

## How it maps to the security pillar

| Best practice | What implements it |
|---|---|
| **SEC05-BP01** Create network layers | Four tiers: public, app, isolated data, and firewall. The data tier has no route outside the VPC. |
| **SEC05-BP02** Control traffic in every layer | Route tables; network ACLs per tier; security groups that reference each other (internet → ALB → app → data); both ingress and egress controlled. |
| **SEC05-BP02** Private access to services | S3 and DynamoDB gateway endpoints, plus 10 interface endpoints, with policies that admit only this account's principals (a data perimeter). |
| **SEC05-BP03** Inspection-based protection | Network Firewall (strict order, default drop, AWS threat signatures and malware/botnet domain lists, domain allow-list). Route 53 DNS Firewall as a walled garden that fails closed. |
| **SEC05-BP04** Automate network protection | All of it is code, with unit tests that check the rules. |
| Lock down defaults (CIS 5.4) | Default security group and default network ACL both stripped of every rule. |
| **SEC04-BP01/02** Logging in standard places | VPC flow logs (all traffic, 1-minute, v5 fields), firewall alert and flow logs, DNS query logs, CloudTrail, AWS Config. |
| **SEC04** Detect unexpected behaviour | GuardDuty (with S3, EKS, EBS malware, RDS, Lambda and runtime monitoring), Security Hub (FSBP + CIS 5.0.0), IAM Access Analyzer. |
| Protect data at rest | Customer-managed KMS keys with rotation for all logs; EBS encryption by default; audit logs in an Object Lock bucket. |
| Keep people away from data | Session Manager endpoints (ssm, ssmmessages, ec2messages) instead of SSH or a bastion. Serial console disabled. |
| Strong identity foundation | IMDSv2 required by default, roles scoped by `aws:SourceAccount`/`aws:SourceArn`, a CIS password policy, and `aws:allowedAccountIds` pinning each stack to one account. |

## Before you deploy

1. **Use a sandbox account, not production.** Put its ID in both stacks'
   `aws:allowedAccountIds`; `111111111111` is a placeholder. The provider
   refuses to run against any other account.
2. **Deploy `account-baseline` first.** GuardDuty, Security Hub, AWS Config and
   the Access Analyzer allow only one of each per region. If the account
   already has any of them, creation fails: `pulumi import` the existing one,
   or remove it from `src/detection.py`.
3. **Extend `allowedDomains`** in `network/Pulumi.dev.yaml` with everything
   your workloads must reach (package registries, SaaS APIs). Anything not on
   it fails DNS resolution and is dropped by the firewall. This is intended,
   but surprising the first time.
4. **Optionally, block the AWS managed DNS threat lists.** Their IDs differ by
   region:
   ```sh
   aws route53resolver list-firewall-domain-lists --region eu-west-1 \
     --query "FirewallDomainLists[?ManagedOwnerName=='Route 53 Resolver DNS Firewall'].[Name,Id]" --output table
   ```
   Put the IDs in `dnsFirewallManagedListIds`.

## Running it

Needs Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```sh
make install                              # a .venv in each project
make test                                 # 29 unit tests across both projects, no AWS needed
make lint                                 # ruff and pyright

pulumi login --local                      # local state while learning
export AWS_PROFILE=<sandbox profile>

cd account-baseline && pulumi stack init dev && pulumi up      # 39 resources
cd ../network       && pulumi stack init dev && pulumi up      # 110 resources
```

## Cost (eu-west-1, approximate)

| Item | Monthly |
|---|---|
| Network Firewall, 3 endpoints | ~$865 + $0.065/GB |
| Interface endpoints, 10 × 3 AZs | ~$240 + $0.01/GB |
| NAT gateways, 1 per AZ × 3 | ~$105 + $0.048/GB |
| GuardDuty, Security Hub, Config | usage-based; usually tens of dollars in a quiet account |
| KMS keys (2), logs, DNS Firewall | a few dollars |
| **Total** | **~$1,220+** |

To cut costs, set `networkFirewall: false` (saves ~$865), set `natGateways: single`
(saves ~$70, but an outage in that AZ cuts every AZ's internet access), or trim
`interfaceEndpoints` in `network/Pulumi.dev.yaml`.

## Tearing down

- `network`: run `pulumi destroy`. Network Firewall `deleteProtection` is off
  for learning; turn it on for anything real.
- `account-baseline`: the audit bucket and its KMS key are `protect`ed, and the
  logs are under Object Lock (GOVERNANCE, 365 days). Destroying the baseline
  stops logging but keeps the evidence, which is the point. To remove them
  anyway, `pulumi state unprotect` them, then delete the objects with
  `s3:BypassGovernanceRetention`. With `objectLockMode: COMPLIANCE`, not even
  the root user can delete them before they expire.

## What's deliberately not here

- **WAF and Shield**: they attach to a load balancer or CloudFront, which this
  project doesn't create yet. Add a WAF web ACL with AWS managed rules when you
  add an ALB.
- **VPC Block Public Access**: an account-wide switch that would also block
  this VPC's own Internet Gateway unless you configure exclusions.
- **Organisation-level controls** (SCPs, delegated GuardDuty/Security Hub
  administrators, centralised log archive account): these need AWS
  Organizations and belong in a separate management-account project.
- **CloudTrail data events and Insights**: add these when you need them; they
  cost extra.
