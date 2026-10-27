# aws-secure-foundation-pulumi

A Pulumi (Python) learning project that builds a VPC in **eu-west-1**
following the
[AWS Well-Architected security pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html),
with an internet-facing Application Load Balancer as the only way in.

Derived from
[aws-highly-secure-foundation-pulumi](https://github.com/markday1962/aws-highly-secure-foundation-pulumi),
with these changes: Network Firewall and DNS Firewall are removed; an ALB is
added (HTTP redirects to HTTPS); and the account baseline closes the Security
Hub gaps the original left open, adding alerting. **AWS WAF** sits in front of
the ALB, with per-IP rate limiting and the AWS managed rule groups (in count
mode to begin with).

```
aws-secure-foundation-pulumi/
├── account-baseline/   once per account: CloudTrail, GuardDuty, Security Hub, Config, alerts, account hardening
├── network/            the three-tier VPC, the ALB and its WAF, endpoints and logging
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
                        │  AWS WAF: IP reputation · rate limit → 429 ·
                        │           common rule set · known bad inputs · Bot Control
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
 │ flow logs + WAF logs → CloudWatch (KMS, 365 days) · ALB access logs → S3   │
 └────────────────────────────────────────────────────────────────────────────┘
```

**Inbound:** client → IGW → AWS WAF → ALB. WAF blocks any client IP that
makes more than `wafRateLimit` requests per `wafRateWindowSec` (default 1000
per 5 minutes) with `429 Too Many Requests` and a `Retry-After` header, until
its rate drops back under the limit. Four AWS managed rule groups run
around it:

| Priority | Rule | What it matches |
|---|---|---|
| 10 | `AWSManagedRulesAmazonIpReputationList` | IPs Amazon threat intelligence has seen attacking (checked first, so they don't use up the rate limit) |
| 20 | `rate-limit-per-ip` | any IP over the rate limit (always blocks) |
| 30 | `AWSManagedRulesCommonRuleSet` | the OWASP Top 10 baseline: XSS, path traversal, oversized requests, bad bots |
| 40 | `AWSManagedRulesKnownBadInputsRuleSet` | known exploit patterns such as Log4j and Java deserialisation |
| 50 | `AWSManagedRulesBotControlRuleSet` (paid, optional) | bots and automation: scrapers, scanners, HTTP libraries, headless browsers. Runs last, so requests already blocked aren't charged for its inspection |

The managed groups start in **count mode** (`wafManagedRulesMode: count`):
they record what they *would* block, in CloudWatch metrics
(`AWS/WAFV2`, one metric per rule) and in the web ACL's sampled requests, but
let it through. Watch them under real traffic, add exclusions for any false
positives (the common rule set's `SizeRestrictions_BODY`, which matches bodies
over 8 KB, is the usual one), then set `wafManagedRulesMode: block`.

**Bot Control** is set by `wafBotControl`:
- `common` (the default) matches bots that identify themselves or show
  automation signals. It costs $10/month plus $1 per million requests.
- `targeted` also fingerprints browsers, challenges suspicious clients and
  uses machine learning. It costs $10 per million requests.
- `off` leaves the group out.

Bot Control follows `wafManagedRulesMode`. Before switching to `block`, check
which of your own clients it counts. Health checkers, uptime monitors, CI
jobs and `curl` all count as automation. Its `CategoryHttpLibrary` and
`SignalNonBrowserUserAgent` rules would block the `curl` checks below.

**WAF logs:** every request the web ACL sees is logged in full to the
CloudWatch log group `aws-waf-logs-learning-<stack>-waf`, encrypted with the
network's KMS key and kept for `logRetentionDays`. The `authorization` and
`cookie` headers are redacted. To see what the count-mode groups would have
blocked, run this in CloudWatch Logs Insights:

```
fields @timestamp, httpRequest.clientIp, httpRequest.httpMethod, httpRequest.uri
| filter @message like /"action":"COUNT"/
| sort @timestamp desc
```

Each matching record's `ruleGroupList` names the group and rule that matched.

Port 80 only ever answers with a 301 to
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
| **SEC05-BP03** Inspection-based protection | AWS WAF web ACL on the ALB: AWS IP reputation, common rule set, known bad inputs and Bot Control (count mode first), per-IP rate limiting, with CloudWatch metrics and sampled requests per rule. |
| **SEC05-BP04** Automate network protection | All of it is code, with unit tests that check the rules. |
| **SEC09** Protect data in transit | HTTP→HTTPS redirect, TLS 1.2/1.3 only, HSTS, TLS to the targets; buckets deny non-TLS requests. |
| Lock down defaults (CIS 5.4) | Default security group and default network ACL both stripped of every rule. |
| **SEC04-BP01/02** Logging in standard places | VPC flow logs (all traffic, 1-minute, v5 fields), ALB access logs, WAF logs (every request, credentials redacted), CloudTrail (S3 and CloudWatch Logs), S3 server access logs on the audit bucket, AWS Config. |
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
4. **Before switching on `loadBalancer`, set `domainName` and
   `hostedZoneName`** in `network/Pulumi.dev.yaml`. The hosted zone must be a
   public Route 53 zone in this account that holds `domainName`; the stack
   adds the ACM validation record and an alias record to the ALB. That
   `pulumi up` waits for the certificate to validate (usually a few minutes).
5. **Stack names are at most 10 characters** (lowercase, digits, hyphens).
   Every physical name starts with `learning-<stack>`, so several stacks can
   share an account, and the ALB's name must fit in 32 characters.

## Controlled deployment

The network stack deploys almost nothing by default. Only the VPC, its nine
subnets and their route tables are always there, plus the default security
group and default network ACL with every rule removed. That VPC carries no
traffic at all, and costs nothing.

Everything else is a feature flag in `network/Pulumi.dev.yaml`, off until you
switch it on. Bring the network up one `pulumi up` at a time, checking
`pulumi preview` before each:

| Step | Flag | Needs | Adds | Cost |
|---|---|---|---|---|
| 1 | `networkAcls: true` | | a network ACL per tier; until then every subnet uses the deny-all default ACL | free |
| 1 | `securityGroups: true` | | the ALB, app, data and endpoint security groups | free |
| 1 | `flowLogs: true` | | VPC flow logs, the KMS log key | log volume |
| 2 | `internetGateway: true` | | the Internet Gateway and the public subnets' route to it | free |
| 2 | `gatewayEndpoints: true` | `networkAcls` | S3 and DynamoDB gateway endpoints | free |
| 3 | `natGateways: single` or `perAz` | `internetGateway`, `networkAcls` | NAT gateways and the app tier's route out | ~$35 each |
| 4 | `interfaceEndpoints: [ssm, …]` | `networkAcls`, `securityGroups` | interface endpoints | ~$8 each per AZ |
| 5 | `loadBalancer: true` | `internetGateway`, `networkAcls`, `securityGroups` | the ALB, its certificate, DNS record and log bucket | ~$18 + LCUs |
| 6 | `waf: true` | `loadBalancer` | the WAF web ACL and its logs (and the KMS log key) | ~$20 + per request |

The stack refuses to run if a flag is on without what it needs, for example
`waf needs load_balancer switched on too`. Turning a flag back off removes
what it added on the next `pulumi up`. The exported `features` output shows
what a stack has switched on.

## Running it

Needs Python 3.12+ and [uv](https://docs.astral.sh/uv/).

GitHub Actions (`.github/workflows/ci.yml`) runs the same checks on every pull
request and every push to `main`: for each project, `uv sync --locked`, ruff
format and lint, pyright and pytest. It never touches AWS.

```sh
make install                              # a .venv in each project
make test                                 # 58 unit tests across both projects, no AWS needed
make lint                                 # ruff and pyright

pulumi login --local                      # local state while learning
export AWS_PROFILE=<sandbox profile>

cd account-baseline && pulumi stack init dev && pulumi up
cd ../network       && pulumi stack init dev && pulumi up      # the VPC and subnets only

# Then switch features on step by step (see above). Once loadBalancer and waf are on:
curl -I http://app.example.com            # 301, Location: https://app.example.com:443/
curl https://app.example.com              # ok

# Rate limit: go past wafRateLimit; WAF takes up to a minute or so to start blocking.
for i in $(seq 1 1200); do curl -s -o /dev/null -w "%{http_code}\n" https://app.example.com; done | sort | uniq -c
```

## Cost (eu-west-1, approximate)

With every feature on:

| Item | Monthly |
|---|---|
| Interface endpoints, 10 × 3 AZs | ~$240 + $0.01/GB |
| NAT gateways, 1 per AZ × 3 | ~$105 + $0.048/GB |
| Application Load Balancer | ~$18 + LCUs |
| AWS WAF, 1 web ACL + 5 rules | ~$10 + $0.60 per million requests |
| WAF Bot Control (`common`) | ~$10 + $1 per million requests |
| WAF logs in CloudWatch | ~$0.57/GB ingested (roughly 1–2 GB per million requests) |
| Public IPv4 addresses (NAT EIPs, ALB) | ~$20 |
| GuardDuty, Security Hub, Config | usage-based; usually tens of dollars in a quiet account |
| KMS keys (2), logs, alarms (14), Route 53 zone | a few dollars |
| **Total** | **~$410+** |

With every network feature off, the network stack costs nothing. To cut costs
with them on, set `natGateways: single` (saves ~$70, but an outage in that AZ
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

- **More WAF**: geo rules, and the other paid managed groups (Account
  Takeover Prevention, Account Creation Fraud Prevention), are still to come. A logging filter (keep only
  blocked and counted requests) would cut log costs on a busy site.
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
