from dataclasses import dataclass
from typing import Literal

import pulumi
import pulumi_aws as aws

from .logging import LogEncryption
from .policy import Statement, policy_document

# The evaluation windows AWS WAF supports for rate-based rules, in seconds.
RATE_WINDOWS = (60, 120, 300, 600)

# "count" records what a managed rule group would block (in metrics and sampled
# requests) without blocking it; "block" lets each group's rules act.
ManagedRulesMode = Literal["count", "block"]


@dataclass(frozen=True)
class ManagedRuleGroup:
    # The AWS managed rule group, as AWS names it.
    name: str
    # Where it runs relative to the other rules (lower runs first).
    priority: int


# AWS managed rule groups, free with WAF. Together about 925 of the web ACL's
# 1,500 WCU default capacity.
MANAGED_RULE_GROUPS = [
    # Addresses Amazon threat intelligence has seen attacking: checked before
    # the rate limit, so known-bad clients don't use up any of it.
    ManagedRuleGroup("AWSManagedRulesAmazonIpReputationList", priority=10),
    # The OWASP Top 10 baseline: XSS, path traversal, oversized requests, bad bots, ...
    ManagedRuleGroup("AWSManagedRulesCommonRuleSet", priority=30),
    # Request patterns tied to known exploits, such as Log4j and Java deserialisation.
    ManagedRuleGroup("AWSManagedRulesKnownBadInputsRuleSet", priority=40),
]


# Headers never written to the WAF logs: they carry credentials and session tokens.
REDACTED_HEADERS = ["authorization", "cookie"]


@dataclass(frozen=True)
class WafArgs:
    account_id: str
    region: str
    # The load balancer the web ACL protects.
    alb_arn: pulumi.Input[str]
    # Requests one client IP may make per window before it's blocked.
    rate_limit: int
    # The window the limit is counted over, in seconds (60, 120, 300 or 600).
    rate_window_sec: int
    # Whether the managed rule groups only count matches or block them. Start
    # with "count", check what they'd block, then switch to "block".
    managed_rules_mode: ManagedRulesMode
    # Encrypts the WAF log group and sets its retention.
    logs: LogEncryption


class Waf(pulumi.ComponentResource):
    """
    AWS WAF in front of the ALB (SEC05-BP03, SEC06). The web ACL allows by
    default; its rules match in priority order:

      10  AWS IP reputation list          managed: count or block
      20  rate limit                      any client IP over `rate_limit` requests
                                          per window gets 429 Too Many Requests
                                          until its rate drops back under the limit
      30  AWS common rule set             managed: count or block
      40  AWS known bad inputs            managed: count or block

    Every rule publishes CloudWatch metrics and keeps sampled requests, so you
    can see what a rule matches before relying on it. Every request is also
    logged in full to a KMS-encrypted CloudWatch log group, with credentials
    and cookies redacted: in count mode, that's where false positives show up.
    """

    web_acl: aws.wafv2.WebAcl

    def __init__(self, name: str, args: WafArgs, opts: pulumi.ResourceOptions | None = None):
        super().__init__("learning:network:Waf", name, {}, opts)

        if args.rate_window_sec not in RATE_WINDOWS:
            raise ValueError(f"rate_window_sec must be one of {RATE_WINDOWS}, got {args.rate_window_sec}")
        if not 10 <= args.rate_limit <= 2_000_000_000:
            raise ValueError(f"rate_limit must be between 10 and 2,000,000,000, got {args.rate_limit}")
        if args.managed_rules_mode not in ("count", "block"):
            raise ValueError(f'managed_rules_mode must be "count" or "block", got "{args.managed_rules_mode}"')

        child_opts = pulumi.ResourceOptions(parent=self)

        def visibility(metric: str) -> aws.wafv2.WebAclVisibilityConfigArgsDict:
            return {"cloudwatch_metrics_enabled": True, "metric_name": metric, "sampled_requests_enabled": True}

        managed_rules: list[aws.wafv2.WebAclRuleArgsDict] = [
            {
                "name": group.name,
                "priority": group.priority,
                # Count overrides every rule in the group to count; none leaves their own (block) actions.
                "override_action": {"count": {}} if args.managed_rules_mode == "count" else {"none": {}},
                "statement": {"managed_rule_group_statement": {"vendor_name": "AWS", "name": group.name}},
                "visibility_config": visibility(f"{name}-{group.name}"),
            }
            for group in MANAGED_RULE_GROUPS
        ]

        self.web_acl = aws.wafv2.WebAcl(
            name,
            name=name,
            description="Protects the internet-facing load balancer",
            # Regional, for an ALB (CloudFront web ACLs are "CLOUDFRONT", in us-east-1).
            scope="REGIONAL",
            default_action={"allow": {}},
            custom_response_bodies=[
                {
                    "key": "rate-limited",
                    "content_type": "TEXT_PLAIN",
                    "content": "Too many requests. Slow down and try again shortly.\n",
                }
            ],
            rules=[
                {
                    "name": "rate-limit-per-ip",
                    "priority": 20,
                    "action": {
                        "block": {
                            "custom_response": {
                                "response_code": 429,
                                "custom_response_body_key": "rate-limited",
                                "response_headers": [{"name": "Retry-After", "value": str(args.rate_window_sec)}],
                            }
                        }
                    },
                    "statement": {
                        "rate_based_statement": {
                            # Counted per source IP: the ALB sees the client's address directly.
                            "aggregate_key_type": "IP",
                            "limit": args.rate_limit,
                            "evaluation_window_sec": args.rate_window_sec,
                        }
                    },
                    "visibility_config": visibility(f"{name}-rate-limit-per-ip"),
                },
                *managed_rules,
            ],
            visibility_config=visibility(name),
            opts=child_opts,
        )

        aws.wafv2.WebAclAssociation(name, resource_arn=args.alb_arn, web_acl_arn=self.web_acl.arn, opts=child_opts)

        self._logging(name, args)

        self.register_outputs({"webAclArn": self.web_acl.arn})

    def _logging(self, name: str, args: WafArgs) -> None:
        child_opts = pulumi.ResourceOptions(parent=self)
        # WAF only logs to log groups whose names start with "aws-waf-logs-".
        log_group = args.logs.log_group(f"{name}-logs", f"aws-waf-logs-{name}")

        # WAF delivers through CloudWatch Logs' log delivery service. Without
        # this policy WAF tries to add a broader one of its own.
        log_policy = aws.cloudwatch.LogResourcePolicy(
            f"{name}-logs",
            policy_name=f"{name}-waf-log-delivery",
            policy_document=policy_document(
                [
                    Statement(
                        sid="WafLogDelivery",
                        principals={"type": "Service", "identifiers": ["delivery.logs.amazonaws.com"]},
                        actions=["logs:CreateLogStream", "logs:PutLogEvents"],
                        resources=[pulumi.Output.concat(log_group.arn, ":log-stream:*")],
                        conditions={
                            "StringEquals": {"aws:SourceAccount": args.account_id},
                            "ArnLike": {"aws:SourceArn": f"arn:aws:logs:{args.region}:{args.account_id}:*"},
                        },
                    )
                ]
            ),
            opts=child_opts,
        )

        aws.wafv2.WebAclLoggingConfiguration(
            name,
            resource_arn=self.web_acl.arn,
            log_destination_configs=[log_group.arn],
            redacted_fields=[{"single_header": {"name": header}} for header in REDACTED_HEADERS],
            opts=pulumi.ResourceOptions(parent=self, depends_on=[log_policy]),
        )
