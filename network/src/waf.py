from dataclasses import dataclass

import pulumi
import pulumi_aws as aws

# The evaluation windows AWS WAF supports for rate-based rules, in seconds.
RATE_WINDOWS = (60, 120, 300, 600)


@dataclass(frozen=True)
class WafArgs:
    # The load balancer the web ACL protects.
    alb_arn: pulumi.Input[str]
    # Requests one client IP may make per window before it's blocked.
    rate_limit: int
    # The window the limit is counted over, in seconds (60, 120, 300 or 600).
    rate_window_sec: int


class Waf(pulumi.ComponentResource):
    """
    AWS WAF in front of the ALB (SEC05-BP03, SEC06). The web ACL allows by
    default; its rules block what they match, in priority order:

      1. rate limit: any client IP over `rate_limit` requests per window gets
         429 Too Many Requests until its rate drops back under the limit

    Every rule publishes CloudWatch metrics and keeps sampled requests, so you
    can see what a rule matches before relying on it.
    """

    web_acl: aws.wafv2.WebAcl

    def __init__(self, name: str, args: WafArgs, opts: pulumi.ResourceOptions | None = None):
        super().__init__("learning:network:Waf", name, {}, opts)

        if args.rate_window_sec not in RATE_WINDOWS:
            raise ValueError(f"rate_window_sec must be one of {RATE_WINDOWS}, got {args.rate_window_sec}")
        if not 10 <= args.rate_limit <= 2_000_000_000:
            raise ValueError(f"rate_limit must be between 10 and 2,000,000,000, got {args.rate_limit}")

        child_opts = pulumi.ResourceOptions(parent=self)

        def visibility(metric: str) -> aws.wafv2.WebAclVisibilityConfigArgsDict:
            return {"cloudwatch_metrics_enabled": True, "metric_name": metric, "sampled_requests_enabled": True}

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
                    "priority": 10,
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
            ],
            visibility_config=visibility(name),
            opts=child_opts,
        )

        aws.wafv2.WebAclAssociation(name, resource_arn=args.alb_arn, web_acl_arn=self.web_acl.arn, opts=child_opts)

        self.register_outputs({"webAclArn": self.web_acl.arn})
