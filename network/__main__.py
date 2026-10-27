import re
from dataclasses import asdict

import pulumi

from src.features import Features
from src.load_balancer import LoadBalancer, LoadBalancerArgs
from src.network import Network, NetworkArgs
from src.waf import Waf, WafArgs

config = pulumi.Config()
aws_config = pulumi.Config("aws")

# Every physical name (buckets, trail, log groups, KMS aliases, security
# groups, the ALB) starts with this, so stacks can share an account. The ALB's
# 32-character name limit caps the stack name at 10 characters.
stack = pulumi.get_stack()
if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,9}", stack):
    raise ValueError(f'stack name must be 1-10 lowercase letters, digits or hyphens, got "{stack}"')
prefix = f"learning-{stack}"

# The account this stack is pinned to. The provider refuses to run against
# any other, and policies use it to scope access to this account only.
allowed_account_ids = aws_config.require_object("allowedAccountIds")
account_id = str(allowed_account_ids[0]) if allowed_account_ids else ""
if not re.fullmatch(r"\d{12}", account_id):
    raise ValueError("aws:allowedAccountIds must hold the 12-digit account ID this stack deploys to")

# What to deploy, starting with the VPC itself. Everything is off unless
# switched on; Features checks that what's on has what it depends on.
features = Features(
    vpc=config.get_bool("vpc", default=False),
    public_subnets=config.get_bool("publicSubnets", default=False),
    app_subnets=config.get_bool("appSubnets", default=False),
    data_subnets=config.get_bool("dataSubnets", default=False),
    internet_gateway=config.get_bool("internetGateway", default=False),
    nat_gateways=config.get("natGateways", default="none"),  # pyright: ignore[reportArgumentType]  (checked by Features)
    network_acls=config.get_bool("networkAcls", default=False),
    security_groups=config.get_bool("securityGroups", default=False),
    gateway_endpoints=config.get_bool("gatewayEndpoints", default=False),
    interface_endpoints=config.get_object("interfaceEndpoints", default=[]),
    flow_logs=config.get_bool("flowLogs", default=False),
    load_balancer=config.get_bool("loadBalancer", default=False),
    waf=config.get_bool("waf", default=False),
)

region = aws_config.require("region")
app_port = config.get_int("appPort", default=8443)
log_retention_days = config.get_int("logRetentionDays", default=365)

pulumi.export("features", asdict(features))

# With the VPC off there's nothing to deploy: Features has already refused
# anything else that's on.
if features.vpc:
    network = Network(
        prefix,
        NetworkArgs(
            account_id=account_id,
            region=region,
            cidr=config.get("vpcCidr", default="10.0.0.0/16"),
            availability_zones=config.require_object("availabilityZones"),
            features=features,
            app_port=app_port,
            data_ports=config.get_object("dataPorts", default=[5432]),
            log_retention_days=log_retention_days,
        ),
    )

    pulumi.export("vpcId", network.vpc.id)
    for tier, subnets in network.subnets.items():
        if subnets:
            pulumi.export(f"{tier}SubnetIds", [s.id for s in subnets])
    if network.security_groups:
        pulumi.export(
            "securityGroupIds",
            {
                "alb": network.security_groups.alb.id,
                "app": network.security_groups.app.id,
                "data": network.security_groups.data.id,
            },
        )
    if network.nat_gateways:
        pulumi.export("natGatewayIds", [n.id for n in network.nat_gateways])
    if network.logs:
        pulumi.export("logKeyArn", network.logs.key.arn)

    # ── The internet-facing ALB. Features guarantees the security groups exist.
    if features.load_balancer and network.security_groups:
        domain_name = config.require("domainName")
        alb = LoadBalancer(
            f"{prefix}-alb",
            LoadBalancerArgs(
                account_id=account_id,
                region=region,
                vpc_id=network.vpc.id,
                subnet_ids=[s.id for s in network.subnets["public"]],
                security_group_id=network.security_groups.alb.id,
                app_port=app_port,
                domain_name=domain_name,
                hosted_zone_name=config.require("hostedZoneName"),
                deletion_protection=config.get_bool("albDeletionProtection", default=False),
                log_retention_days=log_retention_days,
            ),
        )
        pulumi.export("albArn", alb.alb.arn)
        pulumi.export("albDnsName", alb.alb.dns_name)
        pulumi.export("httpsListenerArn", alb.https_listener.arn)
        pulumi.export("targetGroupArn", alb.target_group.arn)
        pulumi.export("url", f"https://{domain_name}")

        # ── AWS WAF on the ALB. Features guarantees the log key exists.
        if features.waf and network.logs:
            waf_managed_rules_mode = config.get("wafManagedRulesMode", default="count")
            if waf_managed_rules_mode not in ("count", "block"):
                raise ValueError(f'wafManagedRulesMode must be "count" or "block", got "{waf_managed_rules_mode}"')

            waf_bot_control = config.get("wafBotControl", default="common")
            if waf_bot_control not in ("off", "common", "targeted"):
                raise ValueError(f'wafBotControl must be "off", "common" or "targeted", got "{waf_bot_control}"')

            waf = Waf(
                f"{prefix}-waf",
                WafArgs(
                    account_id=account_id,
                    region=region,
                    alb_arn=alb.alb.arn,
                    rate_limit=config.get_int("wafRateLimit", default=1000),
                    rate_window_sec=config.get_int("wafRateWindowSec", default=300),
                    managed_rules_mode=waf_managed_rules_mode,
                    bot_control=waf_bot_control,
                    logs=network.logs,
                ),
            )
            pulumi.export("webAclArn", waf.web_acl.arn)
