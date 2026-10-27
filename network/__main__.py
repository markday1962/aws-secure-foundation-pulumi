import re

import pulumi

from src.load_balancer import LoadBalancer, LoadBalancerArgs
from src.network import Network, NetworkArgs

config = pulumi.Config()
aws_config = pulumi.Config("aws")

# The account this stack is pinned to. The provider refuses to run against
# any other, and policies use it to scope access to this account only.
allowed_account_ids = aws_config.require_object("allowedAccountIds")
account_id = str(allowed_account_ids[0]) if allowed_account_ids else ""
if not re.fullmatch(r"\d{12}", account_id):
    raise ValueError("aws:allowedAccountIds must hold the 12-digit account ID this stack deploys to")

nat_gateways = config.get("natGateways", default="perAz")
if nat_gateways not in ("single", "perAz"):
    raise ValueError(f'natGateways must be "single" or "perAz", got "{nat_gateways}"')

region = aws_config.require("region")
app_port = config.get_int("appPort", default=8443)
log_retention_days = config.get_int("logRetentionDays", default=365)

network = Network(
    "learning",
    NetworkArgs(
        account_id=account_id,
        region=region,
        cidr=config.get("vpcCidr", default="10.0.0.0/16"),
        availability_zones=config.require_object("availabilityZones"),
        nat_gateways=nat_gateways,
        app_port=app_port,
        data_ports=config.get_object("dataPorts", default=[5432]),
        interface_endpoints=config.get_object("interfaceEndpoints", default=[]),
        log_retention_days=log_retention_days,
    ),
)

domain_name = config.require("domainName")
alb = LoadBalancer(
    "learning-alb",
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

pulumi.export("vpcId", network.vpc.id)
pulumi.export("publicSubnetIds", [s.id for s in network.subnets["public"]])
pulumi.export("appSubnetIds", [s.id for s in network.subnets["app"]])
pulumi.export("dataSubnetIds", [s.id for s in network.subnets["data"]])
pulumi.export(
    "securityGroupIds",
    {
        "alb": network.security_groups.alb.id,
        "app": network.security_groups.app.id,
        "data": network.security_groups.data.id,
    },
)
pulumi.export("natGatewayIds", [n.id for n in network.nat_gateways])
pulumi.export("logKeyArn", network.log_key.arn)
pulumi.export("albArn", alb.alb.arn)
pulumi.export("albDnsName", alb.alb.dns_name)
pulumi.export("httpsListenerArn", alb.https_listener.arn)
pulumi.export("targetGroupArn", alb.target_group.arn)
pulumi.export("url", f"https://{domain_name}")
