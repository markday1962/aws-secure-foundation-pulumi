import re

import pulumi

from src.network import DnsFirewallSettings, Network, NetworkArgs, NetworkFirewallSettings

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

network = Network(
    "learning",
    NetworkArgs(
        account_id=account_id,
        region=aws_config.require("region"),
        cidr=config.get("vpcCidr", default="10.0.0.0/16"),
        availability_zones=config.require_object("availabilityZones"),
        nat_gateways=nat_gateways,
        app_port=config.get_int("appPort", default=8443),
        data_ports=config.get_object("dataPorts", default=[5432]),
        allowed_domains=config.require_object("allowedDomains"),
        network_firewall=NetworkFirewallSettings(
            enabled=config.get_bool("networkFirewall", default=True),
            managed_rule_groups=config.require_object("networkFirewallManagedRuleGroups"),
        ),
        dns_firewall=DnsFirewallSettings(
            enabled=config.get_bool("dnsFirewall", default=True),
            managed_block_list_ids=config.get_object("dnsFirewallManagedListIds", default=[]),
        ),
        interface_endpoints=config.get_object("interfaceEndpoints", default=[]),
        log_retention_days=config.get_int("logRetentionDays", default=365),
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
