from dataclasses import dataclass, field
from typing import Literal

# "none" = no NAT. "single" = one NAT shared by all AZs. "perAz" = one per AZ (survives an AZ outage).
NatMode = Literal["none", "single", "perAz"]
NAT_MODES = ("none", "single", "perAz")


@dataclass(frozen=True)
class Features:
    """
    Which parts of the network to deploy. The VPC, its subnets and route
    tables, and the locked-down default security group and network ACL are
    always deployed. Everything else is off until switched on, so
    infrastructure can be brought up one controlled step at a time.

    Without network_acls, every subnet uses the VPC's default network ACL,
    which denies all traffic. So anything that carries traffic needs it too.
    """

    # Internet Gateway, and the public subnets' default route to it.
    internet_gateway: bool = False
    # NAT gateways for the app tier's outbound internet access.
    nat_gateways: NatMode = "none"
    # A network ACL per tier. Off, all subnet traffic is denied.
    network_acls: bool = False
    # The ALB, app, data and endpoint security groups.
    security_groups: bool = False
    # Free S3 and DynamoDB gateway endpoints on the app route tables.
    gateway_endpoints: bool = False
    # Interface endpoint services, e.g. "ssm". Empty for none.
    interface_endpoints: list[str] = field(default_factory=list)
    # VPC flow logs to a KMS-encrypted CloudWatch log group.
    flow_logs: bool = False
    # The internet-facing ALB, its certificate and DNS record.
    load_balancer: bool = False
    # AWS WAF on the ALB, with its logging.
    waf: bool = False

    def __post_init__(self) -> None:
        if self.nat_gateways not in NAT_MODES:
            raise ValueError(f'nat_gateways must be one of {NAT_MODES}, got "{self.nat_gateways}"')

        requirements = [
            (self.nat_gateways != "none", "nat_gateways", ["internet_gateway", "network_acls"]),
            (self.gateway_endpoints, "gateway_endpoints", ["network_acls"]),
            (bool(self.interface_endpoints), "interface_endpoints", ["network_acls", "security_groups"]),
            (self.load_balancer, "load_balancer", ["internet_gateway", "network_acls", "security_groups"]),
            (self.waf, "waf", ["load_balancer"]),
        ]
        for enabled, feature, needs in requirements:
            missing = [n for n in needs if not getattr(self, n)]
            if enabled and missing:
                raise ValueError(f"{feature} needs {' and '.join(missing)} switched on too")

    @property
    def log_encryption(self) -> bool:
        """Whether anything needs the network's KMS log key."""
        return self.flow_logs or self.waf
