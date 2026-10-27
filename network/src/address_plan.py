from dataclasses import dataclass
from typing import Literal

from .cidr import subnet_cidr

Tier = Literal["public", "app", "data", "firewall"]


@dataclass(frozen=True)
class AddressPlan:
    vpc: str
    # CIDRs per tier, in the same order as the availability zones.
    tiers: dict[Tier, list[str]]


def address_plan(vpc_cidr: str, az_count: int) -> AddressPlan:
    """
    Lays out four tiers across up to three AZs. For a /16 VPC (10.0.0.0/16):

      app       /19  10.0.0.0, 10.0.32.0, 10.0.64.0     workloads (private, egress via NAT)
      public    /24  10.0.96.0, 10.0.97.0, 10.0.98.0    load balancers and NAT gateways
      firewall  /28  10.0.99.0, 10.0.99.16, 10.0.99.32  Network Firewall endpoints
      data      /22  10.0.100.0, 10.0.104.0, 10.0.108.0 databases (isolated: no internet route)

    10.0.112.0 - 10.0.255.255 is left free for future tiers.
    """
    if not 1 <= az_count <= 3:
        raise ValueError(f"the address plan supports 1-3 availability zones, got {az_count}")

    azs = range(az_count)
    return AddressPlan(
        vpc=vpc_cidr,
        tiers={
            "app": [subnet_cidr(vpc_cidr, 3, i) for i in azs],
            "public": [subnet_cidr(vpc_cidr, 8, 96 + i) for i in azs],
            "firewall": [subnet_cidr(vpc_cidr, 12, 99 * 16 + i) for i in azs],
            "data": [subnet_cidr(vpc_cidr, 6, 25 + i) for i in azs],
        },
    )
