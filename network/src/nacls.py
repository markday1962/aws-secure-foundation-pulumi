from dataclasses import dataclass
from typing import Literal

from .address_plan import AddressPlan, Tier

Protocol = Literal["tcp", "-1"]


@dataclass(frozen=True)
class NaclRule:
    rule_no: int
    protocol: Protocol
    action: Literal["allow"]
    cidr_block: str
    from_port: int
    to_port: int


@dataclass(frozen=True)
class TierNacl:
    ingress: list[NaclRule]
    egress: list[NaclRule]


Ports = tuple[int, int]
Entry = tuple[str, Protocol, Ports]

# AWS's default limit is 20 rules per direction per network ACL.
MAX_RULES = 20
ANYWHERE = "0.0.0.0/0"
# Return traffic arrives on the client's ephemeral port.
EPHEMERAL: Ports = (1024, 65535)


def nacl_rules(plan: AddressPlan, app_port: int, data_ports: list[int]) -> dict[Tier, TierNacl]:
    """
    Network ACLs: the stateless, subnet-level second layer under security
    groups. They enforce which *tiers* may talk at all; security groups then
    decide which *resources* may. Being stateless, every allowed flow needs a
    matching rule for its return traffic. Anything not listed is denied.

    Traffic to the VPC's DNS resolver and the instance metadata service isn't
    subject to network ACLs, so no rules are needed for it.
    """
    pub, app, data = plan.tiers["public"], plan.tiers["app"], plan.tiers["data"]

    # Load balancer → target traffic leaves the public tier under the ephemeral-range rule.
    if not EPHEMERAL[0] <= app_port <= EPHEMERAL[1]:
        raise ValueError(f"app_port must be between {EPHEMERAL[0]} and {EPHEMERAL[1]}, got {app_port}")

    https: Ports = (443, 443)

    def port(p: int) -> Ports:
        return (p, p)

    def tcp(cidr: str, ports: Ports) -> Entry:
        return (cidr, "tcp", ports)

    def all_traffic(cidr: str) -> Entry:
        return (cidr, "-1", (0, 0))

    def rules(entries: list[Entry]) -> list[NaclRule]:
        return [
            NaclRule(rule_no=100 + i * 10, protocol=protocol, action="allow", cidr_block=cidr, from_port=lo, to_port=hi)
            for i, (cidr, protocol, (lo, hi)) in enumerate(entries)
        ]

    result: dict[Tier, TierNacl] = {
        # Load balancers (HTTPS in) and NAT gateways (HTTPS out on behalf of the app tier).
        "public": TierNacl(
            ingress=rules(
                [
                    tcp(ANYWHERE, https),  # clients → load balancer; app tier → NAT
                    tcp(ANYWHERE, EPHEMERAL),  # responses: internet → NAT, targets → load balancer
                ]
            ),
            egress=rules(
                [
                    tcp(ANYWHERE, https),  # NAT → internet
                    tcp(ANYWHERE, EPHEMERAL),  # load balancer → clients and targets (app_port ≥ 1024), NAT → app tier
                ]
            ),
        ),
        "app": TierNacl(
            ingress=rules(
                [
                    *(tcp(c, port(app_port)) for c in pub),  # load balancer → app
                    *(tcp(c, https) for c in app),  # app → interface endpoints (which live in the app subnets)
                    tcp(ANYWHERE, EPHEMERAL),  # responses from the internet, AWS APIs and the data tier
                ]
            ),
            egress=rules(
                [
                    tcp(ANYWHERE, https),  # AWS APIs, endpoints, allow-listed internet
                    *(tcp(c, port(p)) for c in data for p in data_ports),
                    *(tcp(c, EPHEMERAL) for c in pub),  # responses to the load balancer
                    *(tcp(c, EPHEMERAL) for c in app),  # endpoint responses
                ]
            ),
        ),
        # Isolated: reachable only from the app tier, and only on the data ports.
        "data": TierNacl(
            ingress=rules(
                [
                    *(tcp(c, port(p)) for c in app for p in data_ports),
                    *(all_traffic(c) for c in data),  # replication within the tier
                ]
            ),
            egress=rules([*(tcp(c, EPHEMERAL) for c in app), *(all_traffic(c) for c in data)]),
        ),
        # Network Firewall must see all traffic to inspect it; AWS advises against filtering its subnets.
        "firewall": TierNacl(
            ingress=rules([all_traffic(ANYWHERE)]),
            egress=rules([all_traffic(ANYWHERE)]),
        ),
    }

    for tier, nacl in result.items():
        for direction, entries in (("ingress", nacl.ingress), ("egress", nacl.egress)):
            if len(entries) > MAX_RULES:
                raise ValueError(f"{tier} network ACL needs {len(entries)} {direction} rules; the limit is {MAX_RULES}")
    return result
