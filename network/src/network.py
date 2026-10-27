from dataclasses import asdict, dataclass

import pulumi
import pulumi_aws as aws

from .address_plan import Tier, address_plan
from .endpoints import VpcEndpoints, VpcEndpointsArgs
from .features import Features
from .logging import LogEncryption, LogEncryptionArgs
from .nacls import nacl_rules
from .policy import Statement, policy_document
from .security_groups import TierSecurityGroups, TierSecurityGroupsArgs


@dataclass(frozen=True)
class NetworkArgs:
    account_id: str
    region: str
    # VPC address range. A /16 fits the address plan (see address_plan.py).
    cidr: str
    # One subnet per tier in each of these AZs (max 3).
    availability_zones: list[str]
    # What to deploy beyond the VPC and its subnets. All off by default.
    features: Features
    # Port the app tier listens on behind the load balancer (1024-65535).
    app_port: int
    # Ports the data tier listens on.
    data_ports: list[int]
    log_retention_days: int


class Network(pulumi.ComponentResource):
    """
    A three-tier VPC built for defence in depth (Well-Architected SEC05):

      internet ⇄ IGW ⇄ public (ALB, NAT) → app (workloads) → data (isolated)

    Every layer filters independently: route tables decide what's reachable at
    all, network ACLs which tiers may talk, and security groups which resources.
    Flow logs record it all, encrypted with a customer-managed key.

    Everything is switched on through `features` (see features.py), starting
    with the VPC itself and each subnet tier. The VPC is protected: once it's
    deployed, Pulumi refuses to delete it until it's deliberately unprotected.
    Create a Network only when `features.vpc` is on.
    """

    vpc: aws.ec2.Vpc
    # One subnet per AZ for each tier that's switched on; empty for the others.
    subnets: dict[Tier, list[aws.ec2.Subnet]]
    # None unless features.security_groups.
    security_groups: TierSecurityGroups | None
    nat_gateways: list[aws.ec2.NatGateway]
    # The KMS log key and log-group factory, for this and other components'
    # logs (e.g. WAF). None unless something needs it.
    logs: LogEncryption | None

    def __init__(self, name: str, args: NetworkArgs, opts: pulumi.ResourceOptions | None = None):
        super().__init__("learning:network:Network", name, {}, opts)

        features = args.features
        if not features.vpc:
            raise ValueError("Network needs features.vpc switched on")

        # Every tier's addresses are fixed by the plan, whether or not the tier
        # is deployed, so switching a tier on never moves another.
        plan = address_plan(args.cidr, len(args.availability_zones))
        azs = args.availability_zones
        child_opts = pulumi.ResourceOptions(parent=self)

        def tag(suffix: str) -> dict[str, str]:
            return {"Name": f"{name}-{suffix}"}

        self.logs = (
            LogEncryption(
                f"{name}-logs",
                LogEncryptionArgs(
                    account_id=args.account_id, region=args.region, retention_days=args.log_retention_days
                ),
                opts=child_opts,
            )
            if features.log_encryption
            else None
        )

        self.vpc = aws.ec2.Vpc(
            name,
            cidr_block=plan.vpc,
            enable_dns_support=True,
            enable_dns_hostnames=True,
            tags=tag("vpc"),
            # Switching the VPC off would take everything in it down; Pulumi
            # refuses until it's deliberately unprotected.
            opts=pulumi.ResourceOptions(parent=self, protect=True),
        )

        # ── Subnets: one per AZ for each tier that's on. None assign public IPs automatically.
        def make_subnets(tier: Tier) -> list[aws.ec2.Subnet]:
            return [
                aws.ec2.Subnet(
                    f"{name}-{tier}-{az}",
                    vpc_id=self.vpc.id,
                    availability_zone=az,
                    cidr_block=plan.tiers[tier][i],
                    map_public_ip_on_launch=False,
                    tags={**tag(f"{tier}-{az}"), "tier": tier},
                    opts=child_opts,
                )
                for i, az in enumerate(azs)
            ]

        tiers_on: dict[Tier, bool] = {
            "public": features.public_subnets,
            "app": features.app_subnets,
            "data": features.data_subnets,
        }
        self.subnets = {tier: make_subnets(tier) if on else [] for tier, on in tiers_on.items()}

        # ── Ingress: the Internet Gateway.
        igw = (
            aws.ec2.InternetGateway(name, vpc_id=self.vpc.id, tags=tag("igw"), opts=child_opts)
            if features.internet_gateway
            else None
        )

        def route_table(table_id: str) -> aws.ec2.RouteTable:
            return aws.ec2.RouteTable(f"{name}-{table_id}", vpc_id=self.vpc.id, tags=tag(table_id), opts=child_opts)

        def associate(assoc_id: str, subnet: aws.ec2.Subnet, table: aws.ec2.RouteTable) -> None:
            aws.ec2.RouteTableAssociation(
                f"{name}-{assoc_id}", subnet_id=subnet.id, route_table_id=table.id, opts=child_opts
            )

        # Public subnets: straight out through the Internet Gateway, if there is one.
        if self.subnets["public"]:
            public_table = route_table("public")
            if igw:
                aws.ec2.Route(
                    f"{name}-public-internet",
                    route_table_id=public_table.id,
                    destination_cidr_block="0.0.0.0/0",
                    gateway_id=igw.id,
                    opts=child_opts,
                )
            for i, az in enumerate(azs):
                associate(f"public-{az}", self.subnets["public"][i], public_table)

        # ── Egress: NAT gateways in the public subnets.
        nat_azs = {"none": [], "single": azs[:1], "perAz": azs}[features.nat_gateways]
        self.nat_gateways = []
        for az in nat_azs:
            eip = aws.ec2.Eip(f"{name}-nat-{az}", domain="vpc", tags=tag(f"nat-{az}"), opts=child_opts)
            self.nat_gateways.append(
                aws.ec2.NatGateway(
                    f"{name}-{az}",
                    allocation_id=eip.id,
                    subnet_id=self.subnets["public"][azs.index(az)].id,
                    tags=tag(f"nat-{az}"),
                    opts=pulumi.ResourceOptions(parent=self, depends_on=[igw] if igw else []),
                )
            )

        # App subnets: internet traffic via NAT, if there is one. One table per
        # AZ so each can use its own NAT.
        app_tables: list[aws.ec2.RouteTable] = []
        for i, az in enumerate(azs if self.subnets["app"] else []):
            table = route_table(f"app-{az}")
            if self.nat_gateways:
                nat = self.nat_gateways[i if features.nat_gateways == "perAz" else 0]
                aws.ec2.Route(
                    f"{name}-app-{az}-egress",
                    route_table_id=table.id,
                    destination_cidr_block="0.0.0.0/0",
                    nat_gateway_id=nat.id,
                    opts=child_opts,
                )
            associate(f"app-{az}", self.subnets["app"][i], table)
            app_tables.append(table)

        # Data subnets: no default route at all. They can reach only the VPC.
        if self.subnets["data"]:
            data_table = route_table("data")
            for i, az in enumerate(azs):
                associate(f"data-{az}", self.subnets["data"][i], data_table)

        # ── Network ACLs per tier, and the default ACL stripped of its allow-all
        # rules. Without the tier ACLs, every subnet falls back to the default
        # ACL, so the VPC carries no traffic.
        if features.network_acls:
            for tier, nacl in nacl_rules(plan, args.app_port, args.data_ports).items():
                if not self.subnets[tier]:
                    continue
                aws.ec2.NetworkAcl(
                    f"{name}-{tier}",
                    vpc_id=self.vpc.id,
                    subnet_ids=[s.id for s in self.subnets[tier]],
                    ingress=[aws.ec2.NetworkAclIngressArgs(**asdict(r)) for r in nacl.ingress],
                    egress=[aws.ec2.NetworkAclEgressArgs(**asdict(r)) for r in nacl.egress],
                    tags=tag(f"{tier}-nacl"),
                    opts=child_opts,
                )
        aws.ec2.DefaultNetworkAcl(
            name,
            default_network_acl_id=self.vpc.default_network_acl_id,
            tags=tag("default-nacl-deny-all"),
            # Every subnet has its own ACL; don't fight AWS over the default ACL's associations.
            opts=pulumi.ResourceOptions(parent=self, ignore_changes=["subnet_ids"]),
        )

        # The VPC's built-in default security group, with every rule removed (CIS 5.4).
        aws.ec2.DefaultSecurityGroup(
            name, vpc_id=self.vpc.id, ingress=[], egress=[], tags=tag("default-sg-locked"), opts=child_opts
        )

        # ── Security groups per tier, chained by reference.
        self.security_groups = (
            TierSecurityGroups(
                f"{name}-sg",
                TierSecurityGroupsArgs(vpc_id=self.vpc.id, app_port=args.app_port, data_ports=args.data_ports),
                opts=child_opts,
            )
            if features.security_groups
            else None
        )

        # ── Private access to AWS APIs.
        if features.gateway_endpoints or features.interface_endpoints:
            VpcEndpoints(
                f"{name}-vpce",
                VpcEndpointsArgs(
                    vpc_id=self.vpc.id,
                    region=args.region,
                    account_id=args.account_id,
                    gateway_route_table_ids=[t.id for t in app_tables] if features.gateway_endpoints else [],
                    interface_services=features.interface_endpoints,
                    interface_subnet_ids=[s.id for s in self.subnets["app"]],
                    security_group_id=self.security_groups.endpoints.id if self.security_groups else None,
                ),
                opts=child_opts,
            )

        # ── VPC Flow Logs: every accepted and rejected flow, at one-minute granularity.
        if features.flow_logs and self.logs:
            self._flow_logs(name, args, self.logs)

        self.register_outputs({"vpcId": self.vpc.id})

    def _flow_logs(self, name: str, args: NetworkArgs, logs: LogEncryption) -> None:
        child_opts = pulumi.ResourceOptions(parent=self)
        log_group = logs.log_group(f"{name}-flow", f"/{name}/vpc/flow-logs")

        role = aws.iam.Role(
            f"{name}-flow-logs",
            assume_role_policy=policy_document(
                [
                    Statement(
                        principals={"type": "Service", "identifiers": ["vpc-flow-logs.amazonaws.com"]},
                        actions=["sts:AssumeRole"],
                        # Only flow logs in this account may use the role (confused-deputy protection).
                        conditions={
                            "StringEquals": {"aws:SourceAccount": args.account_id},
                            "ArnLike": {"aws:SourceArn": f"arn:aws:ec2:{args.region}:{args.account_id}:vpc-flow-log/*"},
                        },
                    )
                ]
            ),
            opts=child_opts,
        )
        aws.iam.RolePolicy(
            f"{name}-flow-logs",
            role=role.name,
            policy=policy_document(
                [
                    Statement(
                        actions=["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"],
                        resources=[log_group.arn, pulumi.Output.concat(log_group.arn, ":*")],
                    )
                ]
            ),
            opts=child_opts,
        )

        aws.ec2.FlowLog(
            name,
            vpc_id=self.vpc.id,
            traffic_type="ALL",
            log_destination_type="cloud-watch-logs",
            log_destination=log_group.arn,
            iam_role_arn=role.arn,
            max_aggregation_interval=60,
            # Version 5 fields add packet-level addresses, direction and path, which
            # show traffic through NAT as it really flowed.
            log_format=" ".join(
                [
                    "${version}",
                    "${account-id}",
                    "${interface-id}",
                    "${srcaddr}",
                    "${dstaddr}",
                    "${srcport}",
                    "${dstport}",
                    "${protocol}",
                    "${packets}",
                    "${bytes}",
                    "${start}",
                    "${end}",
                    "${action}",
                    "${log-status}",
                    "${vpc-id}",
                    "${subnet-id}",
                    "${instance-id}",
                    "${tcp-flags}",
                    "${type}",
                    "${pkt-srcaddr}",
                    "${pkt-dstaddr}",
                    "${region}",
                    "${az-id}",
                    "${flow-direction}",
                    "${traffic-path}",
                ]
            ),  # fmt: skip
            tags={"Name": f"{name}-flow-log"},
            opts=child_opts,
        )
