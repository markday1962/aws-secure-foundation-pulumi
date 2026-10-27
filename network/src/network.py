from dataclasses import asdict, dataclass
from typing import Literal

import pulumi
import pulumi_aws as aws

from .address_plan import Tier, address_plan
from .endpoints import VpcEndpoints, VpcEndpointsArgs
from .logging import LogEncryption, LogEncryptionArgs
from .nacls import nacl_rules
from .policy import Statement, policy_document
from .security_groups import TierSecurityGroups, TierSecurityGroupsArgs

NatMode = Literal["single", "perAz"]


@dataclass(frozen=True)
class NetworkArgs:
    account_id: str
    region: str
    # VPC address range. A /16 fits the address plan (see address_plan.py).
    cidr: str
    # One subnet per tier in each of these AZs (max 3).
    availability_zones: list[str]
    nat_gateways: NatMode
    # Port the app tier listens on behind the load balancer (1024-65535).
    app_port: int
    # Ports the data tier listens on.
    data_ports: list[int]
    # Interface endpoint services, e.g. "ssm". Empty to skip interface endpoints.
    interface_endpoints: list[str]
    log_retention_days: int


class Network(pulumi.ComponentResource):
    """
    A three-tier VPC built for defence in depth (Well-Architected SEC05):

      internet ⇄ IGW ⇄ public (ALB, NAT) → app (workloads) → data (isolated)

    Every layer filters independently: route tables decide what's reachable at
    all, network ACLs which tiers may talk, and security groups which resources.
    Flow logs record it all, encrypted with a customer-managed key.
    """

    vpc: aws.ec2.Vpc
    subnets: dict[Tier, list[aws.ec2.Subnet]]
    security_groups: TierSecurityGroups
    nat_gateways: list[aws.ec2.NatGateway]
    log_key: aws.kms.Key

    def __init__(self, name: str, args: NetworkArgs, opts: pulumi.ResourceOptions | None = None):
        super().__init__("learning:network:Network", name, {}, opts)

        plan = address_plan(args.cidr, len(args.availability_zones))
        nacls = nacl_rules(plan, args.app_port, args.data_ports)
        azs = args.availability_zones
        child_opts = pulumi.ResourceOptions(parent=self)

        def tag(suffix: str) -> dict[str, str]:
            return {"Name": f"{name}-{suffix}"}

        logs = LogEncryption(
            f"{name}-logs",
            LogEncryptionArgs(account_id=args.account_id, region=args.region, retention_days=args.log_retention_days),
            opts=child_opts,
        )
        self.log_key = logs.key

        self.vpc = aws.ec2.Vpc(
            name,
            cidr_block=plan.vpc,
            enable_dns_support=True,
            enable_dns_hostnames=True,
            tags=tag("vpc"),
            opts=child_opts,
        )

        # ── Subnets: one per tier per AZ. None assign public IPs automatically.
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

        self.subnets = {
            "public": make_subnets("public"),
            "app": make_subnets("app"),
            "data": make_subnets("data"),
        }

        # ── Ingress: the Internet Gateway.
        igw = aws.ec2.InternetGateway(name, vpc_id=self.vpc.id, tags=tag("igw"), opts=child_opts)

        def route_table(table_id: str) -> aws.ec2.RouteTable:
            return aws.ec2.RouteTable(f"{name}-{table_id}", vpc_id=self.vpc.id, tags=tag(table_id), opts=child_opts)

        def associate(assoc_id: str, subnet: aws.ec2.Subnet, table: aws.ec2.RouteTable) -> None:
            aws.ec2.RouteTableAssociation(
                f"{name}-{assoc_id}", subnet_id=subnet.id, route_table_id=table.id, opts=child_opts
            )

        # Public subnets: straight out through the Internet Gateway.
        public_table = route_table("public")
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
        nat_azs = azs if args.nat_gateways == "perAz" else azs[:1]
        self.nat_gateways = []
        for az in nat_azs:
            eip = aws.ec2.Eip(f"{name}-nat-{az}", domain="vpc", tags=tag(f"nat-{az}"), opts=child_opts)
            self.nat_gateways.append(
                aws.ec2.NatGateway(
                    f"{name}-{az}",
                    allocation_id=eip.id,
                    subnet_id=self.subnets["public"][azs.index(az)].id,
                    tags=tag(f"nat-{az}"),
                    opts=pulumi.ResourceOptions(parent=self, depends_on=[igw]),
                )
            )

        # App subnets: internet traffic via NAT. One table per AZ
        # so each can use its own NAT.
        app_tables: list[aws.ec2.RouteTable] = []
        for i, az in enumerate(azs):
            table = route_table(f"app-{az}")
            nat = self.nat_gateways[i if args.nat_gateways == "perAz" else 0]
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
        data_table = route_table("data")
        for i, az in enumerate(azs):
            associate(f"data-{az}", self.subnets["data"][i], data_table)

        # ── Network ACLs per tier, and the default ACL stripped of its allow-all rules.
        for tier, nacl in nacls.items():
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
        self.security_groups = TierSecurityGroups(
            f"{name}-sg",
            TierSecurityGroupsArgs(vpc_id=self.vpc.id, app_port=args.app_port, data_ports=args.data_ports),
            opts=child_opts,
        )

        # ── Private access to AWS APIs.
        VpcEndpoints(
            f"{name}-vpce",
            VpcEndpointsArgs(
                vpc_id=self.vpc.id,
                region=args.region,
                account_id=args.account_id,
                gateway_route_table_ids=[t.id for t in app_tables],
                interface_services=args.interface_endpoints,
                interface_subnet_ids=[s.id for s in self.subnets["app"]],
                security_group_id=self.security_groups.endpoints.id,
            ),
            opts=child_opts,
        )

        # ── VPC Flow Logs: every accepted and rejected flow, at one-minute granularity.
        self._flow_logs(name, args, logs)

        self.register_outputs({"vpcId": self.vpc.id})

    def _flow_logs(self, name: str, args: NetworkArgs, logs: LogEncryption) -> None:
        child_opts = pulumi.ResourceOptions(parent=self)
        log_group = logs.log_group(f"{name}-flow", "/learning/vpc/flow-logs")

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
