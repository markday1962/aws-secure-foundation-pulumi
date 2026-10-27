from dataclasses import dataclass
from typing import Any

import pulumi
import pulumi_aws as aws


@dataclass(frozen=True)
class TierSecurityGroupsArgs:
    vpc_id: pulumi.Input[str]
    # Port the application listens on behind the load balancer.
    app_port: int
    # Ports the data tier listens on, e.g. [5432] for PostgreSQL.
    data_ports: list[int]


class TierSecurityGroups(pulumi.ComponentResource):
    """
    One security group per tier, chained by reference rather than by CIDR:

      internet ─443→ alb ─app_port→ app ─data_ports→ data
                                 app ─443→ endpoints, internet (through NAT + firewall)

    Groups start with no rules (the provider removes AWS's default allow-all
    egress), so each rule below is the only way traffic is permitted.
    """

    alb: aws.ec2.SecurityGroup
    app: aws.ec2.SecurityGroup
    data: aws.ec2.SecurityGroup
    endpoints: aws.ec2.SecurityGroup

    def __init__(self, name: str, args: TierSecurityGroupsArgs, opts: pulumi.ResourceOptions | None = None):
        super().__init__("learning:network:TierSecurityGroups", name, {}, opts)

        child_opts = pulumi.ResourceOptions(parent=self)

        def group(tier: str, description: str) -> aws.ec2.SecurityGroup:
            return aws.ec2.SecurityGroup(
                f"{name}-{tier}",
                vpc_id=args.vpc_id,
                name=f"{name}-{tier}",
                description=description,
                tags={"Name": f"{name}-{tier}"},
                opts=child_opts,
            )

        self.alb = group("alb", "Internet-facing load balancers")
        self.app = group("app", "Application workloads")
        self.data = group("data", "Databases and caches")
        self.endpoints = group("endpoints", "Interface VPC endpoints")

        # Every rule here is TCP.
        def ingress(rule_id: str, **rule: Any) -> None:
            aws.vpc.SecurityGroupIngressRule(f"{name}-{rule_id}", ip_protocol="tcp", **rule, opts=child_opts)

        def egress(rule_id: str, **rule: Any) -> None:
            aws.vpc.SecurityGroupEgressRule(f"{name}-{rule_id}", ip_protocol="tcp", **rule, opts=child_opts)

        ingress(
            "alb-in-https",
            security_group_id=self.alb.id,
            cidr_ipv4="0.0.0.0/0",
            from_port=443,
            to_port=443,
            description="HTTPS from the internet",
        )
        egress(
            "alb-out-app",
            security_group_id=self.alb.id,
            referenced_security_group_id=self.app.id,
            from_port=args.app_port,
            to_port=args.app_port,
            description="To application targets",
        )

        ingress(
            "app-in-alb",
            security_group_id=self.app.id,
            referenced_security_group_id=self.alb.id,
            from_port=args.app_port,
            to_port=args.app_port,
            description="From load balancers",
        )
        egress(
            "app-out-https",
            security_group_id=self.app.id,
            cidr_ipv4="0.0.0.0/0",
            from_port=443,
            to_port=443,
            description="HTTPS to AWS APIs and allow-listed domains (filtered by Network Firewall)",
        )

        for port in args.data_ports:
            egress(
                f"app-out-data-{port}",
                security_group_id=self.app.id,
                referenced_security_group_id=self.data.id,
                from_port=port,
                to_port=port,
                description=f"To the data tier on {port}",
            )
            ingress(
                f"data-in-app-{port}",
                security_group_id=self.data.id,
                referenced_security_group_id=self.app.id,
                from_port=port,
                to_port=port,
                description=f"From the app tier on {port}",
            )

        ingress(
            "endpoints-in-app",
            security_group_id=self.endpoints.id,
            referenced_security_group_id=self.app.id,
            from_port=443,
            to_port=443,
            description="HTTPS from the app tier",
        )

        self.register_outputs({})
