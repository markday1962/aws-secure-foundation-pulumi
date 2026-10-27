from dataclasses import dataclass

import pulumi
import pulumi_aws as aws

from .policy import Statement, policy_document

# Services whose interface endpoints accept an endpoint policy.
SUPPORTS_POLICY = {"ssm", "sts", "kms", "logs", "secretsmanager", "ecr.api", "ecr.dkr", "sqs", "sns", "monitoring"}


@dataclass(frozen=True)
class VpcEndpointsArgs:
    vpc_id: pulumi.Input[str]
    region: str
    account_id: str
    # Route tables that get the free S3 and DynamoDB gateway endpoints.
    gateway_route_table_ids: list[pulumi.Input[str]]
    # Interface endpoints: one ENI per subnet. Empty to skip them.
    interface_services: list[str]
    interface_subnet_ids: list[pulumi.Input[str]]
    security_group_id: pulumi.Input[str]


class VpcEndpoints(pulumi.ComponentResource):
    """
    Private connectivity to AWS APIs, so that traffic never crosses the internet
    (or the NAT). Endpoint policies only allow principals from this account,
    which stops stolen credentials from another account using the endpoint to
    exfiltrate data (a "data perimeter").
    """

    def __init__(self, name: str, args: VpcEndpointsArgs, opts: pulumi.ResourceOptions | None = None):
        super().__init__("learning:network:VpcEndpoints", name, {}, opts)

        child_opts = pulumi.ResourceOptions(parent=self)
        this_account_only = Statement(
            sid="ThisAccountPrincipalsOnly",
            principals={"type": "AWS", "identifiers": ["*"]},
            actions=["*"],
            resources=["*"],
            conditions={"StringEquals": {"aws:PrincipalAccount": args.account_id}},
        )

        aws.ec2.VpcEndpoint(
            f"{name}-s3",
            vpc_id=args.vpc_id,
            service_name=f"com.amazonaws.{args.region}.s3",
            vpc_endpoint_type="Gateway",
            route_table_ids=args.gateway_route_table_ids,
            policy=policy_document(
                [
                    this_account_only,
                    # Amazon Linux package repositories are AWS-owned S3 buckets read
                    # anonymously, so they need their own exception.
                    Statement(
                        sid="AmazonLinuxRepositories",
                        principals={"type": "AWS", "identifiers": ["*"]},
                        actions=["s3:GetObject"],
                        resources=[
                            f"arn:aws:s3:::al2023-repos-{args.region}-*/*",
                            f"arn:aws:s3:::amazonlinux-2-repos-{args.region}/*",
                        ],
                    ),
                ]
            ),
            tags={"Name": f"{name}-s3"},
            opts=child_opts,
        )

        aws.ec2.VpcEndpoint(
            f"{name}-dynamodb",
            vpc_id=args.vpc_id,
            service_name=f"com.amazonaws.{args.region}.dynamodb",
            vpc_endpoint_type="Gateway",
            route_table_ids=args.gateway_route_table_ids,
            policy=policy_document([this_account_only]),
            tags={"Name": f"{name}-dynamodb"},
            opts=child_opts,
        )

        for service in args.interface_services:
            aws.ec2.VpcEndpoint(
                f"{name}-{service}",
                vpc_id=args.vpc_id,
                service_name=f"com.amazonaws.{args.region}.{service}",
                vpc_endpoint_type="Interface",
                subnet_ids=args.interface_subnet_ids,
                security_group_ids=[args.security_group_id],
                # Resolve the service's normal hostname to the private endpoint.
                private_dns_enabled=True,
                policy=policy_document([this_account_only]) if service in SUPPORTS_POLICY else None,
                tags={"Name": f"{name}-{service}"},
                opts=child_opts,
            )

        self.register_outputs({})
