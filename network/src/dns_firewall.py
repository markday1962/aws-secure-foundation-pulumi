from dataclasses import dataclass

import pulumi
import pulumi_aws as aws

from .logging import LogEncryption


@dataclass(frozen=True)
class DnsFirewallArgs:
    vpc_id: pulumi.Input[str]
    # Domains the VPC may resolve. Each allows the domain and all its subdomains.
    allowed_domains: list[str]
    # IDs of AWS managed domain lists to block first (they vary by region):
    #   aws route53resolver list-firewall-domain-lists --region eu-west-1 \
    #     --query "FirewallDomainLists[?ManagedOwnerName=='Route 53 Resolver DNS Firewall']"
    managed_block_list_ids: list[str]
    logs: LogEncryption


class DnsFirewall(pulumi.ComponentResource):
    """
    Route 53 Resolver DNS Firewall as a "walled garden": block known-bad domains,
    allow only the approved list, and answer NXDOMAIN for everything else. Also
    logs every DNS query the VPC makes.
    """

    def __init__(self, name: str, args: DnsFirewallArgs, opts: pulumi.ResourceOptions | None = None):
        super().__init__("learning:network:DnsFirewall", name, {}, opts)

        child_opts = pulumi.ResourceOptions(parent=self)

        allowed = aws.route53.ResolverFirewallDomainList(
            f"{name}-allowed",
            name=f"{name}-allowed",
            domains=[
                *(entry for d in args.allowed_domains for entry in (d, f"*.{d}")),
                # VPC-internal names (EC2 hostnames, private hosted zones under .internal).
                "*.internal",
            ],
            opts=child_opts,
        )

        everything = aws.route53.ResolverFirewallDomainList(
            f"{name}-everything", name=f"{name}-everything", domains=["*"], opts=child_opts
        )

        rule_group = aws.route53.ResolverFirewallRuleGroup(name, name=name, opts=child_opts)

        for i, list_id in enumerate(args.managed_block_list_ids):
            aws.route53.ResolverFirewallRule(
                f"{name}-block-managed-{i}",
                name=f"block-managed-{i}",
                firewall_rule_group_id=rule_group.id,
                firewall_domain_list_id=list_id,
                priority=100 + i,
                action="BLOCK",
                block_response="NXDOMAIN",
                opts=child_opts,
            )

        aws.route53.ResolverFirewallRule(
            f"{name}-allow",
            name="allow-approved",
            firewall_rule_group_id=rule_group.id,
            firewall_domain_list_id=allowed.id,
            priority=200,
            action="ALLOW",
            opts=child_opts,
        )

        aws.route53.ResolverFirewallRule(
            f"{name}-block-rest",
            name="block-everything-else",
            firewall_rule_group_id=rule_group.id,
            firewall_domain_list_id=everything.id,
            priority=300,
            action="BLOCK",
            block_response="NXDOMAIN",
            opts=child_opts,
        )

        aws.route53.ResolverFirewallRuleGroupAssociation(
            name,
            name=name,
            firewall_rule_group_id=rule_group.id,
            vpc_id=args.vpc_id,
            priority=101,
            opts=child_opts,
        )

        # Fail closed: if DNS Firewall is unavailable, queries are blocked rather than allowed.
        aws.route53.ResolverFirewallConfig(
            name, resource_id=args.vpc_id, firewall_fail_open="DISABLED", opts=child_opts
        )

        query_logs = args.logs.log_group(f"{name}-queries", "/learning/dns/queries")
        query_log_config = aws.route53.ResolverQueryLogConfig(
            name, name=name, destination_arn=query_logs.arn, opts=child_opts
        )
        aws.route53.ResolverQueryLogConfigAssociation(
            name,
            resolver_query_log_config_id=query_log_config.id,
            resource_id=args.vpc_id,
            opts=child_opts,
        )

        self.register_outputs({})
