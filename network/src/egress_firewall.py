from collections.abc import Sequence
from dataclasses import dataclass

import pulumi
import pulumi_aws as aws

from .logging import LogEncryption


@dataclass(frozen=True)
class FirewallSubnet:
    az: str
    subnet: aws.ec2.Subnet


@dataclass(frozen=True)
class EgressFirewallArgs:
    vpc_id: pulumi.Input[str]
    region: str
    # One firewall subnet per AZ, in AZ order.
    subnets: list[FirewallSubnet]
    # Domains workloads may reach over HTTPS/HTTP, e.g. "amazonaws.com". Each
    # allows the domain and all its subdomains. Everything else is dropped.
    allowed_domains: list[str]
    # AWS managed stateful rule groups (strict-order variants), checked before the allow-list.
    managed_rule_groups: list[str]
    logs: LogEncryption


class EgressFirewall(pulumi.ComponentResource):
    """
    AWS Network Firewall inspecting all traffic between the public subnets and
    the Internet Gateway. Policy, in strict order:

      1. AWS managed threat intelligence (malware, botnet C2, exploits, ...) drops known-bad traffic
      2. a domain allow-list (TLS SNI / HTTP Host) passes approved destinations
      3. everything else on an established connection is dropped and alerted
    """

    firewall: aws.networkfirewall.Firewall

    def __init__(self, name: str, args: EgressFirewallArgs, opts: pulumi.ResourceOptions | None = None):
        super().__init__("learning:network:EgressFirewall", name, {}, opts)

        child_opts = pulumi.ResourceOptions(parent=self)

        if not args.allowed_domains:
            raise ValueError("EgressFirewall needs at least one allowed domain; with none, all egress is blocked")

        # "example.com" matches only that host; ".example.com" matches its subdomains.
        targets = [entry for d in args.allowed_domains for entry in (d.lstrip("."), f".{d.lstrip('.')}")]

        allow_list = aws.networkfirewall.RuleGroup(
            f"{name}-allow-domains",
            name=f"{name}-allow-domains",
            type="STATEFUL",
            capacity=100,
            rule_group={
                "rules_source": {
                    "rules_source_list": {
                        "generated_rules_type": "ALLOWLIST",
                        "target_types": ["TLS_SNI", "HTTP_HOST"],
                        "targets": targets,
                    },
                },
                "stateful_rule_options": {"rule_order": "STRICT_ORDER"},
            },
            opts=child_opts,
        )

        managed_references: list[aws.networkfirewall.FirewallPolicyFirewallPolicyStatefulRuleGroupReferenceArgsDict] = [
            {
                "priority": 10 + i * 10,
                "resource_arn": f"arn:aws:network-firewall:{args.region}:aws-managed:stateful-rulegroup/{group}",
            }
            for i, group in enumerate(args.managed_rule_groups)
        ]

        policy = aws.networkfirewall.FirewallPolicy(
            name,
            name=name,
            firewall_policy={
                # Stateless engine passes everything to the stateful engine, where
                # the real decisions are made.
                "stateless_default_actions": ["aws:forward_to_sfe"],
                "stateless_fragment_default_actions": ["aws:forward_to_sfe"],
                "stateful_engine_options": {
                    "rule_order": "STRICT_ORDER",
                    # Drop a flow if the engine loses track of it mid-stream, rather than letting it through.
                    "stream_exception_policy": "REJECT",
                },
                # Default deny: anything no rule passes is dropped once the TCP
                # handshake completes (so the SNI / Host header can be inspected first).
                "stateful_default_actions": ["aws:drop_established", "aws:alert_established"],
                "stateful_rule_group_references": [
                    *managed_references,
                    {"priority": 10 + len(managed_references) * 10, "resource_arn": allow_list.arn},
                ],
            },
            opts=child_opts,
        )

        self.firewall = aws.networkfirewall.Firewall(
            name,
            name=name,
            vpc_id=args.vpc_id,
            firewall_policy_arn=policy.arn,
            subnet_mappings=[{"subnet_id": s.subnet.id} for s in args.subnets],
            subnet_change_protection=True,
            firewall_policy_change_protection=True,
            # Set to True for a real environment. Off here so `pulumi destroy` works.
            delete_protection=False,
            opts=child_opts,
        )

        alert_logs = args.logs.log_group(f"{name}-alert", "/learning/network-firewall/alert")
        flow_logs = args.logs.log_group(f"{name}-flow", "/learning/network-firewall/flow")

        aws.networkfirewall.LoggingConfiguration(
            name,
            firewall_arn=self.firewall.arn,
            logging_configuration={
                "log_destination_configs": [
                    {
                        "log_type": "ALERT",
                        "log_destination_type": "CloudWatchLogs",
                        "log_destination": {"logGroup": alert_logs.name},
                    },
                    {
                        "log_type": "FLOW",
                        "log_destination_type": "CloudWatchLogs",
                        "log_destination": {"logGroup": flow_logs.name},
                    },
                ],
            },
            opts=child_opts,
        )

        self.register_outputs({"firewallArn": self.firewall.arn})

    def endpoint_id(self, az: str) -> pulumi.Output[str]:
        """The firewall endpoint in one AZ: the next hop for routes that send traffic through inspection."""

        def find(statuses: Sequence[aws.networkfirewall.outputs.FirewallFirewallStatus]) -> str:
            sync_states = (statuses[0].sync_states or []) if statuses else []
            state = next((s for s in sync_states if s.availability_zone == az), None)
            endpoint = state.attachments[0].endpoint_id if state and state.attachments else None
            if not endpoint:
                raise ValueError(f"Network Firewall has no endpoint in {az}")
            return endpoint

        return self.firewall.firewall_statuses.apply(find)
