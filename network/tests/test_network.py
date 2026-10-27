import json
from dataclasses import replace
from typing import Any

import pulumi
import pytest
from conftest import AZS, all_of, find, registered

from src.address_plan import address_plan
from src.cidr import subnet_cidr
from src.nacls import nacl_rules
from src.network import DnsFirewallSettings, Network, NetworkArgs, NetworkFirewallSettings

ARGS = NetworkArgs(
    account_id="123456789012",
    region="eu-west-1",
    cidr="10.0.0.0/16",
    availability_zones=AZS,
    nat_gateways="perAz",
    app_port=8443,
    data_ports=[5432],
    allowed_domains=["amazonaws.com"],
    network_firewall=NetworkFirewallSettings(enabled=True, managed_rule_groups=["MalwareDomainsStrictOrder"]),
    dns_firewall=DnsFirewallSettings(enabled=True, managed_block_list_ids=[]),
    interface_endpoints=["ssm", "ssmmessages", "sts"],
    log_retention_days=365,
)


def build(name: str, args: NetworkArgs = ARGS) -> None:
    """Creates a Network and waits until every resource in it has been registered."""

    @pulumi.runtime.test
    def run() -> None:
        Network(name, args)

    run()


# ── subnet_cidr


def test_carves_subnets_like_terraform_cidrsubnet() -> None:
    assert subnet_cidr("10.0.0.0/16", 3, 2) == "10.0.64.0/19"
    assert subnet_cidr("10.0.0.0/16", 8, 96) == "10.0.96.0/24"
    assert subnet_cidr("10.0.0.0/16", 12, 1585) == "10.0.99.16/28"


def test_rejects_ranges_that_dont_fit() -> None:
    with pytest.raises(ValueError, match="doesn't fit"):
        subnet_cidr("10.0.0.0/16", 4, 16)
    with pytest.raises(ValueError, match="cannot add"):
        subnet_cidr("10.0.0.0/30", 4, 0)
    with pytest.raises(ValueError, match="host bits"):
        subnet_cidr("10.0.0.1/16", 4, 0)
    with pytest.raises(ValueError, match="invalid IPv4 address"):
        subnet_cidr("10.0.0.256/16", 4, 0)


# ── address_plan


def test_lays_out_four_tiers_without_overlap() -> None:
    plan = address_plan("10.0.0.0/16", 3)
    assert plan.tiers["app"] == ["10.0.0.0/19", "10.0.32.0/19", "10.0.64.0/19"]
    assert plan.tiers["public"] == ["10.0.96.0/24", "10.0.97.0/24", "10.0.98.0/24"]
    assert plan.tiers["firewall"] == ["10.0.99.0/28", "10.0.99.16/28", "10.0.99.32/28"]
    assert plan.tiers["data"] == ["10.0.100.0/22", "10.0.104.0/22", "10.0.108.0/22"]

    def address_range(cidr: str) -> tuple[int, int]:
        ip, bits = cidr.split("/")
        start = 0
        for octet in ip.split("."):
            start = start * 256 + int(octet)
        return start, start + 2 ** (32 - int(bits)) - 1

    ranges = sorted(address_range(c) for cidrs in plan.tiers.values() for c in cidrs)
    for previous, current in zip(ranges, ranges[1:], strict=False):
        assert current[0] > previous[1], "subnets overlap"


def test_rejects_more_than_three_azs() -> None:
    with pytest.raises(ValueError, match="1-3 availability zones"):
        address_plan("10.0.0.0/16", 4)


# ── nacl_rules

PLAN = address_plan("10.0.0.0/16", 3)
NACLS = nacl_rules(PLAN, 8443, [5432])


def test_never_lets_the_internet_reach_the_data_tier() -> None:
    for rule in [*NACLS["data"].ingress, *NACLS["data"].egress]:
        assert rule.cidr_block != "0.0.0.0/0"


def test_only_lets_the_app_tier_reach_the_data_tier_on_the_data_ports() -> None:
    from_app = [r for r in NACLS["data"].ingress if r.cidr_block in PLAN.tiers["app"]]
    assert len(from_app) == 3
    assert all(r.protocol == "tcp" and r.from_port == 5432 and r.to_port == 5432 for r in from_app)


def test_only_exposes_https_and_return_traffic_on_the_public_tier() -> None:
    ports = [f"{r.from_port}-{r.to_port}" for r in NACLS["public"].ingress]
    assert ports == ["443-443", "1024-65535"]


def test_rejects_an_app_port_the_public_tiers_rules_wouldnt_carry() -> None:
    with pytest.raises(ValueError, match="app_port must be between"):
        nacl_rules(PLAN, 80, [5432])


def test_enforces_the_20_rule_limit() -> None:
    with pytest.raises(ValueError, match="limit is 20"):
        nacl_rules(PLAN, 8443, [5432, 3306, 6379, 27017, 9200, 11211, 1433])


# ── Network


@pytest.fixture(scope="module")
def network() -> None:
    build("t")


@pytest.mark.usefixtures("network")
class TestNetwork:
    def test_routes_public_subnets_through_the_firewall_endpoint_in_their_own_az(self) -> None:
        for az in AZS:
            route = registered("aws:ec2/route:Route", f"t-public-{az}-internet")
            assert route["vpcEndpointId"] == f"vpce-fw-{az}"
            assert "gatewayId" not in route

    def test_sends_return_traffic_from_the_igw_back_through_the_same_azs_firewall(self) -> None:
        edge = registered("aws:ec2/routeTableAssociation:RouteTableAssociation", "t-igw-edge")
        assert edge["gatewayId"] == "t_id"
        back = registered("aws:ec2/route:Route", "t-igw-edge-eu-west-1b")
        assert back["destinationCidrBlock"] == "10.0.97.0/24"
        assert back["vpcEndpointId"] == "vpce-fw-eu-west-1b"

    def test_sends_each_app_subnets_internet_traffic_to_the_nat_gateway_in_its_own_az(self) -> None:
        for az in AZS:
            nat = registered("aws:ec2/natGateway:NatGateway", f"t-{az}")
            assert nat["subnetId"] == f"t-public-{az}_id"
            route = registered("aws:ec2/route:Route", f"t-app-{az}-egress")
            assert route["natGatewayId"] == f"t-{az}_id"

    def test_shares_one_nat_gateway_across_azs_when_nat_gateways_is_single(self) -> None:
        build("onenat", replace(ARGS, nat_gateways="single"))
        route = registered("aws:ec2/route:Route", "onenat-app-eu-west-1c-egress")
        assert route["natGatewayId"] == "onenat-eu-west-1a_id"
        nats = [r for r in all_of("aws:ec2/natGateway:NatGateway") if r.name.startswith("onenat-")]
        assert len(nats) == 1

    def test_gives_the_data_tier_no_route_out_of_the_vpc(self) -> None:
        registered("aws:ec2/routeTable:RouteTable", "t-data")
        data_routes = [r for r in all_of("aws:ec2/route:Route") if r.inputs.get("routeTableId") == "t-data_id"]
        assert data_routes == []

    def test_denies_by_default_in_the_firewall_policy(self) -> None:
        fp = registered("aws:networkfirewall/firewallPolicy:FirewallPolicy", "t-nfw")["firewallPolicy"]
        assert fp["statefulEngineOptions"]["ruleOrder"] == "STRICT_ORDER"
        assert fp["statefulDefaultActions"] == ["aws:drop_established", "aws:alert_established"]
        assert (
            fp["statefulRuleGroupReferences"][0]["resourceArn"]
            == "arn:aws:network-firewall:eu-west-1:aws-managed:stateful-rulegroup/MalwareDomainsStrictOrder"
        )

    def test_allow_lists_domains_and_their_subdomains(self) -> None:
        group = registered("aws:networkfirewall/ruleGroup:RuleGroup", "t-nfw-allow-domains")
        assert group["ruleGroup"]["rulesSource"]["rulesSourceList"]["targets"] == ["amazonaws.com", ".amazonaws.com"]

    def test_runs_dns_firewall_as_a_walled_garden_that_fails_closed(self) -> None:
        allow = registered("aws:route53/resolverFirewallRule:ResolverFirewallRule", "t-dns-allow")
        block = registered("aws:route53/resolverFirewallRule:ResolverFirewallRule", "t-dns-block-rest")
        assert allow["priority"] < block["priority"]
        assert block["action"] == "BLOCK"
        config = registered("aws:route53/resolverFirewallConfig:ResolverFirewallConfig", "t-dns")
        assert config["firewallFailOpen"] == "DISABLED"

    def test_locks_down_the_default_security_group_and_network_acl(self) -> None:
        sg = registered("aws:ec2/defaultSecurityGroup:DefaultSecurityGroup", "t")
        assert sg["ingress"] == []
        assert sg["egress"] == []
        acl = registered("aws:ec2/defaultNetworkAcl:DefaultNetworkAcl", "t")
        assert "ingress" not in acl
        assert "egress" not in acl

    def test_logs_all_traffic_encrypted_with_a_rotating_customer_managed_key(self) -> None:
        flow = registered("aws:ec2/flowLog:FlowLog", "t")
        assert flow["trafficType"] == "ALL"
        assert flow["logFormat"].startswith("${version} ${account-id} ")
        group = registered("aws:cloudwatch/logGroup:LogGroup", "t-flow")
        assert group["kmsKeyId"] == "arn:aws:mock:::t-logs"
        key = registered("aws:kms/key:Key", "t-logs")
        assert key["enableKeyRotation"] is True

    def test_restricts_endpoints_to_this_accounts_principals_where_policies_are_supported(self) -> None:
        sts = registered("aws:ec2/vpcEndpoint:VpcEndpoint", "t-vpce-sts")
        doc: dict[str, Any] = json.loads(sts["policy"])
        assert doc["Statement"][0]["Condition"] == {"StringEquals": {"aws:PrincipalAccount": "123456789012"}}
        ssmmessages = registered("aws:ec2/vpcEndpoint:VpcEndpoint", "t-vpce-ssmmessages")
        assert "policy" not in ssmmessages

    def test_chains_security_groups_by_reference_and_gives_the_data_tier_no_egress(self) -> None:
        data_in = registered("aws:vpc/securityGroupIngressRule:SecurityGroupIngressRule", "t-sg-data-in-app-5432")
        assert data_in["referencedSecurityGroupId"] == "t-sg-app_id"
        data_egress = [
            r
            for r in all_of("aws:vpc/securityGroupEgressRule:SecurityGroupEgressRule")
            if r.inputs.get("securityGroupId") == "t-sg-data_id"
        ]
        assert data_egress == []

    def test_routes_straight_to_the_igw_when_the_firewall_is_off(self) -> None:
        build(
            "nofw",
            replace(
                ARGS,
                network_firewall=NetworkFirewallSettings(enabled=False, managed_rule_groups=[]),
                dns_firewall=DnsFirewallSettings(enabled=False, managed_block_list_ids=[]),
            ),
        )
        route = registered("aws:ec2/route:Route", "nofw-public-eu-west-1a-internet")
        assert route["gatewayId"] == "nofw_id"
        assert find("aws:ec2/routeTableAssociation:RouteTableAssociation", "nofw-igw-edge") is None
