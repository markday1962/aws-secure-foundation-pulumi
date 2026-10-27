from typing import Any

import pulumi

AZS = ["eu-west-1a", "eu-west-1b", "eu-west-1c"]


class Mocks(pulumi.runtime.Mocks):
    """Records every resource the program registers, and echoes its inputs back as its state."""

    def __init__(self) -> None:
        self.created: list[pulumi.runtime.MockResourceArgs] = []

    def new_resource(self, args: pulumi.runtime.MockResourceArgs) -> tuple[str, dict[str, Any]]:
        self.created.append(args)
        state: dict[str, Any] = {**args.inputs, "arn": f"arn:aws:mock:::{args.name}"}
        if args.typ == "aws:networkfirewall/firewall:Firewall":
            state["firewallStatuses"] = [
                {
                    "syncStates": [
                        {"availabilityZone": az, "attachments": [{"endpointId": f"vpce-fw-{az}", "subnetId": "x"}]}
                        for az in AZS
                    ]
                }
            ]
        if args.typ == "aws:ec2/vpc:Vpc":
            state["defaultNetworkAclId"] = "acl-default"
        return f"{args.name}_id", state

    def call(self, args: pulumi.runtime.MockCallArgs) -> tuple[dict[str, Any], None]:
        return args.args, None


MOCKS = Mocks()
pulumi.runtime.set_mocks(MOCKS, project="highly-secure-foundation-network", stack="test", preview=False)


def all_of(typ: str) -> list[pulumi.runtime.MockResourceArgs]:
    return [r for r in MOCKS.created if r.typ == typ]


def find(typ: str, name: str) -> dict[str, Any] | None:
    return next((r.inputs for r in all_of(typ) if r.name == name), None)


def registered(typ: str, name: str) -> dict[str, Any]:
    """The inputs the resource with this type and name was registered with."""
    inputs = find(typ, name)
    if inputs is None:
        seen = [r.name for r in all_of(typ)]
        raise AssertionError(f'{typ} "{name}" was never registered (saw: {", ".join(seen) or "none"})')
    return inputs
