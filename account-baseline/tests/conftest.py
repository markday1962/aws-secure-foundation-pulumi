from typing import Any

import pulumi


class Mocks(pulumi.runtime.Mocks):
    """Records every resource the program registers, and echoes its inputs back as its state."""

    def __init__(self) -> None:
        self.created: list[pulumi.runtime.MockResourceArgs] = []

    def new_resource(self, args: pulumi.runtime.MockResourceArgs) -> tuple[str, dict[str, Any]]:
        self.created.append(args)
        return f"{args.name}_id", {**args.inputs, "arn": f"arn:aws:mock:::{args.name}"}

    def call(self, args: pulumi.runtime.MockCallArgs) -> tuple[dict[str, Any], None]:
        return args.args, None


MOCKS = Mocks()
pulumi.runtime.set_mocks(MOCKS, project="highly-secure-foundation-account-baseline", stack="test", preview=False)


def registered(typ: str, name: str) -> dict[str, Any]:
    """The inputs the resource with this type and name was registered with."""
    for r in MOCKS.created:
        if r.typ == typ and r.name == name:
            return r.inputs
    seen = [r.name for r in MOCKS.created if r.typ == typ]
    raise AssertionError(f'{typ} "{name}" was never registered (saw: {", ".join(seen) or "none"})')
