from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal, TypedDict

import pulumi


class Principals(TypedDict):
    type: str
    identifiers: Sequence[pulumi.Input[str]]


@dataclass(frozen=True)
class Statement:
    actions: Sequence[str]
    sid: str | None = None
    effect: Literal["Allow", "Deny"] = "Allow"
    # Omit for trust policies, which take a principal instead.
    resources: Sequence[pulumi.Input[str]] | None = None
    principals: Principals | None = None
    conditions: Mapping[str, Mapping[str, pulumi.Input[str | Sequence[str]]]] | None = None


def policy_document(statements: Sequence[Statement]) -> pulumi.Output[str]:
    """Renders an IAM, KMS or endpoint policy document as JSON, resolving any Outputs in it."""

    def render(s: Statement) -> dict[str, Any]:
        statement: dict[str, Any] = {}
        if s.sid:
            statement["Sid"] = s.sid
        statement["Effect"] = s.effect
        if s.principals:
            statement["Principal"] = {s.principals["type"]: s.principals["identifiers"]}
        statement["Action"] = s.actions
        if s.resources is not None:
            statement["Resource"] = s.resources
        if s.conditions:
            statement["Condition"] = s.conditions
        return statement

    # Compact separators, as AWS shows policies and as JSON.stringify writes them.
    document = {"Version": "2012-10-17", "Statement": [render(s) for s in statements]}
    return pulumi.Output.json_dumps(document, separators=(",", ":"))
