from dataclasses import dataclass

import pulumi
import pulumi_aws as aws

from .policy import Statement, policy_document


@dataclass(frozen=True)
class LogEncryptionArgs:
    account_id: str
    region: str
    # Days CloudWatch keeps each log group.
    retention_days: int


class LogEncryption(pulumi.ComponentResource):
    """
    A customer-managed KMS key for this VPC's logs (flow logs, firewall logs,
    DNS query logs), and a factory for log groups encrypted with it.
    """

    key: aws.kms.Key

    def __init__(self, name: str, args: LogEncryptionArgs, opts: pulumi.ResourceOptions | None = None):
        super().__init__("learning:network:LogEncryption", name, {}, opts)

        self._retention_days = args.retention_days
        account_root = f"arn:aws:iam::{args.account_id}:root"

        self.key = aws.kms.Key(
            name,
            description="Encrypts VPC flow, firewall and DNS query logs",
            enable_key_rotation=True,
            deletion_window_in_days=30,
            policy=policy_document(
                [
                    # Lets IAM policies in this account govern the key. Without it the
                    # key can become unmanageable.
                    Statement(
                        sid="AccountAdministration",
                        principals={"type": "AWS", "identifiers": [account_root]},
                        actions=["kms:*"],
                        resources=["*"],
                    ),
                    # CloudWatch Logs encrypts log groups in this account and region only.
                    Statement(
                        sid="CloudWatchLogsUse",
                        principals={"type": "Service", "identifiers": [f"logs.{args.region}.amazonaws.com"]},
                        actions=[
                            "kms:Encrypt*",
                            "kms:Decrypt*",
                            "kms:ReEncrypt*",
                            "kms:GenerateDataKey*",
                            "kms:Describe*",
                        ],
                        resources=["*"],
                        conditions={
                            "ArnLike": {
                                "kms:EncryptionContext:aws:logs:arn": (
                                    f"arn:aws:logs:{args.region}:{args.account_id}:log-group:*"
                                ),
                            },
                        },
                    ),
                ]
            ),
            opts=pulumi.ResourceOptions(parent=self),
        )

        aws.kms.Alias(
            name, name=f"alias/{name}", target_key_id=self.key.key_id, opts=pulumi.ResourceOptions(parent=self)
        )

        self.register_outputs({"keyArn": self.key.arn})

    def log_group(self, name: str, log_group_name: str) -> aws.cloudwatch.LogGroup:
        """A KMS-encrypted log group with this component's retention."""
        return aws.cloudwatch.LogGroup(
            name,
            name=log_group_name,
            retention_in_days=self._retention_days,
            kms_key_id=self.key.arn,
            opts=pulumi.ResourceOptions(parent=self),
        )
