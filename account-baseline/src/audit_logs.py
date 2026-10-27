from dataclasses import dataclass
from typing import Literal

import pulumi
import pulumi_aws as aws

from .policy import Statement, policy_document


@dataclass(frozen=True)
class AuditLogsArgs:
    account_id: str
    region: str
    # Days each log object is locked against deletion and overwrite.
    retention_days: int
    object_lock_mode: Literal["GOVERNANCE", "COMPLIANCE"]


class AuditLogs(pulumi.ComponentResource):
    """
    The account's audit trail (SEC04): a multi-region CloudTrail writing to a
    write-once S3 bucket, encrypted with a customer-managed KMS key. AWS Config
    delivers to the same bucket under its own prefix.

    The key and bucket are `protect`ed: they're meant to outlive this stack,
    and Object Lock stops the logs being deleted for the retention period anyway.
    """

    key: aws.kms.Key
    bucket: aws.s3.Bucket
    trail: aws.cloudtrail.Trail

    def __init__(self, name: str, args: AuditLogsArgs, opts: pulumi.ResourceOptions | None = None):
        super().__init__("learning:baseline:AuditLogs", name, {}, opts)

        child_opts = pulumi.ResourceOptions(parent=self)
        keep = pulumi.ResourceOptions(parent=self, protect=True)
        trail_name = f"{name}-trail"
        trail_arn = f"arn:aws:cloudtrail:{args.region}:{args.account_id}:trail/{trail_name}"

        self.key = aws.kms.Key(
            name,
            description="Encrypts CloudTrail and AWS Config logs",
            enable_key_rotation=True,
            deletion_window_in_days=30,
            policy=policy_document(
                [
                    Statement(
                        sid="AccountAdministration",
                        principals={"type": "AWS", "identifiers": [f"arn:aws:iam::{args.account_id}:root"]},
                        actions=["kms:*"],
                        resources=["*"],
                    ),
                    # CloudTrail may encrypt logs only for this account's trail.
                    Statement(
                        sid="CloudTrailEncrypt",
                        principals={"type": "Service", "identifiers": ["cloudtrail.amazonaws.com"]},
                        actions=["kms:GenerateDataKey*"],
                        resources=["*"],
                        conditions={
                            "StringEquals": {"aws:SourceArn": trail_arn},
                            "StringLike": {
                                "kms:EncryptionContext:aws:cloudtrail:arn": (
                                    f"arn:aws:cloudtrail:*:{args.account_id}:trail/*"
                                ),
                            },
                        },
                    ),
                    Statement(
                        sid="CloudTrailDescribe",
                        principals={"type": "Service", "identifiers": ["cloudtrail.amazonaws.com"]},
                        actions=["kms:DescribeKey"],
                        resources=["*"],
                        conditions={"StringEquals": {"aws:SourceArn": trail_arn}},
                    ),
                ]
            ),
            opts=keep,
        )
        aws.kms.Alias(name, name=f"alias/{name}", target_key_id=self.key.key_id, opts=child_opts)

        # Object Lock can only be switched on when a bucket is created.
        self.bucket = aws.s3.Bucket(
            name,
            bucket=f"{name}-{args.account_id}-{args.region}",
            object_lock_enabled=True,
            force_destroy=False,
            opts=keep,
        )
        bucket_opts = pulumi.ResourceOptions(parent=self, depends_on=[self.bucket])

        public_access_block = aws.s3.BucketPublicAccessBlock(
            name,
            bucket=self.bucket.id,
            block_public_acls=True,
            block_public_policy=True,
            ignore_public_acls=True,
            restrict_public_buckets=True,
            opts=bucket_opts,
        )
        aws.s3.BucketOwnershipControls(
            name,
            bucket=self.bucket.id,
            rule={"object_ownership": "BucketOwnerEnforced"},
            opts=bucket_opts,
        )
        aws.s3.BucketVersioning(
            name,
            bucket=self.bucket.id,
            versioning_configuration={"status": "Enabled"},
            opts=bucket_opts,
        )
        aws.s3.BucketServerSideEncryptionConfiguration(
            name,
            bucket=self.bucket.id,
            rules=[
                {
                    "apply_server_side_encryption_by_default": {
                        "sse_algorithm": "aws:kms",
                        "kms_master_key_id": self.key.arn,
                    },
                    "bucket_key_enabled": True,
                }
            ],
            opts=bucket_opts,
        )
        aws.s3.BucketObjectLockConfiguration(
            name,
            bucket=self.bucket.id,
            object_lock_enabled="Enabled",
            rule={"default_retention": {"mode": args.object_lock_mode, "days": args.retention_days}},
            opts=bucket_opts,
        )
        aws.s3.BucketLifecycleConfiguration(
            name,
            bucket=self.bucket.id,
            rules=[
                {
                    # Logs are deleted a month after their lock expires, to keep storage costs bounded.
                    "id": "expire-after-retention",
                    "status": "Enabled",
                    "filter": {},
                    "expiration": {"days": args.retention_days + 30},
                    "noncurrent_version_expiration": {"noncurrent_days": 30},
                }
            ],
            opts=bucket_opts,
        )

        bucket_policy = aws.s3.BucketPolicy(
            name,
            bucket=self.bucket.id,
            policy=policy_document(
                [
                    Statement(
                        sid="DenyInsecureTransport",
                        effect="Deny",
                        principals={"type": "AWS", "identifiers": ["*"]},
                        actions=["s3:*"],
                        resources=[self.bucket.arn, pulumi.Output.concat(self.bucket.arn, "/*")],
                        conditions={"Bool": {"aws:SecureTransport": "false"}},
                    ),
                    Statement(
                        sid="CloudTrailAclCheck",
                        principals={"type": "Service", "identifiers": ["cloudtrail.amazonaws.com"]},
                        actions=["s3:GetBucketAcl"],
                        resources=[self.bucket.arn],
                        conditions={"StringEquals": {"aws:SourceArn": trail_arn}},
                    ),
                    Statement(
                        sid="CloudTrailWrite",
                        principals={"type": "Service", "identifiers": ["cloudtrail.amazonaws.com"]},
                        actions=["s3:PutObject"],
                        resources=[pulumi.Output.concat(self.bucket.arn, f"/cloudtrail/AWSLogs/{args.account_id}/*")],
                        conditions={
                            "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control", "aws:SourceArn": trail_arn}
                        },
                    ),
                ]
            ),
            opts=pulumi.ResourceOptions(parent=self, depends_on=[public_access_block]),
        )

        self.trail = aws.cloudtrail.Trail(
            name,
            name=trail_name,
            s3_bucket_name=self.bucket.id,
            s3_key_prefix="cloudtrail",
            # Every region, plus global services such as IAM and STS.
            is_multi_region_trail=True,
            include_global_service_events=True,
            # Signed digest files prove the logs haven't been altered.
            enable_log_file_validation=True,
            kms_key_id=self.key.arn,
            enable_logging=True,
            opts=pulumi.ResourceOptions(parent=self, depends_on=[bucket_policy]),
        )

        self.register_outputs({"bucket": self.bucket.id, "trailArn": self.trail.arn})
