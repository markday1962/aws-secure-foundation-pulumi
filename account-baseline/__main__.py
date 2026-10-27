import re

import pulumi

from src.audit_logs import AuditLogs, AuditLogsArgs
from src.detection import Detection, DetectionArgs
from src.hardening import Hardening, HardeningArgs

config = pulumi.Config()
aws_config = pulumi.Config("aws")

# The account this stack is pinned to. The provider refuses to run against
# any other, and policies use it to scope access to this account only.
allowed_account_ids = aws_config.require_object("allowedAccountIds")
account_id = str(allowed_account_ids[0]) if allowed_account_ids else ""
if not re.fullmatch(r"\d{12}", account_id):
    raise ValueError("aws:allowedAccountIds must hold the 12-digit account ID this stack deploys to")
region = aws_config.require("region")

object_lock_mode = config.get("objectLockMode", default="GOVERNANCE")
if object_lock_mode not in ("GOVERNANCE", "COMPLIANCE"):
    raise ValueError(f'objectLockMode must be GOVERNANCE or COMPLIANCE, got "{object_lock_mode}"')

audit = AuditLogs(
    "learning-audit",
    AuditLogsArgs(
        account_id=account_id,
        region=region,
        retention_days=config.get_int("logRetentionDays", default=365),
        object_lock_mode=object_lock_mode,
    ),
)

Detection(
    "learning-detection",
    DetectionArgs(account_id=account_id, region=region, log_bucket=audit.bucket, log_key=audit.key),
)

Hardening("learning-hardening", HardeningArgs(imds_hop_limit=config.get_int("imdsHopLimit", default=1)))

pulumi.export("auditBucket", audit.bucket.id)
pulumi.export("auditKeyArn", audit.key.arn)
pulumi.export("trailArn", audit.trail.arn)
