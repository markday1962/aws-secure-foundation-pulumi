import json

import pulumi
import pytest
from conftest import registered

from src.audit_logs import AuditLogs, AuditLogsArgs
from src.detection import Detection, DetectionArgs
from src.hardening import Hardening, HardeningArgs

ACCOUNT = "123456789012"


@pytest.fixture(scope="module", autouse=True)
def baseline() -> None:
    # pulumi.runtime.test waits until every resource has been registered.
    @pulumi.runtime.test
    def build() -> None:
        audit = AuditLogs(
            "audit",
            AuditLogsArgs(account_id=ACCOUNT, region="eu-west-1", retention_days=365, object_lock_mode="GOVERNANCE"),
        )
        Detection(
            "detect",
            DetectionArgs(account_id=ACCOUNT, region="eu-west-1", log_bucket=audit.bucket, log_key=audit.key),
        )
        Hardening("harden", HardeningArgs(imds_hop_limit=1))

    build()


def test_keeps_a_tamper_evident_multi_region_cloudtrail() -> None:
    trail = registered("aws:cloudtrail/trail:Trail", "audit")
    assert trail["isMultiRegionTrail"] is True
    assert trail["includeGlobalServiceEvents"] is True
    assert trail["enableLogFileValidation"] is True
    assert trail["kmsKeyId"] == "arn:aws:mock:::audit"


def test_locks_audit_logs_against_deletion_for_the_retention_period() -> None:
    bucket = registered("aws:s3/bucket:Bucket", "audit")
    assert bucket["objectLockEnabled"] is True
    lock = registered("aws:s3/bucketObjectLockConfiguration:BucketObjectLockConfiguration", "audit")
    assert lock["rule"]["defaultRetention"] == {"mode": "GOVERNANCE", "days": 365}


def test_lets_only_this_accounts_trail_write_to_the_bucket() -> None:
    policy = registered("aws:s3/bucketPolicy:BucketPolicy", "audit")
    statements = {s["Sid"]: s for s in json.loads(policy["policy"])["Statement"]}
    write = statements["CloudTrailWrite"]
    assert (
        write["Condition"]["StringEquals"]["aws:SourceArn"]
        == f"arn:aws:cloudtrail:eu-west-1:{ACCOUNT}:trail/audit-trail"
    )
    assert statements["DenyInsecureTransport"]["Effect"] == "Deny"


def test_enables_guardduty_runtime_monitoring_with_managed_agents() -> None:
    runtime = registered("aws:guardduty/detectorFeature:DetectorFeature", "detect-runtime_monitoring")
    assert runtime["status"] == "ENABLED"
    assert len(runtime["additionalConfigurations"]) == 3
    registered("aws:guardduty/detectorFeature:DetectorFeature", "detect-s3_data_events")


def test_subscribes_security_hub_to_fsbp_and_cis_5() -> None:
    cis = registered("aws:securityhub/standardsSubscription:StandardsSubscription", "detect-cis-5-0-0")
    assert cis["standardsArn"] == "arn:aws:securityhub:eu-west-1::standards/cis-aws-foundations-benchmark/v/5.0.0"
    registered("aws:securityhub/standardsSubscription:StandardsSubscription", "detect-fsbp")


def test_records_every_resource_type_in_aws_config() -> None:
    recorder = registered("aws:cfg/recorder:Recorder", "detect")
    assert recorder["recordingGroup"] == {"allSupported": True, "includeGlobalResourceTypes": True}


def test_hardens_account_defaults() -> None:
    imds = registered("aws:ec2/instanceMetadataDefaults:InstanceMetadataDefaults", "harden")
    assert imds["httpTokens"] == "required"
    assert imds["httpPutResponseHopLimit"] == 1
    ebs = registered("aws:ebs/encryptionByDefault:EncryptionByDefault", "harden")
    assert ebs["enabled"] is True
    s3 = registered("aws:s3/accountPublicAccessBlock:AccountPublicAccessBlock", "harden")
    assert s3["restrictPublicBuckets"] is True
