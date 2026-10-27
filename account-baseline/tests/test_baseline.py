import json

import pulumi
import pytest
from conftest import registered

from src.audit_logs import AuditLogs, AuditLogsArgs
from src.cis_alarms import CIS_ALARMS
from src.detection import Detection, DetectionArgs
from src.hardening import Hardening, HardeningArgs
from src.monitoring import Monitoring, MonitoringArgs

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
            DetectionArgs(
                account_id=ACCOUNT,
                region="eu-west-1",
                log_bucket=audit.bucket,
                log_key=audit.key,
                log_bucket_policy=audit.bucket_policy,
            ),
        )
        Monitoring(
            "alerts",
            MonitoringArgs(
                account_id=ACCOUNT, key=audit.key, trail_log_group=audit.trail_log_group, alert_email="sec@example.com"
            ),
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


def test_sends_cloudtrail_to_an_encrypted_log_group_too() -> None:
    trail = registered("aws:cloudtrail/trail:Trail", "audit")
    assert trail["cloudWatchLogsGroupArn"] == "arn:aws:mock:::audit-trail:*"
    assert trail["cloudWatchLogsRoleArn"] == "arn:aws:mock:::audit-trail-logs"
    group = registered("aws:cloudwatch/logGroup:LogGroup", "audit-trail")
    assert group["name"] == "/aws/cloudtrail/audit-trail"
    assert group["kmsKeyId"] == "arn:aws:mock:::audit"


def test_records_every_request_to_the_audit_bucket() -> None:
    logging = registered("aws:s3/bucketLogging:BucketLogging", "audit")
    assert logging["bucket"] == "audit_id"
    assert logging["targetBucket"] == "audit-access_id"
    sse = registered(
        "aws:s3/bucketServerSideEncryptionConfiguration:BucketServerSideEncryptionConfiguration", "audit-access"
    )
    assert sse["rules"][0]["applyServerSideEncryptionByDefault"]["sseAlgorithm"] == "AES256"


def test_records_config_with_its_service_linked_role() -> None:
    role = registered("aws:iam/serviceLinkedRole:ServiceLinkedRole", "detect-config")
    assert role["awsServiceName"] == "config.amazonaws.com"
    recorder = registered("aws:cfg/recorder:Recorder", "detect")
    assert recorder["roleArn"] == "arn:aws:mock:::detect-config"
    policy = registered("aws:s3/bucketPolicy:BucketPolicy", "audit")
    statements = {s["Sid"]: s for s in json.loads(policy["policy"])["Statement"]}
    assert statements["ConfigWrite"]["Condition"]["StringEquals"]["aws:SourceAccount"] == ACCOUNT


def test_alarms_on_every_cis_metric_filter() -> None:
    assert len(CIS_ALARMS) == 14
    for alarm in CIS_ALARMS:
        metric_filter = registered("aws:cloudwatch/logMetricFilter:LogMetricFilter", f"alerts-{alarm.id}")
        assert metric_filter["logGroupName"] == "/aws/cloudtrail/audit-trail"
        metric_alarm = registered("aws:cloudwatch/metricAlarm:MetricAlarm", f"alerts-{alarm.id}")
        assert metric_alarm["metricName"] == alarm.id
        assert metric_alarm["alarmActions"] == ["arn:aws:mock:::alerts"]


def test_sends_high_severity_findings_to_the_encrypted_alert_topic() -> None:
    topic = registered("aws:sns/topic:Topic", "alerts")
    assert topic["kmsMasterKeyId"] == "audit_id"
    guardduty = json.loads(registered("aws:cloudwatch/eventRule:EventRule", "alerts-guardduty")["eventPattern"])
    assert guardduty["detail"]["severity"] == [{"numeric": [">=", 7]}]
    hub = json.loads(registered("aws:cloudwatch/eventRule:EventRule", "alerts-securityhub")["eventPattern"])
    assert hub["detail"]["findings"]["Severity"]["Label"] == ["HIGH", "CRITICAL"]
    for rule_id in ("guardduty", "securityhub"):
        target = registered("aws:cloudwatch/eventTarget:EventTarget", f"alerts-{rule_id}")
        assert target["arn"] == "arn:aws:mock:::alerts"
    email = registered("aws:sns/topicSubscription:TopicSubscription", "alerts-email")
    assert email["protocol"] == "email"
