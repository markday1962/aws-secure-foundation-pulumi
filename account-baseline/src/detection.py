from dataclasses import dataclass

import pulumi
import pulumi_aws as aws


@dataclass(frozen=True)
class DetectionArgs:
    account_id: str
    region: str
    # Where AWS Config delivers configuration snapshots and history.
    log_bucket: aws.s3.Bucket
    log_key: aws.kms.Key
    # The bucket policy that lets AWS Config deliver; delivery is checked when the channel is created.
    log_bucket_policy: aws.s3.BucketPolicy


GUARDDUTY_FEATURES = [
    "S3_DATA_EVENTS",
    "EKS_AUDIT_LOGS",
    "EBS_MALWARE_PROTECTION",
    "RDS_LOGIN_EVENTS",
    "LAMBDA_NETWORK_LOGS",
]


class Detection(pulumi.ComponentResource):
    """
    Detection (SEC04): AWS Config records every resource change, GuardDuty
    watches for threats, Security Hub scores the account against AWS FSBP and
    the CIS benchmark, and IAM Access Analyzer flags anything shared outside
    the account.
    """

    def __init__(self, name: str, args: DetectionArgs, opts: pulumi.ResourceOptions | None = None):
        super().__init__("learning:baseline:Detection", name, {}, opts)

        child_opts = pulumi.ResourceOptions(parent=self)

        # ── AWS Config: the inventory and change history Security Hub evaluates.
        # It records with its service-linked role (Security Hub control Config.1);
        # the audit bucket and key policies let the service deliver.
        config_role = aws.iam.ServiceLinkedRole(
            f"{name}-config", aws_service_name="config.amazonaws.com", opts=child_opts
        )

        recorder = aws.cfg.Recorder(
            name,
            name="default",
            role_arn=config_role.arn,
            # Global resources (IAM) are recorded here; record them in one region only.
            recording_group={"all_supported": True, "include_global_resource_types": True},
            opts=child_opts,
        )
        channel = aws.cfg.DeliveryChannel(
            name,
            name="default",
            s3_bucket_name=args.log_bucket.id,
            s3_key_prefix="config",
            s3_kms_key_arn=args.log_key.arn,
            snapshot_delivery_properties={"delivery_frequency": "TwentyFour_Hours"},
            opts=pulumi.ResourceOptions(parent=self, depends_on=[recorder, args.log_bucket_policy]),
        )
        recording = aws.cfg.RecorderStatus(
            name,
            name=recorder.name,
            is_enabled=True,
            opts=pulumi.ResourceOptions(parent=self, depends_on=[channel]),
        )

        # ── GuardDuty: threat detection from CloudTrail, VPC flow, DNS and runtime signals.
        detector = aws.guardduty.Detector(
            name, enable=True, finding_publishing_frequency="FIFTEEN_MINUTES", opts=child_opts
        )
        for feature in GUARDDUTY_FEATURES:
            aws.guardduty.DetectorFeature(
                f"{name}-{feature.lower()}",
                detector_id=detector.id,
                name=feature,
                status="ENABLED",
                opts=child_opts,
            )
        aws.guardduty.DetectorFeature(
            f"{name}-runtime_monitoring",
            detector_id=detector.id,
            name="RUNTIME_MONITORING",
            status="ENABLED",
            # GuardDuty installs and manages its own agents on EKS, ECS Fargate and EC2.
            additional_configurations=[
                {"name": n, "status": "ENABLED"}
                for n in ["EKS_ADDON_MANAGEMENT", "ECS_FARGATE_AGENT_MANAGEMENT", "EC2_AGENT_MANAGEMENT"]
            ],
            opts=child_opts,
        )

        # ── Security Hub: continuous checks against best-practice standards.
        hub = aws.securityhub.Account(
            name,
            # Subscribe to the chosen standards explicitly, below.
            enable_default_standards=False,
            # One finding per control, however many standards include it.
            control_finding_generator="SECURITY_CONTROL",
            auto_enable_controls=True,
            opts=pulumi.ResourceOptions(parent=self, depends_on=[recording]),
        )
        for standard_id, arn in [
            ("fsbp", f"arn:aws:securityhub:{args.region}::standards/aws-foundational-security-best-practices/v/1.0.0"),
            ("cis-5-0-0", f"arn:aws:securityhub:{args.region}::standards/cis-aws-foundations-benchmark/v/5.0.0"),
        ]:
            aws.securityhub.StandardsSubscription(
                f"{name}-{standard_id}",
                standards_arn=arn,
                opts=pulumi.ResourceOptions(parent=self, depends_on=[hub]),
            )

        # ── IAM Access Analyzer: flags resources shared with principals outside the account.
        aws.accessanalyzer.Analyzer(name, analyzer_name=f"{name}-external-access", type="ACCOUNT", opts=child_opts)

        self.register_outputs({"detectorId": detector.id})
