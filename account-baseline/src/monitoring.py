import json
from dataclasses import dataclass

import pulumi
import pulumi_aws as aws

from .cis_alarms import CIS_ALARMS
from .policy import Statement, policy_document

CIS_NAMESPACE = "CISBenchmark"


@dataclass(frozen=True)
class MonitoringArgs:
    account_id: str
    # Encrypts the alert topic. Its key policy must let EventBridge and CloudWatch use it.
    key: aws.kms.Key
    # The CloudTrail log group the CIS metric filters watch.
    trail_log_group: aws.cloudwatch.LogGroup
    # Gets every alert by email (after confirming the subscription). None to skip.
    alert_email: str | None


class Monitoring(pulumi.ComponentResource):
    """
    Turns detection into notification (SEC04-BP03, SEC10): one encrypted SNS
    topic receives high-severity GuardDuty findings, high and critical Security
    Hub findings, and the CIS benchmark's CloudTrail alarms.
    """

    topic: aws.sns.Topic

    def __init__(self, name: str, args: MonitoringArgs, opts: pulumi.ResourceOptions | None = None):
        super().__init__("learning:baseline:Monitoring", name, {}, opts)

        child_opts = pulumi.ResourceOptions(parent=self)

        self.topic = aws.sns.Topic(name, kms_master_key_id=args.key.id, opts=child_opts)
        aws.sns.TopicPolicy(
            name,
            arn=self.topic.arn,
            policy=policy_document(
                [
                    Statement(
                        sid="AccountAdministration",
                        principals={"type": "AWS", "identifiers": [f"arn:aws:iam::{args.account_id}:root"]},
                        actions=[
                            "sns:GetTopicAttributes",
                            "sns:SetTopicAttributes",
                            "sns:Subscribe",
                            "sns:ListSubscriptionsByTopic",
                            "sns:Publish",
                        ],
                        resources=[self.topic.arn],
                    ),
                    # EventBridge rules and CloudWatch alarms in this account only.
                    Statement(
                        sid="AlertPublishers",
                        principals={
                            "type": "Service",
                            "identifiers": ["events.amazonaws.com", "cloudwatch.amazonaws.com"],
                        },
                        actions=["sns:Publish"],
                        resources=[self.topic.arn],
                        conditions={"StringEquals": {"aws:SourceAccount": args.account_id}},
                    ),
                    Statement(
                        sid="DenyInsecureTransport",
                        effect="Deny",
                        principals={"type": "AWS", "identifiers": ["*"]},
                        actions=["sns:Publish"],
                        resources=[self.topic.arn],
                        conditions={"Bool": {"aws:SecureTransport": "false"}},
                    ),
                ]
            ),
            opts=child_opts,
        )

        if args.alert_email:
            aws.sns.TopicSubscription(
                f"{name}-email", topic=self.topic.arn, protocol="email", endpoint=args.alert_email, opts=child_opts
            )

        # ── Findings, as they arrive.
        for rule_id, description, pattern in [
            (
                "guardduty",
                "GuardDuty findings of high severity (7.0 and above)",
                {
                    "source": ["aws.guardduty"],
                    "detail-type": ["GuardDuty Finding"],
                    "detail": {"severity": [{"numeric": [">=", 7]}]},
                },
            ),
            (
                "securityhub",
                "New, active Security Hub findings of high or critical severity",
                {
                    "source": ["aws.securityhub"],
                    "detail-type": ["Security Hub Findings - Imported"],
                    "detail": {
                        "findings": {
                            "Severity": {"Label": ["HIGH", "CRITICAL"]},
                            "Workflow": {"Status": ["NEW"]},
                            "RecordState": ["ACTIVE"],
                        }
                    },
                },
            ),
        ]:
            rule = aws.cloudwatch.EventRule(
                f"{name}-{rule_id}",
                description=description,
                event_pattern=json.dumps(pattern, separators=(",", ":")),
                opts=child_opts,
            )
            aws.cloudwatch.EventTarget(f"{name}-{rule_id}", rule=rule.name, arn=self.topic.arn, opts=child_opts)

        # ── CIS benchmark alarms on CloudTrail events.
        for alarm in CIS_ALARMS:
            aws.cloudwatch.LogMetricFilter(
                f"{name}-{alarm.id}",
                log_group_name=args.trail_log_group.name,
                pattern=alarm.pattern,
                metric_transformation={"name": alarm.id, "namespace": CIS_NAMESPACE, "value": "1"},
                opts=child_opts,
            )
            aws.cloudwatch.MetricAlarm(
                f"{name}-{alarm.id}",
                alarm_description=alarm.description,
                namespace=CIS_NAMESPACE,
                metric_name=alarm.id,
                statistic="Sum",
                period=300,
                evaluation_periods=1,
                threshold=1,
                comparison_operator="GreaterThanOrEqualToThreshold",
                treat_missing_data="notBreaching",
                alarm_actions=[self.topic.arn],
                opts=child_opts,
            )

        self.register_outputs({"topicArn": self.topic.arn})
