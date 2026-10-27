from dataclasses import dataclass


@dataclass(frozen=True)
class CisAlarm:
    # Short, stable ID: used in resource and metric names.
    id: str
    description: str
    # CloudWatch Logs filter pattern over CloudTrail events.
    pattern: str


def _any_event(*names: str) -> str:
    return " || ".join(f"($.eventName = {n})" for n in names)


# CIS AWS Foundations Benchmark: metric filters and alarms on CloudTrail logs
# (Security Hub controls CloudWatch.1-14).
CIS_ALARMS = [
    CisAlarm(
        "root-usage",
        "The root user was used",
        '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }',
    ),
    CisAlarm(
        "unauthorized-api-calls",
        "API calls were denied",
        '{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }',
    ),
    CisAlarm(
        "console-signin-without-mfa",
        "An IAM user signed in to the console without MFA",
        '{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") '
        '&& ($.userIdentity.type = "IAMUser") && ($.responseElements.ConsoleLogin = "Success") }',
    ),
    CisAlarm(
        "console-auth-failures",
        "Console sign-in failed",
        '{ ($.eventName = ConsoleLogin) && ($.errorMessage = "Failed authentication") }',
    ),
    CisAlarm(
        "iam-policy-changes",
        "An IAM policy was changed",
        "{ "
        + _any_event(
            "DeleteGroupPolicy",
            "DeleteRolePolicy",
            "DeleteUserPolicy",
            "PutGroupPolicy",
            "PutRolePolicy",
            "PutUserPolicy",
            "CreatePolicy",
            "DeletePolicy",
            "CreatePolicyVersion",
            "DeletePolicyVersion",
            "AttachRolePolicy",
            "DetachRolePolicy",
            "AttachUserPolicy",
            "DetachUserPolicy",
            "AttachGroupPolicy",
            "DetachGroupPolicy",
        )
        + " }",
    ),
    CisAlarm(
        "cloudtrail-changes",
        "CloudTrail configuration was changed",
        "{ " + _any_event("CreateTrail", "UpdateTrail", "DeleteTrail", "StartLogging", "StopLogging") + " }",
    ),
    CisAlarm(
        "kms-key-disabled-or-deleted",
        "A customer-managed KMS key was disabled or scheduled for deletion",
        "{ ($.eventSource = kms.amazonaws.com) && (" + _any_event("DisableKey", "ScheduleKeyDeletion") + ") }",
    ),
    CisAlarm(
        "s3-bucket-policy-changes",
        "An S3 bucket policy, ACL, CORS, lifecycle or replication rule was changed",
        "{ ($.eventSource = s3.amazonaws.com) && ("
        + _any_event(
            "PutBucketAcl",
            "PutBucketPolicy",
            "PutBucketCors",
            "PutBucketLifecycle",
            "PutBucketReplication",
            "DeleteBucketPolicy",
            "DeleteBucketCors",
            "DeleteBucketLifecycle",
            "DeleteBucketReplication",
        )
        + ") }",
    ),
    CisAlarm(
        "config-changes",
        "AWS Config recording or delivery was changed",
        "{ ($.eventSource = config.amazonaws.com) && ("
        + _any_event(
            "StopConfigurationRecorder", "DeleteDeliveryChannel", "PutDeliveryChannel", "PutConfigurationRecorder"
        )
        + ") }",
    ),
    CisAlarm(
        "security-group-changes",
        "A security group was changed",
        "{ "
        + _any_event(
            "AuthorizeSecurityGroupIngress",
            "AuthorizeSecurityGroupEgress",
            "RevokeSecurityGroupIngress",
            "RevokeSecurityGroupEgress",
            "CreateSecurityGroup",
            "DeleteSecurityGroup",
        )
        + " }",
    ),
    CisAlarm(
        "nacl-changes",
        "A network ACL was changed",
        "{ "
        + _any_event(
            "CreateNetworkAcl",
            "CreateNetworkAclEntry",
            "DeleteNetworkAcl",
            "DeleteNetworkAclEntry",
            "ReplaceNetworkAclEntry",
            "ReplaceNetworkAclAssociation",
        )
        + " }",
    ),
    CisAlarm(
        "network-gateway-changes",
        "An internet or customer gateway was changed",
        "{ "
        + _any_event(
            "CreateCustomerGateway",
            "DeleteCustomerGateway",
            "AttachInternetGateway",
            "CreateInternetGateway",
            "DeleteInternetGateway",
            "DetachInternetGateway",
        )
        + " }",
    ),
    CisAlarm(
        "route-table-changes",
        "A route table was changed",
        "{ ($.eventSource = ec2.amazonaws.com) && ("
        + _any_event(
            "CreateRoute",
            "CreateRouteTable",
            "ReplaceRoute",
            "ReplaceRouteTableAssociation",
            "DeleteRouteTable",
            "DeleteRoute",
            "DisassociateRouteTable",
        )
        + ") }",
    ),
    CisAlarm(
        "vpc-changes",
        "A VPC or VPC peering connection was changed",
        "{ "
        + _any_event(
            "CreateVpc",
            "DeleteVpc",
            "ModifyVpcAttribute",
            "AcceptVpcPeeringConnection",
            "CreateVpcPeeringConnection",
            "DeleteVpcPeeringConnection",
            "RejectVpcPeeringConnection",
        )
        + " }",
    ),
]
