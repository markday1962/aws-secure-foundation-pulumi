from dataclasses import dataclass

import pulumi
import pulumi_aws as aws


@dataclass(frozen=True)
class HardeningArgs:
    # IMDSv2 hop limit: 1 is strictest; containers on EC2 need 2.
    imds_hop_limit: int


class Hardening(pulumi.ComponentResource):
    """
    Account and region defaults that make the insecure option unavailable,
    rather than relying on every resource being configured correctly.
    """

    def __init__(self, name: str, args: HardeningArgs, opts: pulumi.ResourceOptions | None = None):
        super().__init__("learning:baseline:Hardening", name, {}, opts)

        child_opts = pulumi.ResourceOptions(parent=self)

        # New EBS volumes and snapshot copies are always encrypted.
        aws.ebs.EncryptionByDefault(name, enabled=True, opts=child_opts)

        # EBS snapshots and AMIs can't be shared publicly.
        aws.ebs.SnapshotBlockPublicAccess(name, state="block-all-sharing", opts=child_opts)
        aws.ec2.ImageBlockPublicAccess(name, state="block-new-sharing", opts=child_opts)

        # New instances default to IMDSv2 (session tokens), which blocks the
        # SSRF-to-credentials attacks that IMDSv1 allows.
        aws.ec2.InstanceMetadataDefaults(
            name,
            http_tokens="required",
            http_put_response_hop_limit=args.imds_hop_limit,
            http_endpoint="enabled",
            instance_metadata_tags="disabled",
            opts=child_opts,
        )

        # No interactive serial console access to instances.
        aws.ec2.SerialConsoleAccess(name, enabled=False, opts=child_opts)

        # No S3 bucket or object in the account can be made public.
        aws.s3.AccountPublicAccessBlock(
            name,
            block_public_acls=True,
            block_public_policy=True,
            ignore_public_acls=True,
            restrict_public_buckets=True,
            opts=child_opts,
        )

        # For any IAM users that exist (prefer IAM Identity Center): CIS benchmark password rules.
        aws.iam.AccountPasswordPolicy(
            name,
            minimum_password_length=14,
            require_lowercase_characters=True,
            require_uppercase_characters=True,
            require_numbers=True,
            require_symbols=True,
            allow_users_to_change_password=True,
            password_reuse_prevention=24,
            opts=child_opts,
        )

        self.register_outputs({})
