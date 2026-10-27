from dataclasses import dataclass

import pulumi
import pulumi_aws as aws

from .policy import Statement, policy_document

# TLS 1.3 and 1.2 only, with forward-secret AEAD ciphers (the "restricted" variant).
SSL_POLICY = "ELBSecurityPolicy-TLS13-1-2-Res-2021-06"


@dataclass(frozen=True)
class LoadBalancerArgs:
    account_id: str
    region: str
    vpc_id: pulumi.Input[str]
    # The public subnets, one per AZ.
    subnet_ids: list[pulumi.Input[str]]
    security_group_id: pulumi.Input[str]
    # Port the app tier listens on; the target group sends HTTPS to it.
    app_port: int
    # The name clients use, e.g. app.example.com. It must sit in the hosted zone.
    domain_name: str
    # The Route 53 public hosted zone that holds domain_name, e.g. example.com.
    hosted_zone_name: str
    deletion_protection: bool
    log_retention_days: int


class LoadBalancer(pulumi.ComponentResource):
    """
    The internet-facing Application Load Balancer, the only way in from the
    internet (SEC05-BP02):

      :80  HTTP  → 301 redirect to HTTPS
      :443 HTTPS → TLS 1.2/1.3 with an ACM certificate → fixed response (for now)

    An empty HTTPS target group on the app port is ready for workloads, and the
    ALB's ARN is exported so a WAF web ACL can be attached to it.
    """

    alb: aws.lb.LoadBalancer
    https_listener: aws.lb.Listener
    target_group: aws.lb.TargetGroup

    def __init__(self, name: str, args: LoadBalancerArgs, opts: pulumi.ResourceOptions | None = None):
        super().__init__("learning:network:LoadBalancer", name, {}, opts)

        child_opts = pulumi.ResourceOptions(parent=self)

        # ── Certificate: ACM, validated by a DNS record in the hosted zone.
        zone = aws.route53.get_zone_output(name=args.hosted_zone_name, private_zone=False)
        certificate = aws.acm.Certificate(
            name,
            domain_name=args.domain_name,
            validation_method="DNS",
            opts=pulumi.ResourceOptions(parent=self, delete_before_replace=True),
        )
        # One domain, so one validation record.
        validation = certificate.domain_validation_options[0]
        validation_record = aws.route53.Record(
            f"{name}-cert-validation",
            zone_id=zone.zone_id,
            name=validation.resource_record_name,
            type=validation.resource_record_type,
            records=[validation.resource_record_value],
            ttl=300,
            allow_overwrite=True,
            opts=child_opts,
        )
        validated = aws.acm.CertificateValidation(
            name,
            certificate_arn=certificate.arn,
            validation_record_fqdns=[validation_record.fqdn],
            opts=child_opts,
        )

        logs, logs_policy = self._access_log_bucket(name, args)

        self.alb = aws.lb.LoadBalancer(
            name,
            load_balancer_type="application",
            internal=False,
            subnets=args.subnet_ids,
            security_groups=[args.security_group_id],
            # Reject requests with malformed headers, and treat ambiguous ones
            # (HTTP desync / request smuggling) as strictly as possible.
            drop_invalid_header_fields=True,
            desync_mitigation_mode="strictest",
            enable_deletion_protection=args.deletion_protection,
            access_logs={"bucket": logs.id, "prefix": "alb", "enabled": True},
            # The ALB checks it can write to the bucket when access logging is switched on.
            opts=pulumi.ResourceOptions(parent=self, depends_on=[logs_policy]),
        )

        # ── :80 only ever redirects to HTTPS.
        aws.lb.Listener(
            f"{name}-http",
            load_balancer_arn=self.alb.arn,
            port=80,
            protocol="HTTP",
            default_actions=[
                {
                    "type": "redirect",
                    "redirect": {"protocol": "HTTPS", "port": "443", "status_code": "HTTP_301"},
                }
            ],
            opts=child_opts,
        )

        # ── :443 terminates TLS. Until workloads exist it answers with a fixed response.
        self.https_listener = aws.lb.Listener(
            f"{name}-https",
            load_balancer_arn=self.alb.arn,
            port=443,
            protocol="HTTPS",
            certificate_arn=validated.certificate_arn,
            ssl_policy=SSL_POLICY,
            default_actions=[
                {
                    "type": "fixed-response",
                    "fixed_response": {"content_type": "text/plain", "message_body": "ok\n", "status_code": "200"},
                }
            ],
            # Security headers on every response, and no Server header.
            routing_http_response_strict_transport_security_header_value="max-age=31536000; includeSubDomains",
            routing_http_response_x_content_type_options_header_value="nosniff",
            routing_http_response_x_frame_options_header_value="DENY",
            routing_http_response_server_enabled=False,
            opts=child_opts,
        )

        # Where workloads will register. The ALB re-encrypts to them, so traffic is TLS end to end.
        self.target_group = aws.lb.TargetGroup(
            name,
            vpc_id=args.vpc_id,
            port=args.app_port,
            protocol="HTTPS",
            target_type="ip",
            health_check={"protocol": "HTTPS", "path": "/health", "matcher": "200"},
            opts=child_opts,
        )

        aws.route53.Record(
            f"{name}-alias",
            zone_id=zone.zone_id,
            name=args.domain_name,
            type="A",
            aliases=[{"name": self.alb.dns_name, "zone_id": self.alb.zone_id, "evaluate_target_health": True}],
            opts=child_opts,
        )

        self.register_outputs({"albArn": self.alb.arn, "dnsName": self.alb.dns_name})

    def _access_log_bucket(self, name: str, args: LoadBalancerArgs) -> tuple[aws.s3.Bucket, aws.s3.BucketPolicy]:
        """
        A private bucket for ALB access logs. ALB log delivery only supports
        SSE-S3, not KMS, so this bucket uses S3-managed keys.
        """
        child_opts = pulumi.ResourceOptions(parent=self)
        bucket = aws.s3.Bucket(
            f"{name}-logs",
            bucket=f"{name}-logs-{args.account_id}-{args.region}",
            # The network stack is meant to be torn down; the logs go with it.
            force_destroy=True,
            opts=child_opts,
        )
        bucket_opts = pulumi.ResourceOptions(parent=self, depends_on=[bucket])

        public_access_block = aws.s3.BucketPublicAccessBlock(
            f"{name}-logs",
            bucket=bucket.id,
            block_public_acls=True,
            block_public_policy=True,
            ignore_public_acls=True,
            restrict_public_buckets=True,
            opts=bucket_opts,
        )
        aws.s3.BucketOwnershipControls(
            f"{name}-logs",
            bucket=bucket.id,
            rule={"object_ownership": "BucketOwnerEnforced"},
            opts=bucket_opts,
        )
        aws.s3.BucketServerSideEncryptionConfiguration(
            f"{name}-logs",
            bucket=bucket.id,
            rules=[{"apply_server_side_encryption_by_default": {"sse_algorithm": "AES256"}}],
            opts=bucket_opts,
        )
        aws.s3.BucketLifecycleConfiguration(
            f"{name}-logs",
            bucket=bucket.id,
            rules=[
                {
                    "id": "expire-after-retention",
                    "status": "Enabled",
                    "filter": {},
                    "expiration": {"days": args.log_retention_days},
                }
            ],
            opts=bucket_opts,
        )

        # In regions launched before August 2022 (eu-west-1 included), logs are
        # written by the region's Elastic Load Balancing account.
        elb_account = aws.elb.get_service_account_output()
        policy = aws.s3.BucketPolicy(
            f"{name}-logs",
            bucket=bucket.id,
            policy=policy_document(
                [
                    Statement(
                        sid="DenyInsecureTransport",
                        effect="Deny",
                        principals={"type": "AWS", "identifiers": ["*"]},
                        actions=["s3:*"],
                        resources=[bucket.arn, pulumi.Output.concat(bucket.arn, "/*")],
                        conditions={"Bool": {"aws:SecureTransport": "false"}},
                    ),
                    Statement(
                        sid="ElbLogDelivery",
                        principals={"type": "AWS", "identifiers": [elb_account.arn]},
                        actions=["s3:PutObject"],
                        resources=[pulumi.Output.concat(bucket.arn, f"/alb/AWSLogs/{args.account_id}/*")],
                    ),
                ]
            ),
            opts=pulumi.ResourceOptions(parent=self, depends_on=[public_access_block]),
        )
        return bucket, policy
