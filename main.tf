locals {
  enabled = module.this.enabled

  bucket_name = length(var.bucket_name) > 0 ? var.bucket_name : module.bucket_name.id

  arn_format  = "arn:${data.aws_partition.current.partition}"

  lifecycle_configuration_rules = (local.deprecated_lifecycle_rule.enabled ?
    tolist(concat(var.lifecycle_configuration_rules, [local.deprecated_lifecycle_rule])) : var.lifecycle_configuration_rules
  )
}

module "bucket_name" {
  source  = "cloudposse/label/null"
  version = "0.25.0"

  enabled = local.enabled && length(var.bucket_name) == 0

  id_length_limit = 63 # https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html

  context = module.this.context
}

data "aws_partition" "current" {}

data "aws_caller_identity" "current" {}

# https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-s3.html
data "aws_iam_policy_document" "bucket" {
  count = module.this.enabled ? 1 : 0

  statement {
    sid = "AWSLogDeliveryWrite"

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    actions = [
      "s3:PutObject"
    ]

    resources = [
      "${local.arn_format}:s3:::${local.bucket_name}/*"
    ]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"

      values = [
        "bucket-owner-full-control"
      ]
    }
  }

  statement {
    sid = "AWSLogDeliveryAclCheck"

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    actions = [
      "s3:GetBucketAcl"
    ]

    resources = [
      "${local.arn_format}:s3:::${local.bucket_name}"
    ]
  }

  dynamic "statement" {
    for_each = var.allow_ssl_requests_only ? [1] : []

    content {
      sid     = "ForceSSLOnlyAccess"
      effect  = "Deny"
      actions = ["s3:*"]
      resources = [
        "${local.arn_format}:s3:::${local.bucket_name}/*",
        "${local.arn_format}:s3:::${local.bucket_name}"
      ]

      principals {
        identifiers = ["*"]
        type        = "*"
      }

      condition {
        test     = "Bool"
        values   = ["false"]
        variable = "aws:SecureTransport"
      }
    }
  }

  lifecycle {
    # some form of name must be supplied.
    precondition {
      condition     = try(length(local.bucket_name) > 0, false)
      error_message = <<-EOT
        Bucket name must be provided either directly via `bucket_name`
        or indirectly via `null-label` inputs such as `name` or `namespace`.
        EOT
    }
  }
}

module "s3_log_storage_bucket" {
  source  = "cloudposse/s3-log-storage/aws"
  version = "2.0.0"

  bucket_name = local.bucket_name

  lifecycle_configuration_rules = local.lifecycle_configuration_rules
  object_lock_configuration     = var.object_lock_configuration

  force_destroy = var.force_destroy

  acl                     = var.acl
  s3_object_ownership     = var.s3_object_ownership == null ? "BucketOwnerEnforced" : var.s3_object_ownership
  source_policy_documents = data.aws_iam_policy_document.bucket.*.json

  bucket_notifications_enabled = var.bucket_notifications_enabled
  bucket_notifications_type    = var.bucket_notifications_type
  bucket_notifications_prefix  = var.bucket_notifications_prefix

  access_log_bucket_name   = var.access_log_bucket_name
  access_log_bucket_prefix = var.access_log_bucket_prefix

  versioning_enabled = var.versioning_enabled

  context = module.this.context
}

resource "aws_flow_log" "default" {
  count                = local.enabled && var.flow_log_enabled ? 1 : 0
  log_destination      = module.s3_log_storage_bucket.bucket_arn
  log_destination_type = "s3"
  log_format           = var.log_format
  traffic_type         = var.traffic_type
  vpc_id               = var.vpc_id
  destination_options {
    file_format        = "parquet"
  }
  tags = module.this.tags
}
