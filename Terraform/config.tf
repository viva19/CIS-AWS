provider "aws" {
  region     = ""
  access_key = ""
  secret_key = ""

}


resource "aws_cloudtrail" "foobar" {
  name                          = "tf-trail-foobar"
  s3_bucket_name                = "${aws_s3_bucket.foo.id}"
  s3_key_prefix                 = "prefix"
  include_global_service_events = true
  enable_logging                 = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.log_group_default.arn}"
  cloud_watch_logs_role_arn = "${aws_iam_role.cloudtrail_role.arn}"
  kms_key_id = "${aws_kms_key.cloudtrail_key.arn}"


}
data "aws_caller_identity" "current" {}
resource "aws_s3_bucket" "foo" {
  force_destroy = true

}
resource "aws_iam_account_password_policy" "passwordPolicy" {
  minimum_password_length        = "8"
  require_lowercase_characters   = "true"
  require_numbers                = "true"
  require_uppercase_characters   = "true"
  require_symbols                = "true"
  allow_users_to_change_password = "true"

}

resource "aws_s3_bucket_policy" "s3policy" {
    bucket = "${aws_s3_bucket.foo.id}"
  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailAclCheck",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:GetBucketAcl",
            "Resource": "${aws_s3_bucket.foo.arn}"
        },
        {
            "Sid": "AWSCloudTrailWrite",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": "${aws_s3_bucket.foo.arn}/*",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        }
    ]
}
POLICY
}

resource "aws_kms_key" "cloudtrail_key" {
  deletion_window_in_days = 7
  description             = "CloudTrail Log Encryption Key"
  enable_key_rotation     = true

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Enable IAM User Permissions",
      "Effect": "Allow",
      "Principal": {
        "AWS": [
          "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        ]
      },
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "Allow CloudTrail to encrypt logs",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "kms:GenerateDataKey*",
      "Resource": "*",
      "Condition": {
        "StringLike": {
          "kms:EncryptionContext:aws:cloudtrail:arn": [
            "arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"
          ]
        }
      }
    },
    {
      "Sid": "Allow CloudWatch Access",
      "Effect": "Allow",
      "Principal": {
        "Service": "logs.us-east-1.amazonaws.com"
      },
      "Action": [
        "kms:Encrypt*",
        "kms:Decrypt*",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:Describe*"
      ],
      "Resource": "*"
    },
    {
      "Sid": "Allow Describe Key access",
      "Effect": "Allow",
      "Principal": {
        "Service": ["cloudtrail.amazonaws.com", "lambda.amazonaws.com"]
      },
      "Action": "kms:DescribeKey",
      "Resource": "*"
    }
  ]
}
POLICY
}
resource "aws_kms_alias" "cloudtrail_key" {
  name          = "alias/cloudtrail_key"
  target_key_id = "${aws_kms_key.cloudtrail_key.id}"
}
resource "aws_sns_topic" "sns_topic_default" {
  name   = "sns_cloudtrail"
  policy = "${data.aws_iam_policy_document.cloudtrail_alarm_policy.json}"
}


resource "aws_cloudwatch_log_group" "log_group_default" {
  name = "logGroupDefaultCloudTrail"
}

resource "aws_iam_role" "cloudtrail_role" {
  name               = "CloudTrail-terraform-role"
  assume_role_policy = "${data.aws_iam_policy_document.cloudtrail_assume_policy.json}"
}


resource "aws_iam_policy" "cloudtrail_access_policy" {
  name   = "Cloudtrailpolicy"
  policy = "${data.aws_iam_policy_document.cloudtrail_policy.json}"
}

resource "aws_iam_policy_attachment" "cloudtrail_access_policy_attachment" {
  name       = "cloudtrail-policy-attachment"
  policy_arn = "${aws_iam_policy.cloudtrail_access_policy.arn}"
  roles      = ["${aws_iam_role.cloudtrail_role.name}"]
}

resource "aws_vpc" "main" {
  cidr_block       = "10.1.0.0/24"
  instance_tenancy = "dedicated"

  tags {
    Name = "main"
  }
}

resource "aws_flow_log" "test_flow_log" {
  log_group_name = "${aws_cloudwatch_log_group.log_group_default.name}"
  vpc_id         = "${aws_vpc.main.id}"
  iam_role_arn   = "${aws_iam_role.cloudtrail_role.arn}"
  traffic_type   = "ALL"
}

resource "aws_default_security_group" "default" {
  vpc_id = "${aws_vpc.main.id}"

  ingress {
    protocol  = -1
    self      = true
    from_port = 0
    to_port   = 0
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}



resource "aws_iam_role" "r" {
  name = "awsconfig-example"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "config.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
POLICY
}


resource "aws_iam_role_policy_attachment" "a" {
  role       = "${aws_iam_role.r.name}"
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSConfigRole"
}

resource "aws_s3_bucket" "b" {
  force_destroy = true
}
