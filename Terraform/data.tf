
data "aws_caller_identity" "current_user" {}

data "aws_region" "current" {
  current = true
}

data "aws_iam_policy_document" "cloudtrail_assume_policy" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals = {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}
data "aws_iam_policy_document" "cloudtrail_policy" {
  statement {
    effect    = "Allow"
    actions   = ["logs:CreateLogStream"]
    resources = ["arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current_user.account_id}:log-group:*:log-stream:*"]
  }

  statement {
    effect    = "Allow"
    actions   = ["logs:PutLogEvents"]
    resources = ["arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current_user.account_id}:log-group:*:log-stream:*"]
  }
}

data "aws_iam_policy_document" "cloudtrail_alarm_policy" {
  statement {
    effect = "Allow"

    principals = {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions = [
      "SNS:GetTopicAttributes",
      "SNS:SetTopicAttributes",
      "SNS:AddPermission",
      "SNS:RemovePermission",
      "SNS:DeleteTopic",
      "SNS:Subscribe",
      "SNS:ListSubscriptionsByTopic",
      "SNS:Publish",
      "SNS:Receive",
    ]

    resources = ["arn:aws:sns:${data.aws_region.current.name}:${data.aws_caller_identity.current_user.account_id}:sns_cloudtrail"]

    condition = {
      test     = "StringEquals"
      variable = "AWS:SourceOwner"
      values   = ["${data.aws_caller_identity.current_user.account_id}"]
    }
  }
}
