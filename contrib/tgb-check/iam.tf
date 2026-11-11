# Read-only role for the platform-apps TargetGroupBinding check.
# Apply in each environment's account, then put the role ARN in the
# matching repository variable (TGB_CHECK_ROLE_STAGING, TGB_CHECK_ROLE_PROD).

variable "github_org" {
  type = string
}

# Most accounts that run GitHub-driven Terraform already have this provider.
# If yours does, replace this resource with a data source.
resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
}

data "aws_iam_policy_document" "tgb_check_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    # Only pull requests in platform-apps can assume this role.
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_org}/platform-apps:pull_request"]
    }
  }
}

resource "aws_iam_role" "tgb_check" {
  name               = "github-platform-apps-tgb-check"
  assume_role_policy = data.aws_iam_policy_document.tgb_check_trust.json
}

data "aws_iam_policy_document" "tgb_check" {
  statement {
    # Describe calls don't support resource-level permissions.
    actions   = ["elasticloadbalancing:DescribeTargetGroups"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "tgb_check" {
  name   = "describe-target-groups"
  role   = aws_iam_role.tgb_check.id
  policy = data.aws_iam_policy_document.tgb_check.json
}

output "tgb_check_role_arn" {
  value = aws_iam_role.tgb_check.arn
}
