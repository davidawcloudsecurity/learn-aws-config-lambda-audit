# main.tf

# Configure the AWS provider
provider "aws" {
  region = var.region
}

variable "region" {
  default = "us-east-1" # Change to your preferred region
}

resource "aws_iam_role" "config_lambda_role" {
  name = "config_lambda_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy" "lambda_policy" {
  name = "lambda_policy"
  role = aws_iam_role.config_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = [
          "s3:GetBucketPublicAccessBlock",
          "config:PutEvaluations"
        ]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/lambda_function.py"
  output_path = "${path.module}/lambda_function.zip"
}

resource "aws_lambda_function" "config_lambda" {
  filename         = "${path.module}/lambda_function.zip"
  function_name    = "s3_bucket_public_access_check"
  role             = aws_iam_role.config_lambda_role.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.8"
  timeout          = 30
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
}

resource "aws_lambda_permission" "config_permission" {
  statement_id  = "AllowExecutionFromConfig"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.config_lambda.function_name
  principal     = "config.amazonaws.com"
}

resource "aws_config_config_rule" "s3_bucket_public_access_rule" {
  name = "s3-bucket-level-public-access-prohibited"

  source {
    owner             = "CUSTOM_LAMBDA"
    source_identifier = aws_lambda_function.config_lambda.arn

    dynamic "source_detail" {
      for_each = ["ConfigurationItemChangeNotification", "OversizedConfigurationItemChangeNotification"]
      content {
        event_source = "aws.config"
        message_type = source_detail.value
      }
    }
  }

  scope {
    compliance_resource_types = ["AWS::S3::Bucket"]
  }

  depends_on = [aws_lambda_permission.config_permission]
}
