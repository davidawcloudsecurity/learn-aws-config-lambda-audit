provider "aws" {
  region = var.region
}

variable "region" {
  default = "us-east-1"
}

resource "aws_iam_role" "lambda_exec_role" {
  name = "lambda_exec_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_policy" "lambda_s3_policy" {
  name        = "lambda_s3_policy"
  description = "Policy for S3 access required by Lambda function"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:ListBuckets",
          "s3:ListObjectsV2",
          "s3:GetBucketPolicy",
          "s3:GetBucketAcl",
          "s3:GetPublicAccessBlock"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_policy_attachment" "lambda_basic_execution" {
  name       = "lambda_basic_execution"
  roles      = [aws_iam_role.lambda_exec_role.name]
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_policy_attachment" "config_rules_execution" {
  name       = "config_rules_execution"
  roles      = [aws_iam_role.lambda_exec_role.name]
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSConfigRulesExecutionRole"
}

resource "aws_iam_policy_attachment" "lambda_s3_policy_attachment" {
  name       = "lambda_s3_policy_attachment"
  roles      = [aws_iam_role.lambda_exec_role.name]
  policy_arn = aws_iam_policy.lambda_s3_policy.arn
}

resource "aws_lambda_permission" "allow_cloudwatch" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lambda_function.function_name
  principal     = "events.amazonaws.com"
}

resource "null_resource" "package_lambda" {
  provisioner "local-exec" {
    command = <<EOT
      zip -r lambda_function.zip lambda_function.py
    EOT
    working_dir = "${path.module}"
  }
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
