This Lambda function checks and reports on the compliance status of S3 buckets with regard to the AWS Config managed rule `s3-bucket-level-public-access-prohibited`.

Specifically, it evaluates whether S3 buckets have any form of public access enabled, checking three main aspects:

1. **Public Access Block settings** - Verifies that all four public access block settings are enabled:
   - BlockPublicAcls
   - IgnorePublicAcls
   - BlockPublicPolicy
   - RestrictPublicBuckets

2. **Bucket policies** - Examines bucket policies to identify any statements that allow public access (those with a wildcard principal "*" and "Allow" effect)

3. **Bucket ACLs** - Checks for any ACL grants that provide access to the "AllUsers" or "AuthenticatedUsers" groups

The function reports one of these compliance statuses to AWS Config:
- **COMPLIANT**: The bucket has all public access properly blocked
- **NON_COMPLIANT**: The bucket has one or more configurations that allow public access
- **NOT_APPLICABLE**: The resource is not an S3 bucket or no longer exists
- **ERROR**: An exception occurred during evaluation

The rule helps organizations enforce security best practices by ensuring their S3 buckets don't allow public access, which can lead to data exposure if misconfigured.
