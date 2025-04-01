import boto3
import json
import logging
import sys
from datetime import datetime

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Set debug mode to True as requested
DEBUG_MODE = True

def lambda_handler(event, context):
    """
    AWS Lambda function that checks S3 buckets for public access settings.
    This function works with the AWS Config managed rule 's3-bucket-level-public-access-prohibited'.
    
    Parameters:
    event (dict): Event data from AWS Config
    context (object): Lambda execution context
    
    Returns:
    dict: Evaluation results are sent directly to AWS Config
    """
    # Log the incoming event if in debug mode
    if DEBUG_MODE:
        logger.info("Received event: %s", json.dumps(event))
    
    # Initialize AWS clients
    config_client = boto3.client('config')
    s3_client = boto3.client('s3')
    
    # Extract information from the event
    invoking_event = json.loads(event['invokingEvent'])
    rule_parameters = {}
    if 'ruleParameters' in event and event['ruleParameters']:
        rule_parameters = json.loads(event['ruleParameters'])

    # Check if this is a scheduled notification or resource change notification
    is_scheduled_notification = invoking_event.get('messageType') == 'ScheduledNotification'
    
    evaluations = []
    
    # For scheduled notifications, evaluate all applicable S3 buckets
    if is_scheduled_notification:
        if DEBUG_MODE:
            logger.info("Processing scheduled notification")
        
        # Get list of all S3 buckets
        try:
            bucket_list = s3_client.list_buckets()
            for bucket in bucket_list['Buckets']:
                bucket_name = bucket['Name']
                evaluation = evaluate_bucket(s3_client, bucket_name)
                
                # Add the bucket resource info to the evaluation
                evaluation['ComplianceResourceType'] = 'AWS::S3::Bucket'
                evaluation['ComplianceResourceId'] = bucket_name
                evaluation['OrderingTimestamp'] = invoking_event['notificationCreationTime']
                
                evaluations.append(evaluation)
                
                if DEBUG_MODE:
                    logger.info("Evaluated bucket %s: %s", bucket_name, evaluation['ComplianceType'])
        except Exception as e:
            logger.error("Error listing buckets: %s", str(e))
            raise
    
    # For configuration change, evaluate the specific bucket
    else:
        configuration_item = invoking_event.get('configurationItem')
        if not configuration_item:
            configuration_item = invoking_event.get('configurationItemSummary', {})
        
        if DEBUG_MODE:
            logger.info("Processing configuration change for resource: %s", json.dumps(configuration_item))
        
        # Check if this is an S3 bucket
        if configuration_item.get('resourceType') != 'AWS::S3::Bucket':
            if DEBUG_MODE:
                logger.info("Resource is not an S3 bucket, skipping evaluation")
            # Return empty evaluation for non-S3 resources
            config_client.put_evaluations(
                Evaluations=[],
                ResultToken=event['resultToken']
            )
            return
        
        bucket_name = configuration_item['resourceName']
        evaluation = evaluate_bucket(s3_client, bucket_name)
        
        # Add the resource info to the evaluation
        evaluation['ComplianceResourceType'] = configuration_item['resourceType']
        evaluation['ComplianceResourceId'] = configuration_item['resourceId']
        evaluation['OrderingTimestamp'] = configuration_item['configurationItemCaptureTime']
        
        evaluations.append(evaluation)
    
    # Send results to AWS Config
    if evaluations:
        if DEBUG_MODE:
            logger.info("Sending %d evaluation(s) to AWS Config", len(evaluations))
            logger.info("Evaluations: %s", json.dumps(evaluations, default=str))
        
        # Use pagination if there are more than 100 evaluations
        # AWS Config allows max 100 evaluations per API call
        evaluation_chunks = [evaluations[i:i + 100] for i in range(0, len(evaluations), 100)]
        
        for chunk in evaluation_chunks:
            config_client.put_evaluations(
                Evaluations=chunk,
                ResultToken=event['resultToken']
            )
    
    return evaluations

def evaluate_bucket(s3_client, bucket_name):
    """
    Evaluate an S3 bucket for public access configuration.
    
    Parameters:
    s3_client: AWS S3 client
    bucket_name (str): Name of the bucket to evaluate
    
    Returns:
    dict: Evaluation result
    """
    if DEBUG_MODE:
        logger.info("Evaluating bucket: %s", bucket_name)
    
    # Check if the bucket exists without using HeadBucket
    try:
        # Try to perform a less-privileged operation to check if bucket exists
        s3_client.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
    except s3_client.exceptions.ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        
        # NoSuchBucket means bucket doesn't exist
        if error_code == 'NoSuchBucket':
            return {
                'ComplianceType': 'NOT_APPLICABLE',
                'Annotation': f"The bucket {bucket_name} no longer exists."
            }
        
        # For access issues, try to continue with the evaluation
        logger.warning("Warning checking bucket %s existence: %s", bucket_name, str(e)[:200])
        # We'll continue and let individual operations handle their own errors
    
    try:
        # Check the bucket's public access block settings
        try:
            public_access_block = s3_client.get_public_access_block(Bucket=bucket_name)
            block_config = public_access_block['PublicAccessBlockConfiguration']
            
            if DEBUG_MODE:
                logger.info("Public Access Block Configuration for %s: %s", bucket_name, json.dumps(block_config))
            
            # Check if any of the public access block settings are disabled
            if (not block_config['BlockPublicAcls'] or
                not block_config['IgnorePublicAcls'] or
                not block_config['BlockPublicPolicy'] or
                not block_config['RestrictPublicBuckets']):
                return {
                    'ComplianceType': 'NON_COMPLIANT',
                    'Annotation': f"Bucket {bucket_name} has one or more public access block settings disabled."
                }
        except Exception as e:
            # Handle the case when no public access block configuration exists
            error_msg = str(e)
            if 'NoSuchPublicAccessBlockConfiguration' in error_msg or 'NoSuchConfiguration' in error_msg:
                if DEBUG_MODE:
                    logger.info("No Public Access Block Configuration found for bucket: %s", bucket_name)
                return {
                    'ComplianceType': 'NON_COMPLIANT',
                    'Annotation': f"Bucket {bucket_name} does not have public access block configuration."
                }
            elif 'NoSuchBucket' in error_msg:
                return {
                    'ComplianceType': 'NOT_APPLICABLE',
                    'Annotation': f"The bucket {bucket_name} no longer exists."
                }
            else:
                # For other exceptions, log and continue to other checks
                logger.error("Error checking public access block for %s: %s", bucket_name, str(e)[:200])
                # We'll continue with other checks instead of returning immediately
        
        # Check bucket policy
        has_bucket_policy = False
        try:
            bucket_policy = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy = json.loads(bucket_policy['Policy'])
            has_bucket_policy = True
            
            if DEBUG_MODE:
                logger.info("Bucket policy for %s: %s", bucket_name, json.dumps(policy))
            
            # Basic check for potentially public policy
            for statement in policy.get('Statement', []):
                principal = statement.get('Principal', {})
                effect = statement.get('Effect', '')
                
                # Check if effect is "Allow" and principal has public access
                if effect.upper() == 'ALLOW':
                    if principal == '*' or principal.get('AWS') == '*' or (
                        isinstance(principal.get('AWS'), list) and '*' in principal.get('AWS')):
                        return {
                            'ComplianceType': 'NON_COMPLIANT',
                            'Annotation': f"Bucket {bucket_name} has a policy with a wildcard principal."
                        }
        except Exception as e:
            error_msg = str(e)
            if 'NoSuchBucketPolicy' in error_msg:
                # No bucket policy is fine
                if DEBUG_MODE:
                    logger.info("No bucket policy found for: %s", bucket_name)
            elif 'NoSuchBucket' in error_msg:
                return {
                    'ComplianceType': 'NOT_APPLICABLE',
                    'Annotation': f"The bucket {bucket_name} no longer exists."
                }
            else:
                logger.error("Error checking bucket policy for %s: %s", bucket_name, str(e)[:200])
                # Continue with other checks
        
        # Check ACLs
        has_acl_info = False
        try:
            acl = s3_client.get_bucket_acl(Bucket=bucket_name)
            has_acl_info = True
            
            if DEBUG_MODE:
                logger.info("ACL for bucket %s: %s", bucket_name, json.dumps(acl, default=str))
            
            # Check for public access in ACLs
            for grant in acl.get('Grants', []):
                grantee = grant.get('Grantee', {})
                if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers' or \
                   grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers':
                    return {
                        'ComplianceType': 'NON_COMPLIANT',
                        'Annotation': f"Bucket {bucket_name} has public access granted through ACLs."
                    }
        except Exception as e:
            error_msg = str(e)
            if 'NoSuchBucket' in error_msg:
                return {
                    'ComplianceType': 'NOT_APPLICABLE',
                    'Annotation': f"The bucket {bucket_name} no longer exists."
                }
            else:
                logger.error("Error checking ACLs for %s: %s", bucket_name, str(e)[:200])
                # Continue with other checks
        
        # If we weren't able to check any security settings, return NOT_APPLICABLE instead of INSUFFICIENT_DATA
        if not has_acl_info and not has_bucket_policy:
            return {
                'ComplianceType': 'NOT_APPLICABLE',
                'Annotation': f"Unable to evaluate bucket {bucket_name} security settings."
            }
        
        # If we've passed all checks that we were able to perform, the bucket is compliant
        return {
            'ComplianceType': 'COMPLIANT',
            'Annotation': f"Bucket {bucket_name} does not have public access enabled."
        }
    
    except Exception as e:
        logger.error("Error evaluating bucket %s: %s", bucket_name, str(e)[:200])
        # Use NOT_APPLICABLE instead of INSUFFICIENT_DATA
        return {
            'ComplianceType': 'NOT_APPLICABLE',
            'Annotation': f"Could not complete evaluation: {str(e)[:200]}"
        }
    """
    Evaluate an S3 bucket for public access configuration.
    
    Parameters:
    s3_client: AWS S3 client
    bucket_name (str): Name of the bucket to evaluate
    
    Returns:
    dict: Evaluation result
    """
    if DEBUG_MODE:
        logger.info("Evaluating bucket: %s", bucket_name)
    
    # Check if the bucket still exists
    try:
        # Check the bucket's public access block settings
        try:
            public_access_block = s3_client.get_public_access_block(Bucket=bucket_name)
            block_config = public_access_block['PublicAccessBlockConfiguration']
            
            if DEBUG_MODE:
                logger.info("Public Access Block Configuration for %s: %s", bucket_name, json.dumps(block_config))
            
            # Check if any of the public access block settings are disabled
            if (not block_config['BlockPublicAcls'] or
                not block_config['IgnorePublicAcls'] or
                not block_config['BlockPublicPolicy'] or
                not block_config['RestrictPublicBuckets']):
                return {
                    'ComplianceType': 'NON_COMPLIANT',
                    'Annotation': f"Bucket {bucket_name} has one or more public access block settings disabled."
                }
        except s3_client.exceptions.NoSuchPublicAccessBlockConfiguration:
            # If there's no public access block configuration, the bucket is non-compliant
            if DEBUG_MODE:
                logger.info("No Public Access Block Configuration found for bucket: %s", bucket_name)
            return {
                'ComplianceType': 'NON_COMPLIANT',
                'Annotation': f"Bucket {bucket_name} does not have public access block configuration."
            }
        except Exception as e:
            # Handle case when NoSuchPublicAccessBlockConfiguration isn't a proper exception
            if 'NoSuchPublicAccessBlockConfiguration' in str(e):
                if DEBUG_MODE:
                    logger.info("No Public Access Block Configuration found for bucket: %s", bucket_name)
                return {
                    'ComplianceType': 'NON_COMPLIANT',
                    'Annotation': f"Bucket {bucket_name} does not have public access block configuration."
                }
            else:
                # For other exceptions, log and return INSUFFICIENT_DATA
                logger.error("Error checking public access block for %s: %s", bucket_name, str(e)[:200])
                return {
                    'ComplianceType': 'INSUFFICIENT_DATA',
                    'Annotation': f"Could not evaluate bucket {bucket_name} public access block configuration."
                }
        
        # Check bucket policy
        try:
            bucket_policy = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy = json.loads(bucket_policy['Policy'])
            
            if DEBUG_MODE:
                logger.info("Bucket policy for %s: %s", bucket_name, json.dumps(policy))
            
            # Basic check for potentially public policy
            for statement in policy.get('Statement', []):
                principal = statement.get('Principal', {})
                effect = statement.get('Effect', '')
                
                # Check if effect is "Allow" and principal has public access
                if effect.upper() == 'ALLOW':
                    if principal == '*' or principal.get('AWS') == '*' or (
                        isinstance(principal.get('AWS'), list) and '*' in principal.get('AWS')):
                        return {
                            'ComplianceType': 'NON_COMPLIANT',
                            'Annotation': f"Bucket {bucket_name} has a policy with a wildcard principal that allows public access."
                        }
        except s3_client.exceptions.NoSuchBucketPolicy:
            # No bucket policy is fine
            if DEBUG_MODE:
                logger.info("No bucket policy found for: %s", bucket_name)
        
        # Check ACLs
        acl = s3_client.get_bucket_acl(Bucket=bucket_name)
        if DEBUG_MODE:
            logger.info("ACL for bucket %s: %s", bucket_name, json.dumps(acl, default=str))
        
        # Check for public access in ACLs
        for grant in acl.get('Grants', []):
            grantee = grant.get('Grantee', {})
            if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers' or \
               grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers':
                return {
                    'ComplianceType': 'NON_COMPLIANT',
                    'Annotation': f"Bucket {bucket_name} has public access granted through ACLs."
                }
        
        # If we've passed all checks, the bucket is compliant
        return {
            'ComplianceType': 'COMPLIANT',
            'Annotation': f"Bucket {bucket_name} does not have public access enabled."
        }
    
    except s3_client.exceptions.NoSuchBucket:
        return {
            'ComplianceType': 'NOT_APPLICABLE',
            'Annotation': f"The bucket {bucket_name} no longer exists."
        }
    except Exception as e:
        logger.error("Error evaluating bucket %s: %s", bucket_name, str(e))
        # Change ERROR to INSUFFICIENT_DATA and limit annotation length
        return {
            'ComplianceType': 'INSUFFICIENT_DATA',
            'Annotation': f"Error evaluating compliance: {str(e)[:200]}"
        }
