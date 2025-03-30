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
    AWS Lambda function that checks S3 buckets for encryption settings.
    This function works with the AWS Config managed rule 's3-bucket-server-side-encryption-enabled'.
    
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
                evaluation = evaluate_bucket_encryption(s3_client, bucket_name)
                
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
        evaluation = evaluate_bucket_encryption(s3_client, bucket_name)
        
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

def evaluate_bucket_encryption(s3_client, bucket_name):
    """
    Evaluate an S3 bucket for server-side encryption configuration.
    
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
        # Check the bucket's server-side encryption configuration
        try:
            encryption_config = s3_client.get_bucket_encryption(Bucket=bucket_name)
            if DEBUG_MODE:
                logger.info("Encryption Configuration for %s: %s", bucket_name, json.dumps(encryption_config))
            
            # Check if encryption is enabled
            if 'ServerSideEncryptionConfiguration' in encryption_config:
                return {
                    'ComplianceType': 'COMPLIANT',
                    'Annotation': f"Bucket {bucket_name} has server-side encryption enabled."
                }
            else:
                return {
                    'ComplianceType': 'NON_COMPLIANT',
                    'Annotation': f"Bucket {bucket_name} does not have server-side encryption enabled."
                }
        except s3_client.exceptions.ServerSideEncryptionConfigurationNotFoundError:
            # If there's no encryption configuration, the bucket is non-compliant
            if DEBUG_MODE:
                logger.info("No Encryption Configuration found for bucket: %s", bucket_name)
            return {
                'ComplianceType': 'NON_COMPLIANT',
                'Annotation': f"Bucket {bucket_name} does not have server-side encryption enabled."
            }
    
    except s3_client.exceptions.NoSuchBucket:
        return {
            'ComplianceType': 'NOT_APPLICABLE',
            'Annotation': f"The bucket {bucket_name} no longer exists."
        }
    except Exception as e:
        logger.error("Error evaluating bucket %s: %s", bucket_name, str(e))
        return {
            'ComplianceType': 'ERROR',
            'Annotation': f"Error evaluating compliance: {str(e)}"
        }
