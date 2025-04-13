import boto3
import json
import logging
from datetime import datetime

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Enable debug mode
DEBUG_MODE = False

def lambda_handler(event, context):
    """
    AWS Lambda function that checks security groups for rules allowing traffic from/to 0.0.0.0/0.
    This function works with AWS Config to evaluate security group compliance.
    
    Parameters:
    - event (dict): Event data from AWS Config
    - context (object): Lambda execution context
    
    Returns:
    - dict: Evaluation results are sent directly to AWS Config
    """
    global DEBUG_MODE
    rule_parameters = json.loads(event.get('ruleParameters', '{}'))
    DEBUG_MODE_str = rule_parameters.get('debug_mode', 'False')
    DEBUG_MODE = DEBUG_MODE_str.lower() == 'true'
    
    if DEBUG_MODE:
        logger.info("Received event: %s", json.dumps(event))
    
    # Initialize AWS clients
    config_client = boto3.client('config')
    ec2_client = boto3.client('ec2')
    
    # Parse event data
    invoking_event = json.loads(event['invokingEvent'])
    rule_parameters = json.loads(event.get('ruleParameters', '{}'))
    is_scheduled_notification = invoking_event.get('messageType') == 'ScheduledNotification'
    
    evaluations = []
    
    # Handle scheduled notifications (evaluate all security groups)
    if is_scheduled_notification:
        if DEBUG_MODE:
            logger.info("Processing scheduled notification")
        
        try:
            security_groups = []
            response = ec2_client.describe_security_groups()
            security_groups.extend(response['SecurityGroups'])
            while 'NextToken' in response:
                response = ec2_client.describe_security_groups(NextToken=response['NextToken'])
                security_groups.extend(response['SecurityGroups'])
            
            for sg in security_groups:
                group_id = sg['GroupId']
                evaluation = evaluate_security_group(ec2_client, group_id)
                
                # Only add evaluation if it exists
                if evaluation is not None:
                    evaluation.update({
                        'ComplianceResourceType': 'AWS::EC2::SecurityGroup',
                        'ComplianceResourceId': group_id,
                        'OrderingTimestamp': invoking_event['notificationCreationTime']
                    })
                    evaluations.append(evaluation)
                    if DEBUG_MODE:
                        logger.info("Evaluated security group %s: %s", group_id, evaluation['ComplianceType'])
        except Exception as e:
            logger.error("Error listing security groups: %s", str(e))
            raise
    
    # Handle configuration change (evaluate a specific security group)
    else:
        configuration_item = invoking_event.get('configurationItem', invoking_event.get('configurationItemSummary', {}))
        
        if DEBUG_MODE:
            logger.info("Processing configuration change: %s", json.dumps(configuration_item))
        
        if configuration_item.get('resourceType') != 'AWS::EC2::SecurityGroup':
            if DEBUG_MODE:
                logger.info("Not a security group, skipping evaluation")
            config_client.put_evaluations(Evaluations=[], ResultToken=event['resultToken'])
            return
        
        group_id = configuration_item['resourceId']
        evaluation = evaluate_security_group(ec2_client, group_id)
        
        # Only add evaluation if it exists
        if evaluation is not None:
            evaluation.update({
                'ComplianceResourceType': configuration_item['resourceType'],
                'ComplianceResourceId': group_id,
                'OrderingTimestamp': configuration_item['configurationItemCaptureTime']
            })
            evaluations.append(evaluation)
    
    # Send evaluations to AWS Config
    if evaluations:
        if DEBUG_MODE:
            logger.info("Sending %d evaluation(s) to AWS Config: %s", len(evaluations), json.dumps(evaluations, default=str))
        
        # Paginate evaluations (AWS Config limit is 100 per call)
        for i in range(0, len(evaluations), 100):
            chunk = evaluations[i:i + 100]
            config_client.put_evaluations(Evaluations=chunk, ResultToken=event['resultToken'])
    
    return evaluations

def evaluate_security_group(ec2_client, group_id):
    """
    Evaluate a security group for rules allowing traffic from/to 0.0.0.0/0.
    
    Parameters:
    - ec2_client: AWS EC2 client
    - group_id (str): ID of the security group
    
    Returns:
    - dict or None: Evaluation result if the security group exists, None if it doesn’t
    """
    if DEBUG_MODE:
        logger.info("Evaluating security group: %s", group_id)
    
    try:
        # First, confirm the security group exists
        response = ec2_client.describe_security_groups(GroupIds=[group_id])
        # If we reach here, the security group exists
        
        # Get the security group rules with their IDs
        rules_response = ec2_client.describe_security_group_rules(
            Filters=[{'Name': 'group-id', 'Values': [group_id]}]
        )
        rules = rules_response['SecurityGroupRules']
        
        # Check for rules allowing traffic from/to 0.0.0.0/0
        non_compliant_rules = []
        for rule in rules:
            if rule.get('CidrIpv4') == '0.0.0.0/0':
                rule_id = rule['SecurityGroupRuleId']
                direction = 'inbound' if not rule['IsEgress'] else 'outbound'
                non_compliant_rules.append((direction, rule_id))
        
        if non_compliant_rules:
            annotation = f"Security group {group_id} has non-compliant rules: "
            for direction, rule_id in non_compliant_rules:
                annotation += f"{direction} rule {rule_id}, "
            annotation = annotation.rstrip(', ')
            return {
                'ComplianceType': 'NON_COMPLIANT',
                'Annotation': annotation
            }
        else:
            return {
                'ComplianceType': 'COMPLIANT',
                'Annotation': f"Security group {group_id} does not have rules allowing traffic from/to 0.0.0.0/0."
            }
    
    except ec2_client.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidGroup.NotFound':
            if DEBUG_MODE:
                logger.info("Security group %s does not exist, skipping evaluation", group_id)
            return None  # Skip evaluation for non-existent security groups
        else:
            logger.error("Error evaluating security group %s: %s", group_id, str(e))
            return {
                'ComplianceType': 'INSUFFICIENT_DATA',
                'Annotation': f"Error: {str(e)[:200]}"
            }
    except Exception as e:
        logger.error("Unexpected error evaluating security group %s: %s", group_id, str(e))
        return {
            'ComplianceType': 'INSUFFICIENT_DATA',
            'Annotation': f"Unexpected error: {str(e)[:200]}"
        }
