import boto3
import json
import logging
from datetime import datetime

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

DEBUG_MODE = False

def lambda_handler(event, context):
    global DEBUG_MODE
    rule_parameters = json.loads(event.get('ruleParameters', '{}'))
    logger.info("Rule parameters: %s", rule_parameters)
    DEBUG_MODE_str = rule_parameters.get('DEBUG_MODE', str(DEBUG_MODE))
    DEBUG_MODE = DEBUG_MODE_str.lower() == 'true'
  
    if DEBUG_MODE:
        logger.info(json.dumps({"DEBUG_MODE": DEBUG_MODE}))  # Now this will show the updated value        
        logger.info(f"Lambda invoked at {datetime.now().isoformat()}")
        logger.info(f"Event: {json.dumps(event)}")
        logger.info(f"Context: {context.function_name}, {context.aws_request_id}")
    
    config_client = boto3.client('config')
    ec2_client = boto3.client('ec2')
    invoking_event = json.loads(event['invokingEvent'])
    remediate = rule_parameters.get('remediate', 'False').lower() == 'true'
    is_scheduled = invoking_event.get('messageType') == 'ScheduledNotification'
    evaluations = []

    if is_scheduled:
        response = ec2_client.describe_security_groups()
        for sg in response['SecurityGroups']:
            should_evaluate, should_remediate = check_tags(ec2_client, sg['GroupId'])
            evaluation = evaluate_security_group(ec2_client, sg['GroupId'], should_remediate and remediate)
            if evaluation:
                evaluation['OrderingTimestamp'] = invoking_event['notificationCreationTime']
                evaluations.append(evaluation)
    else:
        config_item = invoking_event.get('configurationItem', {})
        if config_item.get('resourceType') == 'AWS::EC2::SecurityGroup':
            group_id = config_item['resourceId']
            should_evaluate, should_remediate = check_tags(ec2_client, group_id)
            evaluation = evaluate_security_group(ec2_client, group_id, should_remediate and remediate)
            if evaluation:
                evaluation['OrderingTimestamp'] = config_item['configurationItemCaptureTime']
                evaluations.append(evaluation)
    
    if evaluations:
        config_client.put_evaluations(Evaluations=evaluations, ResultToken=event['resultToken'])
    
    return evaluations

def check_tags(ec2_client, group_id):
    try:
        response = ec2_client.describe_tags(Filters=[
            {'Name': 'resource-id', 'Values': [group_id]},
            {'Name': 'key', 'Values': ['applysecuritygrouprule']}
        ])
        for tag in response.get('Tags', []):
            if tag.get('Value', '').lower() == 'false':
                return True, False  # Evaluate, but do not remediate
        return True, True  # Evaluate and remediate
    except Exception as e:
        return True, True  # Default to evaluating and remediating

def evaluate_security_group(ec2_client, group_id, remediate):
    try:
        response = ec2_client.describe_security_group_rules(Filters=[{'Name': 'group-id', 'Values': [group_id]}])
        rules = response['SecurityGroupRules']
        non_compliant_rules = [rule for rule in rules if rule.get('CidrIpv4') == '0.0.0.0/0']
        
        if non_compliant_rules:
            if remediate:
                for rule in non_compliant_rules:
                    ec2_client.revoke_security_group_ingress(GroupId=group_id, SecurityGroupRuleIds=[rule['SecurityGroupRuleId']])
            return {
                'ComplianceType': 'NON_COMPLIANT' if non_compliant_rules else 'COMPLIANT',
                'ComplianceResourceType': 'AWS::EC2::SecurityGroup',
                'ComplianceResourceId': group_id,
                'Annotation': 'Non-compliant rules found and remediated' if remediate else 'Non-compliant rules found'
            }
        
        return {
            'ComplianceType': 'COMPLIANT',
            'ComplianceResourceType': 'AWS::EC2::SecurityGroup',
            'ComplianceResourceId': group_id,
            'Annotation': 'No non-compliant rules found'
        }
    except Exception as e:
        return {
            'ComplianceType': 'NOT_APPLICABLE',
            'ComplianceResourceType': 'AWS::EC2::SecurityGroup',
            'ComplianceResourceId': group_id,
            'Annotation': f"Error: {str(e)[:200]}"
        }
