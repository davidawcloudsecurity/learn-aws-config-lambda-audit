import boto3
import json
import logging

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """
    AWS Lambda function to evaluate and optionally remediate security groups.
    Works with AWS Config to report compliance.
    Test with remediate=true in a safe environment to confirm rules are removed.
    Test with remediate=false to verify evaluation without changes.
    """
    # Initialize AWS clients
    config_client = boto3.client('config')
    ec2_client = boto3.client('ec2')

    # Parse event data
    invoking_event = json.loads(event['invokingEvent'])
    rule_parameters = json.loads(event.get('ruleParameters', '{}'))
    remediate = rule_parameters.get('remediate', False)  # Remediation flag (default: False)
    is_scheduled = invoking_event.get('messageType') == 'ScheduledNotification'

    evaluations = []

    if is_scheduled:
        # Evaluate all security groups for scheduled events
        response = ec2_client.describe_security_groups()
        for sg in response['SecurityGroups']:
            evaluation = evaluate_and_remediate(ec2_client, sg['GroupId'], remediate)
            if evaluation:
                evaluation.update({
                    'ComplianceResourceType': 'AWS::EC2::SecurityGroup',
                    'ComplianceResourceId': sg['GroupId'],
                    'OrderingTimestamp': invoking_event['notificationCreationTime']
                })
                evaluations.append(evaluation)
    else:
        # Evaluate a specific security group for configuration changes
        config_item = invoking_event.get('configurationItem', {})
        if config_item.get('resourceType') == 'AWS::EC2::SecurityGroup':
            group_id = config_item['resourceId']
            evaluation = evaluate_and_remediate(ec2_client, group_id, remediate)
            if evaluation:
                evaluation.update({
                    'ComplianceResourceType': 'AWS::EC2::SecurityGroup',
                    'ComplianceResourceId': group_id,
                    'OrderingTimestamp': config_item['configurationItemCaptureTime']
                })
                evaluations.append(evaluation)

    # Send evaluations to AWS Config
    if evaluations:
        config_client.put_evaluations(Evaluations=evaluations, ResultToken=event['resultToken'])

    return evaluations

def evaluate_and_remediate(ec2_client, group_id, remediate):
    """
    Evaluate a security group and optionally remediate non-compliant rules.
    """
    try:
        # Fetch security group rules
        response = ec2_client.describe_security_group_rules(
            Filters=[{'Name': 'group-id', 'Values': [group_id]}]
        )
        rules = response['SecurityGroupRules']

        # Check for non-compliant rules (0.0.0.0/0)
        non_compliant_rules = []
        for rule in rules:
            if rule.get('CidrIpv4') == '0.0.0.0/0':
                direction = 'inbound' if not rule['IsEgress'] else 'outbound'
                non_compliant_rules.append((direction, rule['SecurityGroupRuleId']))

        if non_compliant_rules:
            annotation = f"Non-compliant rules found in {group_id}: {len(non_compliant_rules)} rules"
            if remediate:
                # Remediate by removing non-compliant rules
                for direction, rule_id in non_compliant_rules:
                    if direction == 'inbound':
                        ec2_client.revoke_security_group_ingress(GroupId=group_id, SecurityGroupRuleIds=[rule_id])
                    else:
                        ec2_client.revoke_security_group_egress(GroupId=group_id, SecurityGroupRuleIds=[rule_id])
                return {
                    'ComplianceType': 'COMPLIANT',
                    'Annotation': f"Remediated {group_id} by removing non-compliant rules."
                }
            return {
                'ComplianceType': 'NON_COMPLIANT',
                'Annotation': annotation
            }
        return {
            'ComplianceType': 'COMPLIANT',
            'Annotation': f"{group_id} has no rules allowing 0.0.0.0/0."
        }

    except ec2_client.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidGroup.NotFound':
            return None  # Skip non-existent security groups
        logger.error(f"Error evaluating {group_id}: {str(e)}")
        return {
            'ComplianceType': 'INSUFFICIENT_DATA',
            'Annotation': f"Error: {str(e)[:200]}"
        }
