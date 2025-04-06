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
    AWS Lambda function that checks security groups for public access configurations.

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
    ec2_client = boto3.client('ec2')

    # Extract information from the event
    invoking_event = json.loads(event['invokingEvent'])
    rule_parameters = {}
    if 'ruleParameters' in event and event['ruleParameters']:
        rule_parameters = json.loads(event['ruleParameters'])

    # Check if this is a scheduled notification or resource change notification
    is_scheduled_notification = invoking_event.get('messageType') == 'ScheduledNotification'

    evaluations = []

    # For scheduled notifications, evaluate all applicable security groups
    if is_scheduled_notification:
        if DEBUG_MODE:
            logger.info("Processing scheduled notification")

        # Get list of all security groups
        try:
            security_groups = ec2_client.describe_security_groups()
            for security_group in security_groups['SecurityGroups']:
                evaluation = evaluate_security_group(ec2_client, security_group, rule_parameters)

                # Add the security group resource info to the evaluation
                evaluation['ComplianceResourceType'] = 'AWS::EC2::SecurityGroup'
                evaluation['ComplianceResourceId'] = security_group['GroupId']
                evaluation['OrderingTimestamp'] = invoking_event['notificationCreationTime']

                evaluations.append(evaluation)

                if DEBUG_MODE:
                    logger.info("Evaluated security group %s: %s", security_group['GroupId'], evaluation['ComplianceType'])
        except Exception as e:
            logger.error("Error listing security groups: %s", str(e))
            raise

    # For configuration change, evaluate the specific security group
    else:
        configuration_item = invoking_event.get('configificationItem')
        if not configuration_item:
            configuration_item = invoking_event.get('configificationItemSummary', {})

        if DEBUG_MODE:
            logger.info("Processing configuration change for resource: %s", json.dumps(configuration_item))

        # Check if this is a security group
        if configuration_item.get('resourceType') != 'AWS::EC2::SecurityGroup':
            if DEBUG_MODE:
                logger.info("Resource is not a security group, skipping evaluation")
            # Return empty evaluation for non-security group resources
            config_client.put_evaluations(
                Evaluations=[],
                ResultToken=event['resultToken']
            )
            return

        security_group_id = configuration_item['resourceId']
        security_group = ec2_client.describe_security_groups(GroupIds=[security_group_id])['SecurityGroups'][0]
        evaluation = evaluate_security_group(ec2_client, security_group, rule_parameters)

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

def evaluate_security_group(ec2_client, security_group, rule_parameters):
    """
    Evaluate a security group for public access configuration.

    Parameters:
    ec2_client: AWS EC2 client
    security_group (dict): Security group information
    rule_parameters (dict): Rule parameters from the event

    Returns:
    dict: Evaluation result
    """
    if DEBUG_MODE:
        logger.info("Evaluating security group: %s", security_group['GroupId'])

    try:
        # Check the security group's IP permissions
        ip_permissions = security_group['IpPermissions']

        # Get the authorized ports from the rule parameters
        authorized_ports = get_authorized_ports(rule_parameters)

        # Check for public access (0.0.0.0/0 or ::/0)
        for ip_permission in ip_permissions:
            for ip_range in ip_permission['IpRanges']:
                if ip_range['CidrIp'] == '0.0.0.0/0':
                    if not is_authorized_port(ip_permission, authorized_ports):
                        return {
                            'ComplianceType': 'NON_COMPLIANT',
                            'Annotation': f"Security group {security_group['GroupId']} has 0.0.0.0/0 access with unauthorized ports."
                        }
            for ipv6_range in ip_permission['Ipv6Ranges']:
                if ipv6_range['CidrIpv6'] == '::/0':
                    if not is_authorized_port(ip_permission, authorized_ports):
                        return {
                            'ComplianceType': 'NON_COMPLIANT',
                            'Annotation': f"Security group {security_group['GroupId']} has ::/0 access with unauthorized ports."
                        }

        # If we've passed the check, the security group is compliant
        return {
            'ComplianceType': 'COMPLIANT',
            'Annotation': f"Security group {security_group['GroupId']} does not have public access enabled or has authorized ports."
        }

    except Exception as e:
        logger.error("Error evaluating security group %s: %s", security_group['GroupId'], str(e))
        # Change ERROR to INSUFFICIENT_DATA and limit annotation length
        return {
            'ComplianceType': 'INSUFFICIENT_DATA',
            'Annotation': f"Error evaluating compliance: {str(e)[:200]}"
        }

def get_authorized_ports(rule_parameters):
    """
    Get the authorized ports from the rule parameters.

    Parameters:
    rule_parameters (dict): Rule parameters from the event

    Returns:
    list: Authorized ports
    """
    authorized_ports = []
    if 'authorizedPorts' in rule_parameters:
        authorized_ports = [int(port) for port in rule_parameters['authorizedPorts'].split(',')]
    return authorized_ports

def is_authorized_port(ip_permission, authorized_ports):
    """
    Check if the IP permission is for an authorized port.

    Parameters:
    ip_permission (dict): IP permission information
    authorized_ports (list): Authorized ports

    Returns:
    bool: True if the port is authorized, False otherwise
    """
    for port_range in ip_permission['FromPort'], ip_permission['ToPort']:
        if port_range not in authorized_ports:
            return False
    return True
