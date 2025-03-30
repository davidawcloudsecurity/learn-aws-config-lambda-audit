![image](https://github.com/user-attachments/assets/299320f0-5e03-4773-a5f1-e0888d4697c2)
# learn-aws-config-lambda-rule
How to create lambda rule with aws config

Yes, I understand this code! It's a more sophisticated version of the S3 public access check that also evaluates bucket policies and ACLs. Let's create a **generalized template** that can be adapted for other AWS resource checks with AWS Config + Lambda.

---

### **Generic AWS Config Compliance Check Template**
```python
import boto3
import json
import logging
import sys
from datetime import datetime

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ========== USER CONFIGURATION ==========
DEBUG_MODE = True  # Toggle debug logging
TARGET_RESOURCE_TYPE = "AWS::S3::Bucket"  # <-- CHANGE ME for other resources
RULE_PARAMETERS = {}  # <-- ADD any rule parameters here
# ========================================

def lambda_handler(event, context):
    """
    Generic AWS Config compliance checker
    """
    if DEBUG_MODE:
        logger.info("Received event: %s", json.dumps(event))

    config_client = boto3.client('config')
    aws_client = boto3.client('s3')  # <-- CHANGE ME to appropriate AWS service client

    invoking_event = json.loads(event['invokingEvent'])
    rule_params = json.loads(event.get('ruleParameters', '{}'))
    
    evaluations = []
    is_scheduled = invoking_event.get('messageType') == 'ScheduledNotification'

    if is_scheduled:
        # Evaluate all resources of target type
        try:
            resources = get_all_resources(aws_client)  # <-- IMPLEMENT RESOURCE LISTING
            for resource in resources:
                evaluation = evaluate_resource(aws_client, resource, rule_params)
                evaluation.update({
                    'ComplianceResourceType': TARGET_RESOURCE_TYPE,
                    'ComplianceResourceId': resource['Identifier'],
                    'OrderingTimestamp': invoking_event['notificationCreationTime']
                })
                evaluations.append(evaluation)
        except Exception as e:
            logger.error("Error listing resources: %s", str(e))
            raise
    else:
        # Evaluate specific changed resource
        config_item = invoking_event.get('configurationItem') or invoking_event.get('configurationItemSummary', {})
        
        if config_item.get('resourceType') != TARGET_RESOURCE_TYPE:
            config_client.put_evaluations(Evaluations=[], ResultToken=event['resultToken'])
            return []

        evaluation = evaluate_resource(aws_client, config_item, rule_params)
        evaluation.update({
            'ComplianceResourceType': config_item['resourceType'],
            'ComplianceResourceId': config_item['resourceId'],
            'OrderingTimestamp': config_item['configurationItemCaptureTime']
        })
        evaluations.append(evaluation)

    # Submit evaluations with pagination
    if evaluations:
        for chunk in [evaluations[i:i+100] for i in range(0, len(evaluations), 100)]:
            config_client.put_evaluations(
                Evaluations=chunk,
                ResultToken=event['resultToken']
            )

    return evaluations

# ========== USER IMPLEMENTATION ==========
def get_all_resources(client):
    """
    Implement resource enumeration for scheduled evaluations
    Returns: List of resource identifiers (dicts with 'Identifier' and other needed fields)
    """
    # EXAMPLE FOR S3:
    # buckets = client.list_buckets()['Buckets']
    # return [{'Identifier': b['Name']} for b in buckets]
    raise NotImplementedError("Implement resource listing")

def evaluate_resource(client, resource, rule_params):
    """
    Implement your compliance logic here
    Returns: {
        'ComplianceType': 'COMPLIANT'|'NON_COMPLIANT'|'NOT_APPLICABLE',
        'Annotation': 'Reason for compliance status'
    }
    """
    try:
        # ===== YOUR COMPLIANCE CHECKS HERE =====
        # Example for S3:
        # public_access = client.get_public_access_block(Bucket=resource['Identifier'])
        # ... evaluation logic ...
        # return {'ComplianceType': 'COMPLIANT', 'Annotation': '...'}
        
        raise NotImplementedError("Implement compliance checks")
    
    except client.exceptions.ResourceNotFoundException:
        return {'ComplianceType': 'NOT_APPLICABLE', 'Annotation': 'Resource no longer exists'}
    except Exception as e:
        logger.error("Evaluation error: %s", str(e))
        return {  # CHANGED FROM 'ERROR' TO 'NON_COMPLIANT'
            'ComplianceType': 'NON_COMPLIANT',  # or 'NOT_APPLICABLE' if appropriate
            'Annotation': f"Error checking encryption: {str(e)}"
        }
```

---

### **How to Use This Template**
1. **Change Service Client**  
   Replace `boto3.client('s3')` with the appropriate client for your resource (e.g., `ec2`, `iam`, etc.)

2. **Implement Two Core Functions**  
   - `get_all_resources()`: How to list all resources of your target type
   - `evaluate_resource()`: Your compliance logic for individual resources

3. **Set Resource Type**  
   Update `TARGET_RESOURCE_TYPE` to match the AWS resource type you're checking

4. **(Optional) Add Rule Parameters**  
   Use the `rule_params` argument in `evaluate_resource()` if your rule needs configurable settings

---

### **Example Implementation Checklist**
1. Update IAM permissions in Terraform for your target service
2. Replace all S3-specific code with your resource's API calls
3. Handle resource-specific exceptions in `evaluate_resource`
4. Update AWS Config rule scope in Terraform:
   ```terraform
   scope {
     compliance_resource_types = ["AWS::YOUR::SERVICE::HERE"]
   }
   ```

---

### **Key Benefits**
1. **Handles Both Evaluation Modes**  
   - Scheduled periodic checks
   - Configuration change triggers

2. **Built-in Error Handling**  
   - Resource not found handling
   - Error logging and reporting

3. **Pagination Support**  
   Automatically handles >100 evaluations

4. **Debug Mode**  
   Toggle verbose logging with `DEBUG_MODE`

This template provides the scaffolding while letting you focus on the resource-specific compliance logic. Would you like me to show a concrete example for a different AWS service (e.g., check for unencrypted RDS instances)?
