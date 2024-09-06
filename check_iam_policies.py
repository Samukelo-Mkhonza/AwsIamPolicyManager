import boto3
import json

# Initialize IAM client and EC2 client in us-east-1 (default region)
iam_client = boto3.client('iam')
ec2_client = boto3.client('ec2')

# List of unsupported condition keys for CreateVolume and CopySnapshot actions
unsupported_condition_keys = [
    "ec2:ProductCode", "ec2:Encrypted", "ec2:VolumeSize",
    "ec2:ParentSnapshot", "ec2:Owner", "ec2:ParentVolume",
    "ec2:SnapshotTime"
]

def list_all_managed_policies():
    """List all managed IAM policies (both AWS and customer-managed) in the AWS account."""
    paginator = iam_client.get_paginator('list_policies')
    policy_iterator = paginator.paginate(Scope='All')  # 'All' includes AWS-managed and customer-managed policies
    policies = []

    for page in policy_iterator:
        policies.extend(page['Policies'])

    print(f"Total managed policies retrieved: {len(policies)}\n")
    return policies

def list_inline_policies(entity_type, entity_name):
    """List all inline policies attached to a specific user, group, or role."""
    policies = []
    try:
        if entity_type == 'user':
            response = iam_client.list_user_policies(UserName=entity_name)
            policies = response['PolicyNames']
        elif entity_type == 'group':
            response = iam_client.list_group_policies(GroupName=entity_name)
            policies = response['PolicyNames']
        elif entity_type == 'role':
            response = iam_client.list_role_policies(RoleName=entity_name)
            policies = response['PolicyNames']
    except Exception as e:
        print(f"Error listing inline policies for {entity_type} '{entity_name}': {str(e)}")

    return policies

def list_all_inline_policies():
    """List all inline policies for all users, groups, and roles in the AWS account."""
    # List all users
    users = iam_client.list_users()['Users']
    for user in users:
        list_inline_policies('user', user['UserName'])

    # List all groups
    groups = iam_client.list_groups()['Groups']
    for group in groups:
        list_inline_policies('group', group['GroupName'])

    # List all roles
    roles = iam_client.list_roles()['Roles']
    for role in roles:
        list_inline_policies('role', role['RoleName'])

def get_policy_version(policy_arn, version_id):
    """Retrieve the policy document for a specific version of an IAM policy."""
    try:
        response = iam_client.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=version_id
        )
        return response['PolicyVersion']['Document']
    except Exception as e:
        print(f"Error retrieving policy version for {policy_arn}: {str(e)}")
        return None

def find_unsupported_conditions_in_policy(policy_document):
    """Check if the policy document contains unsupported condition keys."""
    unsupported_conditions_found = []
    for statement in policy_document.get('Statement', []):
        if 'Condition' in statement:
            conditions = statement['Condition']
            for key in conditions.keys():
                if key in unsupported_condition_keys:
                    unsupported_conditions_found.append(key)
    return unsupported_conditions_found

def output_policies_with_unsupported_conditions():
    """Find and display IAM policies with unsupported condition keys."""
    policies = list_all_managed_policies()  # Include managed policies
    policies_with_unsupported_conditions = []

    for policy in policies:
        # Get the default policy version
        policy_arn = policy['Arn']
        default_version_id = policy['DefaultVersionId']
        policy_document = get_policy_version(policy_arn, default_version_id)

        if policy_document:
            # Check for unsupported conditions
            unsupported_conditions = find_unsupported_conditions_in_policy(policy_document)

            if unsupported_conditions:
                policies_with_unsupported_conditions.append({
                    'PolicyName': policy['PolicyName'],
                    'PolicyArn': policy_arn,
                    'UnsupportedConditions': list(set(unsupported_conditions))
                })

    # Output the policies with unsupported condition keys
    if policies_with_unsupported_conditions:
        print("Policies containing unsupported condition keys:")
        for policy in policies_with_unsupported_conditions:
            print(f"Policy Name: {policy['PolicyName']}")
            print(f"Policy ARN: {policy['PolicyArn']}")
            print(f"Unsupported Conditions: {', '.join(policy['UnsupportedConditions'])}")
            print("-" * 60)
    else:
        print("No policies found with unsupported condition keys.")

def get_all_regions():
    """Retrieve all AWS regions."""
    ec2 = boto3.client('ec2')
    response = ec2.describe_regions()
    return [region['RegionName'] for region in response['Regions']]

def query_cloudtrail_logs_for_unsupported_keys(region):
    """Query CloudTrail logs for unsupported condition keys in specific API calls."""
    cloudtrail_client = boto3.client('cloudtrail', region_name=region)
    
    try:
        # Lookup events for CreateVolume and CopySnapshot actions
        response = cloudtrail_client.lookup_events(
            LookupAttributes=[
                {'AttributeKey': 'EventName', 'AttributeValue': 'CreateVolume'},
                {'AttributeKey': 'EventName', 'AttributeValue': 'CopySnapshot'}
            ],
            MaxResults=1000
        )
        
        events = response['Events']
        unsupported_events = []
        
        for event in events:
            event_details = json.loads(event['CloudTrailEvent'])
            request_parameters = event_details.get('requestParameters', {})
            
            # Check for unsupported condition keys in the request parameters
            for key in unsupported_condition_keys:
                if key in request_parameters:
                    # Check if the event succeeded or failed
                    if 'errorCode' in event_details:
                        status = 'Failed'
                        error_message = event_details['errorCode']
                    else:
                        status = 'Succeeded'
                        error_message = 'None'
                    
                    unsupported_events.append({
                        'EventId': event['EventId'],
                        'EventName': event['EventName'],
                        'UnsupportedCondition': key,
                        'EventTime': event['EventTime'],
                        'Status': status,
                        'ErrorMessage': error_message
                    })

        return unsupported_events

    except Exception as e:
        print(f"Error querying CloudTrail logs in region {region}: {str(e)}")
        return []

def check_cloudtrail_logs():
    """Check CloudTrail logs in all regions for unsupported condition keys."""
    regions = get_all_regions()
    all_unsupported_events = []
    
    for region in regions:
        print(f"Checking CloudTrail logs in region: {region}")
        unsupported_events = query_cloudtrail_logs_for_unsupported_keys(region)
        if unsupported_events:
            all_unsupported_events.extend(unsupported_events)
    
    # Output the events with unsupported condition keys
    if all_unsupported_events:
        print("CloudTrail events with unsupported condition keys found:")
        for event in all_unsupported_events:
            print(f"Event ID: {event['EventId']}")
            print(f"Event Name: {event['EventName']}")
            print(f"Unsupported Condition: {event['UnsupportedCondition']}")
            print(f"Event Time: {event['EventTime']}")
            print(f"Status: {event['Status']}")
            print(f"Error Message: {event['ErrorMessage']}")
            print("-" * 60)
    else:
        print("No CloudTrail events with unsupported condition keys found across all regions.")

if __name__ == "__main__":
    # List all IAM policies
    list_all_managed_policies()
    list_all_inline_policies()

    # Output IAM policies with unsupported condition keys
    output_policies_with_unsupported_conditions()
    
    # Check CloudTrail logs for unsupported condition keys across all regions
    check_cloudtrail_logs()
