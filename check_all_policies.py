import boto3
import json
from datetime import datetime, timedelta
from collections import defaultdict

# Initialize IAM and CloudTrail clients for the specific region (us-east-1)
region_name = 'us-east-1'
iam_client = boto3.client('iam', region_name=region_name)
cloudtrail_client = boto3.client('cloudtrail', region_name=region_name)

# Actions to search for in policies
target_actions = ["ec2:CreateVolume", "ec2:CopySnapshot"]

# List of unsupported condition keys for CreateVolume and CopySnapshot actions
unsupported_condition_keys = [
    "ec2:ProductCode", "ec2:Encrypted", "ec2:VolumeSize", 
    "ec2:ParentSnapshot", "ec2:Owner", "ec2:ParentVolume", 
    "ec2:SnapshotTime"
]

def get_all_policies():
    """Retrieve all IAM policies in the AWS account (customer-managed, AWS-managed, and job function-managed), filtering for relevant policies."""
    print("\033[92mLoading all IAM policies (customer-managed, AWS-managed, and job function-managed)...\033[0m")  
    paginator = iam_client.get_paginator('list_policies')
    policy_iterator = paginator.paginate(Scope='All')
    policies = []

    for page in policy_iterator:
        for policy in page['Policies']:
            policy_arn = policy['Arn']
            default_version_id = policy['DefaultVersionId']
            policy_document = get_policy_version(policy_arn, default_version_id)
            if contains_target_actions(policy_document):
                policies.append(policy)
                print(f"Found relevant policy: {policy['PolicyName']}")

    print(f"Total relevant IAM policies found: {len(policies)}")
    print("-" * 60)
    return policies

def normalize_actions(actions):
    """Normalize actions to a list format."""
    if isinstance(actions, str):
        return [actions]  
    elif isinstance(actions, list):
        return actions  
    else:
        return []  

def contains_target_actions(policy_document):
    """Check if the policy document contains the target actions (ec2:CreateVolume, ec2:CopySnapshot)."""
    for statement in policy_document.get('Statement', []):
        if isinstance(statement, dict):
            actions = statement.get('Action', [])
            actions = normalize_actions(actions)

            # Handle wildcard actions (*)
            if '*' in actions:
                print("Policy contains a wildcard action (*) which includes all actions.")
                return True

            # Check if any of the target actions are in the policy's actions
            if any(action in target_actions for action in actions):
                return True
    return False

def get_policy_version(policy_arn, version_id):
    """Retrieve the policy document for a specific version of an IAM policy."""
    response = iam_client.get_policy_version(
        PolicyArn=policy_arn,
        VersionId=version_id
    )
    return response['PolicyVersion']['Document']

def query_cloudtrail_logs():
    """Query CloudTrail logs for unsupported condition keys in specific API calls."""
    print("\033[92mSearching CloudTrail logs for unsupported condition keys...\033[0m")  
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
                        'User': event_details['userIdentity'].get('arn', 'Unknown'),
                        'UnsupportedCondition': key,
                        'EventTime': event['EventTime'],
                        'Status': status,
                        'ErrorMessage': error_message
                    })

        # Output the CloudTrail events with unsupported condition keys
        if unsupported_events:
            print("CloudTrail events with unsupported condition keys found:")
            for event in unsupported_events:
                print(f"Event ID: {event['EventId']}")
                print(f"Event Name: {event['EventName']}")
                print(f"User: {event['User']}")
                print(f"Unsupported Condition: {event['UnsupportedCondition']}")
                print(f"Event Time: {event['EventTime']}")
                print(f"Status: {event['Status']}")
                print(f"Error Message: {event['ErrorMessage']}")
                print("-" * 60)
        else:
            print("No CloudTrail events with unsupported condition keys found.")
            print("-" * 60)

    except Exception as e:
        print(f"Error querying CloudTrail logs: {str(e)}")
        print("-" * 60)

def get_users_with_policies(policies):
    """Retrieve all users who have any of the specific policies attached, along with their groups."""
    user_policies_map = defaultdict(lambda: {'policies': [], 'groups': []}) 

    for policy in policies:
        policy_arn = policy['Arn']
        try:
            response = iam_client.list_entities_for_policy(PolicyArn=policy_arn, EntityFilter='User')
            users = [user['UserName'] for user in response['PolicyUsers']]
            for user in users:
                user_policies_map[user]['policies'].append(policy['PolicyName'])
                # Get groups for each user
                groups = get_groups_for_user(user)
                user_policies_map[user]['groups'] = groups
        except Exception as e:
            print(f"Error retrieving users for policy {policy_arn}: {str(e)}")
            print("-" * 60)

    return user_policies_map

def get_groups_for_user(user_name):
    """Retrieve groups for a specific user."""
    groups = []
    try:
        response = iam_client.list_groups_for_user(UserName=user_name)
        groups = [group['GroupName'] for group in response['Groups']]
    except Exception as e:
        print(f"Error retrieving groups for user {user_name}: {str(e)}")
        print("-" * 60)
    return groups

def output_users_with_policies(user_policies_map):
    """Display users with policies containing unsupported keys and their groups."""
    print("\033[92mProcessing all IAM policies to find users...\033[0m")  

    # Output the users with policies containing target actions
    if user_policies_map:
        print("Users with IAM policies containing target actions:")
        for user, info in user_policies_map.items():
            print(f"User: {user}")
            print(f"Number of Policies: {len(info['policies'])}")
            print(f"Policy Names: {', '.join(info['policies'])}")
            print(f"Groups: {', '.join(info['groups']) if info['groups'] else 'None'}")
            print("-" * 60)
    else:
        print("No users found with IAM policies containing target actions.")
        print("-" * 60)

if __name__ == "__main__":
    # Output all IAM policies with target actions
    print("\033[92mStarting search for all IAM policies with target actions...\033[0m")  
    policies = get_all_policies()
    
    # Search CloudTrail logs for events with unsupported condition keys
    query_cloudtrail_logs()

    # Output users with policies containing unsupported keys
    user_policies_map = get_users_with_policies(policies)
    output_users_with_policies(user_policies_map)
    
    print("\033[92mSearch completed.\033[0m")  
    print("-" * 60)
