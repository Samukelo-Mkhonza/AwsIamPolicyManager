import boto3
import json
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

# Initialize IAM client and CloudTrail client for the specific region (us-east-1)
region_name = 'us-east-1'
iam_client = boto3.client('iam', region_name=region_name)
cloudtrail_client = boto3.client('cloudtrail', region_name=region_name)

# Actions to search for in policies
target_actions = ["ec2:CreateVolume", "ec2:CopySnapshot"]

def get_all_managed_policies():
    """Retrieve all managed IAM policies in the AWS account, filtering for relevant policies."""
    print("Loading managed IAM policies...")
    paginator = iam_client.get_paginator('list_policies')
    policy_iterator = paginator.paginate(Scope='All')  # Include both AWS-managed and customer-managed policies
    policies = []

    for page in policy_iterator:
        for policy in page['Policies']:
            # Only include policies that are relevant to the target actions
            policy_arn = policy['Arn']
            default_version_id = policy['DefaultVersionId']
            policy_document = get_policy_version(policy_arn, default_version_id)
            if contains_target_actions(policy_document):
                policies.append(policy)
                print(f"Found relevant policy: {policy['PolicyName']}")

    print(f"Total relevant managed policies found: {len(policies)}")
    return policies

def normalize_actions(actions):
    """
    Normalize actions to a list format.
    """
    if isinstance(actions, str):
        return [actions]
    elif isinstance(actions, list):
        return actions
    else:
        return []

def contains_target_actions(policy_document):
    """Check if the policy document contains the target actions (ec2:CreateVolume, ec2:CopySnapshot)."""
    for statement in policy_document.get('Statement', []):
        # Ensure 'statement' is a dictionary
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
        elif isinstance(statement, str) or isinstance(statement, list):
            # Skip known valid formats like strings or lists
            continue
        else:
            # Print debug information only for truly unexpected formats
            print(f"Unexpected format in policy statement: {statement}")
    return False

def convert_datetime_to_string(obj):
    """
    Helper function to convert datetime objects to strings within a dictionary.
    """
    if isinstance(obj, dict):
        return {k: convert_datetime_to_string(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_datetime_to_string(element) for element in obj]
    elif isinstance(obj, datetime):
        return obj.isoformat()
    else:
        return obj

def get_policy_version(policy_arn, version_id):
    """Retrieve the policy document for a specific version of an IAM policy."""
    response = iam_client.get_policy_version(
        PolicyArn=policy_arn,
        VersionId=version_id
    )
    return response['PolicyVersion']['Document']

def get_users_with_policy(policy_arn):
    """Retrieve all users who have a specific managed policy attached."""
    print(f"Searching for users with policy: {policy_arn}")
    users = []
    try:
        response = iam_client.list_entities_for_policy(PolicyArn=policy_arn, EntityFilter='User')
        users = [user['UserName'] for user in response['PolicyUsers']]
        print(f"Found {len(users)} users with policy: {policy_arn}")
    except Exception as e:
        print(f"Error retrieving users for policy {policy_arn}: {str(e)}")
    return users

def check_user_inline_policies(user_name):
    """Check inline policies for a specific user for the target actions."""
    print(f"Checking inline policies for user: {user_name}")
    try:
        response = iam_client.list_user_policies(UserName=user_name)
        inline_policies = response['PolicyNames']

        for policy_name in inline_policies:
            policy_document = iam_client.get_user_policy(UserName=user_name, PolicyName=policy_name)['PolicyDocument']
            if contains_target_actions(policy_document):
                print(f"Found inline policy with target actions for user: {user_name}")
                return {
                    'UserName': user_name,
                    'InlinePolicyName': policy_name,
                    'Actions': target_actions
                }
    except Exception as e:
        print(f"Error retrieving inline policies for user {user_name}: {str(e)}")
    return None

def output_policies_with_target_actions_and_users():
    """Find and display IAM policies with target actions and associated users."""
    policies = get_all_managed_policies()
    policies_with_target_actions = []

    print("Processing policies to find users...")
    # Use threading to process policies concurrently
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(process_policy, policy): policy for policy in policies}
        
        for future in as_completed(futures):
            policy = futures[future]
            try:
                result = future.result()
                if result:
                    policies_with_target_actions.append(result)
            except Exception as e:
                print(f"Error processing policy {policy['PolicyName']}: {str(e)}")

    # Output the policies with target actions and associated users
    if policies_with_target_actions:
        print("Policies containing target actions and associated users:")
        for policy in policies_with_target_actions:
            print(f"Policy Name: {policy['PolicyName']}")
            print(f"Policy ARN: {policy['PolicyArn']}")
            
            # Find users with this managed policy attached
            users = get_users_with_policy(policy['PolicyArn'])
            if users:
                print(f"Users with this policy: {', '.join(users)}")
            
            # Check for inline policies for each user
            for user in users:
                user_inline_policy = check_user_inline_policies(user)
                if user_inline_policy:
                    print(f"User '{user}' has inline policy '{user_inline_policy['InlinePolicyName']}' with target actions: {', '.join(user_inline_policy['Actions'])}")
            
            print("-" * 60)
    else:
        print("No policies found with target actions.")

def process_policy(policy):
    """Process each policy to check for target actions."""
    policy_arn = policy['Arn']
    default_version_id = policy['DefaultVersionId']
    policy_document = get_policy_version(policy_arn, default_version_id)

    # Check for target actions
    if contains_target_actions(policy_document):
        return {
            'PolicyName': policy['PolicyName'],
            'PolicyArn': policy_arn
        }
    return None

if __name__ == "__main__":
    # Output IAM policies with target actions and associated users
    print("Starting search for IAM policies with target actions...")
    output_policies_with_target_actions_and_users()
    print("Search completed.")
