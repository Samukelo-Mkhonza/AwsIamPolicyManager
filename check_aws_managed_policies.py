import boto3
import json
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

# Initialize IAM client for the specific region (us-east-1)
region_name = 'us-east-1'
iam_client = boto3.client('iam', region_name=region_name)

# Actions to search for in policies
target_actions = ["ec2:CreateVolume", "ec2:CopySnapshot"]

def get_all_aws_managed_policies():
    """Retrieve all AWS-managed IAM policies in the AWS account, filtering for relevant policies."""
    print("\033[92mLoading AWS-managed IAM policies...\033[0m") 
    paginator = iam_client.get_paginator('list_policies')
    policy_iterator = paginator.paginate(Scope='AWS')  # 'AWS' includes only AWS-managed policies
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

    print(f"Total relevant AWS-managed policies found: {len(policies)}")
    return policies

def normalize_actions(actions):
    """
    Normalize actions to a list format.
    """
    if isinstance(actions, str):
        return [actions]  # Convert single string to a list
    elif isinstance(actions, list):
        return actions  # Already a list
    else:
        return []  # If it's neither a string nor a list, return an empty list

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

def get_users_with_policy(policy_arn):
    """Retrieve all users who have a specific AWS-managed policy attached."""
    print(f"Searching for users with policy: {policy_arn}")
    users = []
    try:
        response = iam_client.list_entities_for_policy(PolicyArn=policy_arn, EntityFilter='User')
        users = [user['UserName'] for user in response['PolicyUsers']]
        print(f"Found {len(users)} users with policy: {policy_arn}")
    except Exception as e:
        print(f"Error retrieving users for policy {policy_arn}: {str(e)}")
    return users

def output_policies_with_target_actions_and_users():
    """Find and display AWS-managed IAM policies with target actions and associated users."""
    policies = get_all_aws_managed_policies()
    policies_with_target_actions = []

    print("\033[92mProcessing AWS-managed policies to find users...\033[0m")  #  
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
        print("AWS-managed policies containing target actions and associated users:")
        for policy in policies_with_target_actions:
            print(f"Policy Name: {policy['PolicyName']}")
            print(f"Policy ARN: {policy['PolicyArn']}")
            
            # Find users with this managed policy attached
            users = get_users_with_policy(policy['PolicyArn'])
            if users:
                print(f"Users with this policy: {', '.join(users)}")
            print("-" * 60)
    else:
        print("No AWS-managed policies found with target actions.")

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
    # Output AWS-managed IAM policies with target actions and associated users
    print("\033[92mStarting search for AWS-managed IAM policies with target actions...\033[0m")  #  
    output_policies_with_target_actions_and_users()
    print("\033[92mSearch completed.\033[0m")  
