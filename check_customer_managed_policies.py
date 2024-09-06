import boto3
import json
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

# Initialize IAM client for the specific region (us-east-1)
region_name = 'us-east-1'
iam_client = boto3.client('iam', region_name=region_name)

# Actions to search for in policies
target_actions = ["ec2:CreateVolume", "ec2:CopySnapshot"]

def get_all_customer_managed_policies():
    """Retrieve all customer-managed IAM policies in the AWS account, filtering for relevant policies."""
    print("\033[92mLoading customer-managed IAM policies...\033[0m")  
    paginator = iam_client.get_paginator('list_policies')
    policy_iterator = paginator.paginate(Scope='Local')  # 'Local' includes only customer-managed policies
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

    print(f"Total relevant customer-managed policies found: {len(policies)}")
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

def get_users_with_policies(policies):
    """Retrieve all users who have any of the specific policies attached, along with their groups."""
    user_policies_map = defaultdict(lambda: {'policies': [], 'groups': []})  # Dictionary to store users, their associated policies, and groups

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

    return user_policies_map

def get_groups_for_user(user_name):
    """Retrieve groups for a specific user."""
    groups = []
    try:
        response = iam_client.list_groups_for_user(UserName=user_name)
        groups = [group['GroupName'] for group in response['Groups']]
    except Exception as e:
        print(f"Error retrieving groups for user {user_name}: {str(e)}")
    return groups

def output_policies_with_target_actions_and_users():
    """Find and display customer-managed IAM policies with target actions and associated users."""
    policies = get_all_customer_managed_policies()
    user_policies_map = get_users_with_policies(policies)

    print("\033[92mProcessing customer-managed policies to find users...\033[0m")  

    # Output the users with policies containing target actions
    if user_policies_map:
        print("Users with customer-managed policies containing target actions:")
        for user, info in user_policies_map.items():
            print(f"User: {user}")
            print(f"Number of Policies: {len(info['policies'])}")
            print(f"Policy Names: {', '.join(info['policies'])}")
            print(f"Groups: {', '.join(info['groups']) if info['groups'] else 'None'}")
            print("-" * 60)
    else:
        print("No users found with customer-managed policies containing target actions.")

if __name__ == "__main__":
    # Output customer-managed IAM policies with target actions and associated users
    print("\033[92mStarting search for customer-managed IAM policies with target actions...\033[0m")  
    output_policies_with_target_actions_and_users()
    print("\033[92mSearch completed.\033[0m")  
