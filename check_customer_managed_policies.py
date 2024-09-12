import boto3
import json
import csv
from io import StringIO
from datetime import datetime, timedelta, timezone
from collections import defaultdict

# Actions to search for in policies
target_actions = ["ec2:CreateVolume", "ec2:CopySnapshot"]

# List of unsupported condition keys for CreateVolume and CopySnapshot actions
unsupported_condition_keys = [
    "ec2:ProductCode", "ec2:Encrypted", "ec2:VolumeSize", 
    "ec2:ParentSnapshot", "ec2:Owner", "ec2:ParentVolume", 
    "ec2:SnapshotTime"
]

def get_all_regions():
    """Retrieve a list of all AWS regions."""
    ec2 = boto3.client('ec2')
    response = ec2.describe_regions()
    return [region['RegionName'] for region in response['Regions']]

def get_iam_client(region_name):
    """Initialize IAM client for a specific region."""
    return boto3.client('iam', region_name=region_name)

def get_cloudtrail_client(region_name):
    """Initialize CloudTrail client for a specific region."""
    return boto3.client('cloudtrail', region_name=region_name)

def get_s3_client():
    """Initialize S3 client."""
    return boto3.client('s3')

def get_all_customer_managed_policies(iam_client):
    """Retrieve all customer-managed IAM policies in the AWS account, filtering for relevant policies."""
    print("\033[92mLoading customer-managed IAM policies...\033[0m")
    paginator = iam_client.get_paginator('list_policies')
    policy_iterator = paginator.paginate(Scope='Local')
    policies = []

    for page in policy_iterator:
        for policy in page['Policies']:
            policy_arn = policy['Arn']
            default_version_id = policy['DefaultVersionId']
            policy_document = get_policy_version(iam_client, policy_arn, default_version_id)
            if contains_target_actions(policy_document):
                policies.append(policy)
                print(f"Found relevant policy: {policy['PolicyName']}")

    print(f"Total relevant customer-managed policies found: {len(policies)}")
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
    """Check if the policy document contains the target actions and unsupported condition keys."""
    unsupported_conditions_found = []

    for statement in policy_document.get('Statement', []):
        if isinstance(statement, dict):
            actions = statement.get('Action', [])
            actions = normalize_actions(actions)

            if '*' in actions:
                print("Policy contains a wildcard action (*) which includes all actions.")
                return True

            if any(action in target_actions for action in actions):
                print(f"Found target action(s) in policy statement: {actions}")
                
                condition = statement.get('Condition', {})
                if check_unsupported_conditions(condition, unsupported_conditions_found):
                    print(f"Found unsupported condition key(s) in policy statement: {unsupported_conditions_found}")
                    return True

    return False

def check_unsupported_conditions(condition, unsupported_conditions_found):
    """Check if any unsupported condition keys are present in the policy statement's 'Condition'."""
    if not condition:
        return False

    for condition_key, condition_value in condition.items():
        for key in condition_value.keys():
            if key in unsupported_condition_keys:
                unsupported_conditions_found.append(key)
                return True
    return False

def get_policy_version(iam_client, policy_arn, version_id):
    """Retrieve the policy document for a specific version of an IAM policy."""
    response = iam_client.get_policy_version(
        PolicyArn=policy_arn,
        VersionId=version_id
    )
    return response['PolicyVersion']['Document']

def query_cloudtrail_logs(cloudtrail_client):
    """Query CloudTrail logs for unsupported condition keys in specific API calls."""
    print("\033[92mSearching CloudTrail logs for unsupported condition keys...\033[0m")
    unsupported_events = []
    try:
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=90)
        
        response = cloudtrail_client.lookup_events(
            LookupAttributes=[
                {'AttributeKey': 'EventName', 'AttributeValue': 'CreateVolume'},
                {'AttributeKey': 'EventName', 'AttributeValue': 'CopySnapshot'}
            ],
            StartTime=start_time,
            EndTime=end_time,
            MaxResults=1000
        )
        
        events = response['Events']

        if not events:
            print("No events found in CloudTrail for the given timeframe and event names.")
        
        for event in events:
            event_details = json.loads(event['CloudTrailEvent'])
            request_parameters = event_details.get('requestParameters', {})
            event_name = event['EventName']
            error_code = event_details.get('errorCode', None)
            error_message = event_details.get('errorMessage', None)

            print(f"Debug: Request Parameters from {event_name} API Call for Event ID {event['EventId']}:\n{json.dumps(request_parameters, indent=4)}")
            if error_code:
                print(f"Error Code: {error_code}, Error Message: {error_message}")
            else:
                print("Request was successful.")
            print("-" * 60)

            found_keys = False
            for key in unsupported_condition_keys:
                if search_key_in_dict(request_parameters, key):
                    found_keys = True
                    status = 'Succeeded' if not error_code else 'Failed'
                    
                    unsupported_events.append({
                        'EventId': event['EventId'],
                        'EventName': event['EventName'],
                        'User': event_details['userIdentity'].get('arn', 'Unknown'),
                        'UnsupportedCondition': key,
                        'EventTime': event['EventTime'],
                        'Status': status,
                        'ErrorMessage': error_message
                    })
            
            if not found_keys:
                print(f"No unsupported condition keys found in requestParameters for event ID {event['EventId']}.")

    except Exception as e:
        print(f"Error querying CloudTrail logs: {str(e)}")
        print("-" * 60)

    return unsupported_events

def search_key_in_dict(d, key):
    """Recursively search for a key in a dictionary."""
    if key in d:
        return True
    for k, v in d.items():
        if isinstance(v, dict):
            if search_key_in_dict(v, key):
                return True
    return False

def save_results_to_s3_csv(results, s3_bucket_name):
    """Save the consolidated results to an S3 bucket as a CSV file."""
    s3_client = get_s3_client()
    try:
        csv_buffer = StringIO()
        csv_writer = csv.DictWriter(csv_buffer, fieldnames=['EventId', 'EventName', 'User', 'UnsupportedCondition', 'EventTime', 'Status', 'ErrorMessage'])
        csv_writer.writeheader()
        csv_writer.writerows(results)
        
        s3_file_path = f'cloudtrail-results/consolidated_results_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        
        s3_client.put_object(
            Bucket=s3_bucket_name,
            Key=s3_file_path,
            Body=csv_buffer.getvalue(),
            ContentType='text/csv'
        )
        print(f"Results successfully saved to S3: s3://{s3_bucket_name}/{s3_file_path}")
    except Exception as e:
        print(f"Error saving results to S3: {str(e)}")

def get_users_with_policies(iam_client, policies):
    """Retrieve all users who have any of the specific policies attached, along with their groups."""
    user_policies_map = defaultdict(lambda: {'policies': [], 'groups': []})

    for policy in policies:
        policy_arn = policy['Arn']
        try:
            response = iam_client.list_entities_for_policy(PolicyArn=policy_arn, EntityFilter='User')
            users = [user['UserName'] for user in response['PolicyUsers']]
            for user in users:
                user_policies_map[user]['policies'].append(policy['PolicyName'])
                groups = get_groups_for_user(iam_client, user)
                user_policies_map[user]['groups'] = groups
        except Exception as e:
            print(f"Error retrieving users for policy {policy_arn}: {str(e)}")
            print("-" * 60)

    return user_policies_map

def get_groups_for_user(iam_client, user_name):
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
    print("\033[92mProcessing customer-managed policies to find users...\033[0m")

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
        print("-" * 60)

def process_region(region):
    """Run the script logic for a single AWS region and return the results."""
    print(f"\033[94mRunning in region: {region}\033[0m")
    iam_client = get_iam_client(region)
    cloudtrail_client = get_cloudtrail_client(region)

    print("\033[92mStarting search for customer-managed IAM policies with target actions...\033[0m")
    policies = get_all_customer_managed_policies(iam_client)
    
    unsupported_events = query_cloudtrail_logs(cloudtrail_client)

    user_policies_map = get_users_with_policies(iam_client, policies)
    output_users_with_policies(user_policies_map)

    print(f"\033[92mSearch completed in region: {region}!\033[0m")
    print("-" * 60)

    return unsupported_events

def run_in_all_regions(save_to_s3, s3_bucket_name):
    """Run the script logic in all AWS regions sequentially and save results to a single CSV file if required."""
    regions = get_all_regions()
    consolidated_results = []

    for region in regions:
        try:
            region_results = process_region(region)
            consolidated_results.extend(region_results)
        except Exception as e:
            print(f"Error in region {region}: {str(e)}")

    # Save consolidated results to a single CSV file in S3 if requested
    if save_to_s3:
        save_results_to_s3_csv(consolidated_results, s3_bucket_name)

def run_in_specific_region(region, save_to_s3, s3_bucket_name):
    """Run the script logic in a specific AWS region and save results to a single CSV file if required."""
    consolidated_results = []
    try:
        region_results = process_region(region)
        consolidated_results.extend(region_results)
    except Exception as e:
        print(f"Error in region {region}: {str(e)}")

    # Save consolidated results to a single CSV file in S3 if requested
    if save_to_s3:
        save_results_to_s3_csv(consolidated_results, s3_bucket_name)

if __name__ == "__main__":
    # Prompt user whether to search in all regions or a specific region
    search_choice = input("Do you want to search in all regions or a specific region? (all/specific): ").strip().lower()
    if search_choice == 'specific':
        region = input("Enter the AWS region to search in (e.g., us-east-1): ").strip()
    else:
        region = None

    # Ask user if they want to save results to S3
    save_to_s3 = input("Do you want to save the results to S3? (yes/no): ").strip().lower() == 'yes'
    s3_bucket_name = None
    if save_to_s3:
        s3_bucket_name = input("Enter the S3 bucket name where results should be saved: ").strip()

    # Execute based on user's choice
    if region:
        run_in_specific_region(region, save_to_s3, s3_bucket_name)
    else:
        run_in_all_regions(save_to_s3, s3_bucket_name)
