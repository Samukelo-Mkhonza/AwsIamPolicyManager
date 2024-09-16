import boto3
import json
import csv
from io import StringIO
from datetime import datetime, timedelta, tzinfo
from collections import defaultdict
import fnmatch
import logging
from tabulate import tabulate

# ANSI escape sequences for colors
RED = '\033[91m'
GREEN = '\033[92m'
BLUE = '\033[94m'
CYAN = '\033[96m'
YELLOW = '\033[93m'
MAGENTA = '\033[95m'
RESET = '\033[0m'

# Define a custom UTC timezone class
class UTC(tzinfo):
    """UTC Timezone"""

    def utcoffset(self, dt):
        return timedelta(0)

    def tzname(self, dt):
        return "UTC"

    def dst(self, dt):
        return timedelta(0)

utc = UTC()

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
    """Initialize IAM client."""
    return boto3.client('iam', region_name=region_name)

def get_cloudtrail_client(region_name):
    """Initialize CloudTrail client."""
    return boto3.client('cloudtrail', region_name=region_name)

def get_s3_client():
    """Initialize S3 client."""
    return boto3.client('s3')

def get_all_customer_managed_policies(iam_client):
    """Retrieve all customer-managed IAM policies in the AWS account."""
    logging.info(f"{GREEN}Loading customer-managed IAM policies...{RESET}")
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
                logging.info(f"{CYAN}Found relevant policy: {policy['PolicyName']}{RESET}")

    logging.info(f"{GREEN}Total relevant customer-managed policies found: {len(policies)}{RESET}")
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
    for statement in policy_document.get('Statement', []):
        if isinstance(statement, dict):
            actions = statement.get('Action', [])
            actions = normalize_actions(actions)
            matched_actions = []

            for action in actions:
                action_lower = action.lower()
                for target_action in target_actions:
                    target_action_lower = target_action.lower()
                    if fnmatch.fnmatchcase(action_lower, target_action_lower):
                        matched_actions.append(target_action)
                    elif action_lower == '*' or action_lower == 'ec2:*':
                        matched_actions.append(target_action)

            if matched_actions:
                condition = statement.get('Condition', {})
                if check_unsupported_conditions(condition):
                    logging.debug(f"Found target actions with unsupported conditions: {matched_actions}")
                    return True
    return False

def check_unsupported_conditions(condition):
    """Check if any unsupported condition keys are present in the policy statement's 'Condition'."""
    if not condition:
        return False
    for condition_operator, condition_kv in condition.items():
        if isinstance(condition_kv, dict):
            for key in condition_kv.keys():
                if key in unsupported_condition_keys:
                    return True
        elif isinstance(condition_kv, list):
            for item in condition_kv:
                if isinstance(item, dict):
                    if check_unsupported_conditions(item):
                        return True
    return False

def get_policy_version(iam_client, policy_arn, version_id):
    """Retrieve the policy document for a specific version of an IAM policy."""
    try:
        response = iam_client.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=version_id
        )
        return response['PolicyVersion']['Document']
    except Exception as e:
        logging.error(f"Error retrieving policy version {version_id} for {policy_arn}: {e}")
        return {}

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
            logging.error(f"Error retrieving users for policy {policy_arn}: {e}")

    return user_policies_map

def get_groups_for_user(iam_client, user_name):
    """Retrieve groups for a specific user."""
    groups = []
    try:
        response = iam_client.list_groups_for_user(UserName=user_name)
        groups = [group['GroupName'] for group in response['Groups']]
    except Exception as e:
        logging.error(f"Error retrieving groups for user {user_name}: {e}")
    return groups

def get_roles_with_policies(iam_client, policies):
    """Retrieve all roles that have any of the specific policies attached."""
    role_policies_map = defaultdict(list)

    for policy in policies:
        policy_arn = policy['Arn']
        try:
            response = iam_client.list_entities_for_policy(PolicyArn=policy_arn, EntityFilter='Role')
            roles = [role['RoleName'] for role in response['PolicyRoles']]
            for role in roles:
                role_policies_map[role].append(policy['PolicyName'])
        except Exception as e:
            logging.error(f"Error retrieving roles for policy {policy_arn}: {e}")

    return role_policies_map

def output_entities_with_policies(user_policies_map, role_policies_map):
    """Display users and roles with policies containing unsupported keys and their groups."""
    consolidated_results = []
    logging.info(f"{GREEN}Processing customer-managed policies to find users and roles...{RESET}")

    if user_policies_map:
        logging.info(f"{YELLOW}Users with customer-managed policies containing target actions and unsupported condition keys:{RESET}")
        for user, info in user_policies_map.items():
            consolidated_results.append({
                'Type': 'User',
                'Name': user,
                'Policies': ', '.join(info['policies']),
                'Groups': ', '.join(info['groups']) if info['groups'] else 'None'
            })
    else:
        logging.info(f"{YELLOW}No users found with customer-managed policies containing target actions and unsupported condition keys.{RESET}")

    if role_policies_map:
        logging.info(f"{YELLOW}Roles with customer-managed policies containing target actions and unsupported condition keys:{RESET}")
        for role, policies in role_policies_map.items():
            consolidated_results.append({
                'Type': 'Role',
                'Name': role,
                'Policies': ', '.join(policies),
                'Groups': 'N/A'
            })
    else:
        logging.info(f"{YELLOW}No roles found with customer-managed policies containing target actions and unsupported condition keys.{RESET}")

    # Output results in table form with colors
    if consolidated_results:
        headers = ['Type', 'Name', 'Policies', 'Groups']
        table = []
        for res in consolidated_results:
            color = GREEN if res['Type'] == 'User' else CYAN
            row = [
                f"{color}{res['Type']}{RESET}",
                f"{color}{res['Name']}{RESET}",
                res['Policies'],
                res['Groups']
            ]
            table.append(row)
        print(tabulate(table, headers, tablefmt="grid"))
    else:
        print(f"{RED}No entities found with policies containing unsupported condition keys.{RESET}")

    return consolidated_results

def query_cloudtrail_logs(cloudtrail_client, user_policies_map, role_policies_map):
    """Query CloudTrail logs for CreateVolume and CopySnapshot events."""
    logging.info(f"{GREEN}Querying CloudTrail logs for CreateVolume and CopySnapshot events...{RESET}")
    events_with_unsupported_keys = []
    try:
        end_time = datetime.now(utc)  # Use timezone-aware datetime object
        start_time = end_time - timedelta(days=90)  # Adjust as needed
        paginator = cloudtrail_client.get_paginator('lookup_events')
        event_iterator = paginator.paginate(
            LookupAttributes=[
                {'AttributeKey': 'EventName', 'AttributeValue': 'CreateVolume'},
                {'AttributeKey': 'EventName', 'AttributeValue': 'CopySnapshot'}
            ],
            StartTime=start_time,
            EndTime=end_time,
        )
        for page in event_iterator:
            for event in page['Events']:
                event_name = event['EventName']
                event_time = event['EventTime']
                cloudtrail_event = json.loads(event['CloudTrailEvent'])
                user_identity = cloudtrail_event.get('userIdentity', {})
                user_type = user_identity.get('type')
                user_name = user_identity.get('userName')
                arn = user_identity.get('arn')
                error_code = cloudtrail_event.get('errorCode')
                error_message = cloudtrail_event.get('errorMessage')
                status = 'Success' if not error_code else 'Failure'
                # Match user or role
                matched = False
                policies = ''
                if user_type == 'IAMUser' and user_name in user_policies_map:
                    matched = True
                    policies = ', '.join(user_policies_map[user_name]['policies'])
                elif user_type == 'AssumedRole':
                    role_name = user_identity.get('sessionContext', {}).get('sessionIssuer', {}).get('userName')
                    if role_name in role_policies_map:
                        matched = True
                        policies = ', '.join(role_policies_map[role_name])
                if matched:
                    events_with_unsupported_keys.append({
                        'User/Role': user_name or role_name,
                        'Type': user_type,
                        'Event Time': event_time.strftime('%Y-%m-%d %H:%M:%S'),
                        'API Call': event_name,
                        'Status': status,
                        'Error Code': error_code or 'None',
                        'Policies': policies
                    })
    except Exception as e:
        logging.error(f"Error querying CloudTrail logs: {e}")
    return events_with_unsupported_keys

def output_cloudtrail_events(cloudtrail_events):
    """Output CloudTrail events in table form with colors."""
    if cloudtrail_events:
        logging.info(f"{GREEN}CloudTrail events involving unsupported condition keys:{RESET}")
        headers = ['User/Role', 'Type', 'Event Time', 'API Call', 'Status', 'Error Code', 'Policies']
        table = []
        for event in cloudtrail_events:
            color = GREEN if event['Status'] == 'Success' else RED
            row = [
                f"{color}{event['User/Role']}{RESET}",
                event['Type'],
                event['Event Time'],
                event['API Call'],
                f"{color}{event['Status']}{RESET}",
                event['Error Code'],
                event['Policies']
            ]
            table.append(row)
        print(tabulate(table, headers, tablefmt="grid"))
    else:
        print(f"{RED}No CloudTrail events found for users/roles with unsupported condition keys.{RESET}")

def save_results_to_s3_csv(results, cloudtrail_events, s3_bucket_name):
    """Save the consolidated results to an S3 bucket as CSV files."""
    s3_client = get_s3_client()
    try:
        # Save IAM entities results
        csv_buffer = StringIO()
        csv_writer = csv.DictWriter(csv_buffer, fieldnames=['Type', 'Name', 'Policies', 'Groups'])
        csv_writer.writeheader()
        csv_writer.writerows(results)
        s3_file_path = f'cloudtrail-results/entities_results_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        s3_client.put_object(
            Bucket=s3_bucket_name,
            Key=s3_file_path,
            Body=csv_buffer.getvalue(),
            ContentType='text/csv'
        )
        logging.info(f"{GREEN}Entities results successfully saved to S3: s3://{s3_bucket_name}/{s3_file_path}{RESET}")

        # Save CloudTrail events results
        if cloudtrail_events:
            csv_buffer = StringIO()
            csv_writer = csv.DictWriter(csv_buffer, fieldnames=['User/Role', 'Type', 'Event Time', 'API Call', 'Status', 'Error Code', 'Policies'])
            csv_writer.writeheader()
            csv_writer.writerows(cloudtrail_events)
            s3_file_path = f'cloudtrail-results/cloudtrail_events_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            s3_client.put_object(
                Bucket=s3_bucket_name,
                Key=s3_file_path,
                Body=csv_buffer.getvalue(),
                ContentType='text/csv'
            )
            logging.info(f"{GREEN}CloudTrail events successfully saved to S3: s3://{s3_bucket_name}/{s3_file_path}{RESET}")
    except Exception as e:
        logging.error(f"Error saving results to S3: {e}")

def process_region(region, s3_bucket_name=None):
    """Run the script logic for a single AWS region and return the results."""
    logging.info(f"{BLUE}Running in region: {region}{RESET}")
    iam_client = get_iam_client(region)
    cloudtrail_client = get_cloudtrail_client(region)

    policies = get_all_customer_managed_policies(iam_client)

    user_policies_map = get_users_with_policies(iam_client, policies)
    role_policies_map = get_roles_with_policies(iam_client, policies)

    consolidated_results = output_entities_with_policies(user_policies_map, role_policies_map)

    cloudtrail_events = query_cloudtrail_logs(cloudtrail_client, user_policies_map, role_policies_map)
    output_cloudtrail_events(cloudtrail_events)

    if s3_bucket_name and (consolidated_results or cloudtrail_events):
        save_results_to_s3_csv(consolidated_results, cloudtrail_events, s3_bucket_name)

def run_in_all_regions(save_to_s3, s3_bucket_name):
    """Run the script logic in all AWS regions sequentially."""
    regions = get_all_regions()

    for region in regions:
        try:
            process_region(region, s3_bucket_name if save_to_s3 else None)
        except Exception as e:
            logging.error(f"Error in region {region}: {e}")

def run_in_specific_region(region, save_to_s3, s3_bucket_name):
    """Run the script logic in a specific AWS region."""
    try:
        process_region(region, s3_bucket_name if save_to_s3 else None)
    except Exception as e:
        logging.error(f"Error in region {region}: {e}")

if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Prompt user whether to search in all regions or a specific region
    search_choice = input(f"{CYAN}Do you want to search in all regions or a specific region? (all/specific): {RESET}").strip().lower()
    if search_choice == 'specific':
        region = input(f"{CYAN}Enter the AWS region to search in (e.g., us-east-1): {RESET}").strip()
    else:
        region = None

    # Ask user if they want to save results to S3
    save_to_s3_input = input(f"{CYAN}Do you want to save the results to S3? (yes/no): {RESET}").strip().lower()
    save_to_s3 = save_to_s3_input == 'yes'
    s3_bucket_name = None
    if save_to_s3:
        s3_bucket_name = input(f"{CYAN}Enter the S3 bucket name where results should be saved: {RESET}").strip()

    # Execute based on user's choice
    if region:
        run_in_specific_region(region, save_to_s3, s3_bucket_name)
    else:
        run_in_all_regions(save_to_s3, s3_bucket_name)
