import boto3
import json

# Initialize IAM client
iam_client = boto3.client('iam')

# List of unsupported condition keys for CreateVolume and CopySnapshot actions
unsupported_condition_keys = [
    "ec2:ProductCode", "ec2:Encrypted", "ec2:VolumeSize", 
    "ec2:ParentSnapshot", "ec2:Owner", "ec2:ParentVolume", 
    "ec2:SnapshotTime"
]

def get_all_policies():
    """Retrieve all managed IAM policies in the AWS account."""
    paginator = iam_client.get_paginator('list_policies')
    policy_iterator = paginator.paginate(Scope='Local')
    policies = []
    for page in policy_iterator:
        policies.extend(page['Policies'])
    return policies

def get_policy_version(policy_arn, version_id):
    """Retrieve the policy document for a specific version of an IAM policy."""
    response = iam_client.get_policy_version(
        PolicyArn=policy_arn,
        VersionId=version_id
    )
    return response['PolicyVersion']['Document']

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

def update_policy(policy_arn, policy_document):
    """Create a new version of the policy without unsupported condition keys."""
    # Convert the policy document to JSON format
    policy_json = json.dumps(policy_document)

    # Check if there are already 5 versions of the policy; if so, delete the oldest non-default version
    versions = iam_client.list_policy_versions(PolicyArn=policy_arn)['Versions']
    if len(versions) >= 5:
        for version in versions:
            if not version['IsDefaultVersion']:
                iam_client.delete_policy_version(PolicyArn=policy_arn, VersionId=version['VersionId'])
                print(f"Deleted old policy version: {version['VersionId']} for policy {policy_arn}")
                break

    # Create a new policy version
    iam_client.create_policy_version(
        PolicyArn=policy_arn,
        PolicyDocument=policy_json,
        SetAsDefault=True
    )
    print(f"Updated policy: {policy_arn} with new version set as default.")

def remove_unsupported_conditions():
    """Find policies with unsupported condition keys and automatically fix them."""
    policies = get_all_policies()
    policies_fixed = 0
    policies_unchanged = 0

    for policy in policies:
        # Get the default policy version
        policy_arn = policy['Arn']
        default_version_id = policy['DefaultVersionId']
        policy_document = get_policy_version(policy_arn, default_version_id)

        # Check and update statements with unsupported condition keys
        modified = False
        updated_statements = []

        for statement in policy_document.get('Statement', []):
            if 'Condition' in statement:
                conditions = statement['Condition']
                # Remove unsupported condition keys
                updated_conditions = {
                    key: value for key, value in conditions.items()
                    if key not in unsupported_condition_keys
                }

                if len(updated_conditions) < len(conditions):
                    modified = True
                    removed_keys = set(conditions.keys()) - set(updated_conditions.keys())
                    print(f"Removing unsupported condition keys {removed_keys} from policy: {policy['PolicyName']} ({policy_arn})")
                    statement['Condition'] = updated_conditions

            updated_statements.append(statement)

        # If policy was modified, update it
        if modified:
            policy_document['Statement'] = updated_statements
            update_policy(policy_arn, policy_document)
            policies_fixed += 1
        else:
            policies_unchanged += 1

    print(f"\nSummary:")
    print(f"Total policies checked: {len(policies)}")
    print(f"Policies fixed: {policies_fixed}")
    print(f"Policies unchanged (no unsupported keys found): {policies_unchanged}")

if __name__ == "__main__":
    # Remove unsupported condition keys from policies automatically
    remove_unsupported_conditions()
