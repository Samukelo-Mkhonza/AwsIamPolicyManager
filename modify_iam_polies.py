import boto3
import json

# Initialize IAM client
iam_client = boto3.client('iam')

# Unsupported condition keys that need to be removed from IAM policies
unsupported_condition_keys = [
    "ec2:ProductCode", "ec2:Encrypted", "ec2:VolumeSize",
    "ec2:ParentSnapshot", "ec2:Owner", "ec2:ParentVolume",
    "ec2:SnapshotTime"
]

# Actions associated with these condition keys
target_actions = ["ec2:CreateVolume", "ec2:CopySnapshot"]

def list_all_policies():
    """Retrieve all managed IAM policies in the AWS account."""
    paginator = iam_client.get_paginator('list_policies')
    policy_iterator = paginator.paginate(Scope='Local')
    policies = []
    
    for page in policy_iterator:
        policies.extend(page['Policies'])
    
    return policies

def get_policy_document(policy_arn, version_id):
    """Retrieve the policy document for a specific version of an IAM policy."""
    response = iam_client.get_policy_version(
        PolicyArn=policy_arn,
        VersionId=version_id
    )
    return response['PolicyVersion']['Document']

def remove_unsupported_conditions(policy_document):
    """Remove unsupported condition keys from the policy document."""
    modified = False

    for statement in policy_document.get('Statement', []):
        if 'Condition' in statement:
            conditions = statement['Condition']
            # Remove unsupported condition keys
            for key in list(conditions.keys()):
                if key in unsupported_condition_keys:
                    del conditions[key]
                    modified = True
    return policy_document if modified else None

def update_policy(policy_arn, policy_document):
    """Create a new version of the IAM policy with the modified policy document."""
    try:
        response = iam_client.create_policy_version(
            PolicyArn=policy_arn,
            PolicyDocument=json.dumps(policy_document),
            SetAsDefault=True
        )
        print(f"Updated policy: {policy_arn}")
        return True
    except Exception as e:
        print(f"Error updating policy {policy_arn}: {e}")
        return False

def process_policies():
    """Main function to process and update policies."""
    policies = list_all_policies()
    print(f"Found {len(policies)} policies to evaluate.")
    
    modified_policies = []

    for policy in policies:
        policy_arn = policy['Arn']
        policy_name = policy['PolicyName']
        default_version_id = policy['DefaultVersionId']

        print(f"Checking policy: {policy_name} ({policy_arn})")
        
        policy_document = get_policy_document(policy_arn, default_version_id)
        modified_document = remove_unsupported_conditions(policy_document)

        if modified_document:
            print(f"Unsupported condition keys found and removed in policy: {policy_name} ({policy_arn})")
            if update_policy(policy_arn, modified_document):
                modified_policies.append(policy_name)
        else:
            print(f"No unsupported condition keys found in policy: {policy_name} ({policy_arn})")

    # Summary of modified policies
    print("\n\033[92mSummary of Modified Policies:\033[0m")
    if modified_policies:
        for policy in modified_policies:
            print(f"- {policy}")
    else:
        print("No policies were modified.")

if __name__ == "__main__":
    process_policies()
