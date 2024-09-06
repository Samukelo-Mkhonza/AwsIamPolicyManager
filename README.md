# AwsIamPolicyManager

**AwsIamPolicyManager** is a Python-based tool that automates the identification and fixing of AWS Identity and Access Management (IAM) policies containing unsupported condition keys. It also audits AWS CloudTrail logs across all regions to find events using these unsupported keys.

## Features

- **Identify Unsupported Condition Keys**: Scans all IAM policies in your AWS account and lists those containing unsupported condition keys.
- **Automatically Fix Policies**: Removes unsupported condition keys from policies and updates them to compliant versions.
- **Audit CloudTrail Logs**: Searches CloudTrail logs in all AWS regions to find events using unsupported condition keys for `CreateVolume` and `CopySnapshot` actions.
- **Detailed Output**: Provides detailed output of actions taken, including policy modifications and CloudTrail findings.
- **Automated Cleanup**: Automatically handles policy versioning by deleting old versions when limits are reached.

## Prerequisites

- Python 3.6 or higher
- Boto3 library
- AWS CLI configured with appropriate permissions

## Required IAM Permissions

To run the tool, the following IAM permissions are required:

- **IAM Permissions**:
  - `iam:ListPolicies`
  - `iam:GetPolicyVersion`
  - `iam:ListPolicyVersions`
  - `iam:DeletePolicyVersion`
  - `iam:CreatePolicyVersion`
  - `iam:GetPolicy`

- **CloudTrail Permissions**:
  - `cloudtrail:LookupEvents`

- **EC2 Permissions**:
  - `ec2:DescribeRegions`

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/IamPolicyFixer.git
   cd IamPolicyFixer
