# AWS IAM Policy Manager

## Overview

The AWS IAM Policy Manager is a set of Python scripts designed to help AWS administrators manage and audit IAM policies in their AWS accounts. The scripts identify policies with specific unsupported keys, ensure correct configuration of supported condition keys, find users and groups associated with these policies, and categorize policies into customer-managed, AWS-managed, and AWS job function-managed policies. The scripts also provide an option to audit CloudTrail logs for activities related to these IAM policies.

### Scripts Included

1. **Customer-Managed IAM Policies Script (`check_customer_managed_policies.py`)**: This script retrieves all customer-managed IAM policies in your AWS account, filters for those containing specific actions (`ec2:CreateVolume`, `ec2:CopySnapshot`), removes unsupported condition keys, corrects supported condition keys if needed, and lists the users and groups associated with those policies.

2. **AWS-Managed IAM Policies Script (`check_aws_managed_policies.py`)**: This script retrieves all AWS-managed IAM policies, filters for those containing specific actions, removes unsupported condition keys, corrects supported condition keys, and lists the users and groups associated with those policies.

3. **AWS Job Function-Managed IAM Policies Script (`check_managed_job_function_policies.py`)**: This script retrieves all AWS-managed job function IAM policies, filters for those containing specific actions, removes unsupported condition keys, corrects supported condition keys, and lists the users and groups associated with those policies.

4. **Combined IAM Policies Script (`modify_iam_polies.py`)**: This comprehensive script combines all the functionality above to process and manage all IAM policies (customer-managed, AWS-managed, and AWS job function-managed) in your AWS account, remove unsupported condition keys, correct supported condition keys, audit CloudTrail logs for related events, and list users and groups associated with those policies.

### Prerequisites

- Python 3.6 or higher
- AWS CLI configured with appropriate credentials and permissions to access IAM resources.
- Boto3 Python package installed.

### Installation

1. **Clone the Repository:**

    ```bash
    git clone https://github.com/Samukelo-Mkhonza/AwsIamPolicyManager.git
    cd AwsIamPolicyManager
    ```

2. **Install Python Dependencies:**

    Make sure you have Python 3.6 or higher installed and use `pip` to install the `boto3` library:

    ```bash
    pip install boto3
    ```

3. **Configure AWS CLI:**

   Ensure your AWS CLI is configured with the necessary credentials:

    ```bash
    aws configure
    ```

   The AWS IAM user must have sufficient permissions to list policies, list policy versions, list users, list groups, list entities for policies, and lookup events in CloudTrail.

### Usage

1. **Customer-Managed IAM Policies:**

    To find and list users and groups associated with customer-managed IAM policies containing specific unsupported actions:

    ```bash
    check_customer_managed_policies.py
    ```

    - **Description**: This script scans for customer-managed IAM policies that have unsupported keys, removes unsupported condition keys, corrects supported keys, identifies users and groups associated with those policies, and prints a summary of the results.

2. **AWS-Managed IAM Policies:**

    To find and list users and groups associated with AWS-managed IAM policies containing specific unsupported actions:

    ```bash
    python check_aws_managed_policies.py
    ```

    - **Description**: This script scans for AWS-managed IAM policies that have unsupported keys, removes unsupported condition keys, corrects supported keys, identifies users and groups associated with those policies, and prints a summary of the results.

3. **AWS Job Function-Managed IAM Policies:**

    To find and list users and groups associated with AWS-managed job function IAM policies containing specific unsupported actions:

    ```bash
    python check_managed_job_function_policies.py
    ```

    - **Description**: This script scans for AWS-managed job function IAM policies that have unsupported keys, removes unsupported condition keys, corrects supported keys, identifies users and groups associated with those policies, and prints a summary of the results.

4. **Combined IAM Policies Script:**

    To run a comprehensive check on all IAM policies (customer-managed, AWS-managed, and AWS job function-managed), remove unsupported condition keys, correct supported keys, and audit CloudTrail logs:

    ```bash
    python modify_iam_policies.py
    ```

    - **Description**: This script performs all the tasks mentioned above for all IAM policies in your AWS account and provides a comprehensive summary.

### Output

For each user associated with a policy that contains unsupported keys:

- **User**: The IAM username.
- **Number of Policies**: The number of policies associated with the user that contain unsupported keys.
- **Policy Names**: The names of the policies associated with the user that contain unsupported keys.
- **Groups**: The names of the groups to which the user belongs.
- **CloudTrail Events**: The list of events where unsupported condition keys were used in `ec2:CreateVolume` and `ec2:CopySnapshot` actions, providing the event time, status, and user details.

### Customization

- **Modify Supported Condition Keys:**
  - You can customize the `supported_condition_keys` dictionary in each script to reflect the correct expected values for your environment. For example, if your organization requires a specific value for the `ec2:Owner` condition key, update it in the script.

- **Adjust AWS Region and Other Settings:**
  - The scripts currently target the `us-east-1` region. You can modify the region by changing the `region_name` parameter when initializing the `boto3` client in each script.

### Notes

- Ensure that your AWS user has the necessary IAM permissions to execute the operations required by these scripts.
- The scripts use ANSI escape codes to display certain text in green, which may not work in all terminal environments. If you encounter issues, you can remove the escape codes from the `print` statements.
- Always test the scripts in a safe, non-production environment to ensure they behave as expected.
- Backup your IAM policies or their versions before running the scripts to avoid accidental loss of important policy configurations.

### Contributing

Contributions are welcome! Please fork the repository and submit a pull request for any improvements.

### Support

If you encounter any issues or have any questions, please feel free to open an issue or contact the repository owner.
