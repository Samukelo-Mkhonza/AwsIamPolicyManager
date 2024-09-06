# AWS IAM Policy Manager

## Overview

The AWS IAM Policy Manager is a set of Python scripts that help you manage and audit IAM policies in your AWS account. The scripts allow you to identify policies with specific unsupported keys, find users and groups associated with these policies, and categorize policies into customer-managed, AWS-managed, and AWS job function-managed policies.

### Scripts Included

1. **Customer-Managed IAM Policies Script (`customer_managed_policies.py`)**: This script retrieves all customer-managed IAM policies in your AWS account, filters for those containing specific actions (`ec2:CreateVolume`, `ec2:CopySnapshot`), and lists the users and groups associated with those policies.

2. **AWS-Managed IAM Policies Script (`aws_managed_policies.py`)**: This script retrieves all AWS-managed IAM policies, filters for those containing specific actions, and lists the users and groups associated with those policies.

3. **AWS Job Function-Managed IAM Policies Script (`aws_job_function_policies.py`)**: This script retrieves all AWS-managed job function IAM policies, filters for those containing specific actions, and lists the users and groups associated with those policies.

### Prerequisites

- Python 3.6 or higher
- AWS CLI configured with appropriate credentials and permissions to access IAM resources.
- Boto3 Python package installed.

### Installation

1. **Clone the Repository:**

    ```bash
    git clone <repository-url>
    cd aws-iam-policy-manager
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

   The AWS IAM user must have sufficient permissions to list policies, list policy versions, list users, list groups, and list entities for policies.

### Usage

1. **Customer-Managed IAM Policies:**

    To find and list users and groups associated with customer-managed IAM policies containing specific unsupported actions:

    ```bash
    python customer_managed_policies.py
    ```

    - **Description**: This script scans for customer-managed IAM policies that have unsupported keys, identifies users and groups associated with those policies, and prints a summary of the results.

2. **AWS-Managed IAM Policies:**

    To find and list users and groups associated with AWS-managed IAM policies containing specific unsupported actions:

    ```bash
    python aws_managed_policies.py
    ```

    - **Description**: This script scans for AWS-managed IAM policies that have unsupported keys, identifies users and groups associated with those policies, and prints a summary of the results.

3. **AWS Job Function-Managed IAM Policies:**

    To find and list users and groups associated with AWS-managed job function IAM policies containing specific unsupported actions:

    ```bash
    python aws_job_function_policies.py
    ```

    - **Description**: This script scans for AWS-managed job function IAM policies that have unsupported keys, identifies users and groups associated with those policies, and prints a summary of the results.

### Output

For each user associated with a policy that contains unsupported keys:

- **User**: The IAM username.
- **Number of Policies**: The number of policies associated with the user that contain unsupported keys.
- **Policy Names**: The names of the policies associated with the user that contain unsupported keys.
- **Groups**: The names of the groups to which the user belongs.

### Notes

- Ensure that your AWS user has the necessary IAM permissions to execute the operations required by these scripts.
- The scripts use ANSI escape codes to display certain text in green, which may not work in all terminal environments. If you encounter issues, you can remove the escape codes from the `print` statements.

### License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

### Contributing

Contributions are welcome! Please fork the repository and submit a pull request for any improvements.

### Support

If you encounter any issues or have any questions, please feel free to open an issue or contact the repository owner.

