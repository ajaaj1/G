# AWS Limits and Information Checker

A Python script to check AWS service limits, quotas, and account information using AWS access keys.

## Features

- **Account Information**: Display AWS account ID, user ARN, and user ID
- **EC2 Limits**: Check EC2 instances, VPCs, security groups, elastic IPs, EBS volumes, and snapshots
- **IAM Limits**: Check IAM users, groups, roles, policies, and server certificates
- **Service Quotas**: Query specific service quotas for any AWS service
- **Region Information**: List available AWS regions
- **JSON Export**: Save reports to JSON files for later analysis

## Installation

1. Install Python 3 (if not already installed)

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

Or install boto3 directly:
```bash
pip install boto3
```

## Usage

### Interactive Mode

Run the script and follow the prompts:

```bash
python3 aws_limits_checker.py
```

You'll be prompted to enter:
- AWS Access Key ID
- AWS Secret Access Key
- AWS Region (default: us-east-1)

### Programmatic Usage

You can also use the script as a module:

```python
from aws_limits_checker import AWSLimitsChecker

# Initialize checker
checker = AWSLimitsChecker(
    access_key='YOUR_ACCESS_KEY',
    secret_key='YOUR_SECRET_KEY',
    region='us-east-1'
)

# Generate report
report = checker.generate_report()

# Print report
checker.print_report(report)

# Get specific service quotas
ec2_quotas = checker.get_service_quotas('ec2')
```

## AWS Credentials

### Option 1: Interactive Input (Recommended for testing)
The script will prompt you for credentials when run.

### Option 2: Environment Variables
Set environment variables before running:

```bash
export AWS_ACCESS_KEY_ID='your_access_key'
export AWS_SECRET_ACCESS_KEY='your_secret_key'
export AWS_DEFAULT_REGION='us-east-1'
```

### Option 3: AWS Credentials File
Configure AWS credentials in `~/.aws/credentials`:

```ini
[default]
aws_access_key_id = YOUR_ACCESS_KEY
aws_secret_access_key = YOUR_SECRET_KEY
```

## Required IAM Permissions

The AWS credentials need the following permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*",
        "iam:GetAccountSummary",
        "sts:GetCallerIdentity",
        "servicequotas:ListServiceQuotas",
        "servicequotas:GetServiceQuota"
      ],
      "Resource": "*"
    }
  ]
}
```

## Output Information

The script provides information about:

### Account Information
- Account ID
- User ARN
- User ID

### EC2 Resources
- Running/stopped instances count
- VPCs count
- Security groups count
- Elastic IPs count
- EBS volumes (count and total size)
- EBS snapshots count

### IAM Resources
- Users (current count and limit)
- Groups (current count and limit)
- Roles (current count and limit)
- Policies (current count and limit)
- Server certificates (current count and limit)

### Service Quotas
- Query any AWS service for its quotas
- Shows quota name, value, unit, and whether it's adjustable

## Example Output

```
================================================================================
AWS LIMITS AND INFORMATION REPORT
================================================================================

Timestamp: 2025-11-13T10:30:00.123456
Region: us-east-1

--------------------------------------------------------------------------------
ACCOUNT INFORMATION
--------------------------------------------------------------------------------
Account Id: 123456789012
User Arn: arn:aws:iam::123456789012:user/admin
User Id: AIDAI23XXXXXXXXXXXX

--------------------------------------------------------------------------------
EC2 LIMITS AND USAGE
--------------------------------------------------------------------------------

Instances:
  Current Count: 5
  Description: Total EC2 instances

Vpcs:
  Current Count: 2
  Description: Total VPCs

...
```

## Service Codes for Quotas

Common AWS service codes:
- `ec2` - Amazon EC2
- `vpc` - Amazon VPC
- `lambda` - AWS Lambda
- `s3` - Amazon S3
- `rds` - Amazon RDS
- `dynamodb` - Amazon DynamoDB
- `elasticloadbalancing` - Elastic Load Balancing
- `cloudformation` - AWS CloudFormation
- `ecs` - Amazon ECS
- `eks` - Amazon EKS

## Troubleshooting

### Authentication Errors
- Verify your access key and secret key are correct
- Check that the IAM user has the required permissions
- Ensure credentials haven't expired (for temporary credentials)

### Region Errors
- Verify the region name is correct (e.g., 'us-east-1', 'eu-west-1')
- Some services may not be available in all regions

### Permission Errors
- Ensure the IAM user/role has the necessary read permissions
- Check the IAM policy attached to your credentials

## Security Notes

- Never commit AWS credentials to version control
- Use IAM roles when running on EC2 instances
- Follow the principle of least privilege for IAM permissions
- Rotate access keys regularly
- Consider using AWS Secrets Manager or Parameter Store for credential management

## License

This script is provided as-is for checking AWS limits and information.
