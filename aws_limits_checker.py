#!/usr/bin/env python3
"""
AWS Limits and Information Checker
This script checks various AWS service limits and account information using AWS credentials.
"""

import boto3
import json
from datetime import datetime
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from typing import Dict, List, Any


class AWSLimitsChecker:
    """Check AWS service limits and account information."""
    
    def __init__(self, access_key: str, secret_key: str, region: str = 'us-east-1'):
        """
        Initialize AWS clients with credentials.
        
        Args:
            access_key: AWS Access Key ID
            secret_key: AWS Secret Access Key
            region: AWS region (default: us-east-1)
        """
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region
        
        # Initialize boto3 session
        self.session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )
        
        # Initialize clients
        self.ec2_client = self.session.client('ec2')
        self.iam_client = self.session.client('iam')
        self.sts_client = self.session.client('sts')
        self.service_quotas_client = self.session.client('service-quotas')
        self.cloudwatch_client = self.session.client('cloudwatch')
        
    def get_account_info(self) -> Dict[str, Any]:
        """Get AWS account information."""
        try:
            identity = self.sts_client.get_caller_identity()
            return {
                'account_id': identity['Account'],
                'user_arn': identity['Arn'],
                'user_id': identity['UserId']
            }
        except ClientError as e:
            return {'error': str(e)}
    
    def get_ec2_limits(self) -> Dict[str, Any]:
        """Get EC2 service limits and current usage."""
        limits = {}
        
        try:
            # Get running instances
            instances = self.ec2_client.describe_instances(
                Filters=[{'Name': 'instance-state-name', 'Values': ['running', 'pending', 'stopping', 'stopped']}]
            )
            
            instance_count = sum(len(r['Instances']) for r in instances['Reservations'])
            limits['instances'] = {
                'current_count': instance_count,
                'description': 'Total EC2 instances'
            }
            
            # Get VPCs
            vpcs = self.ec2_client.describe_vpcs()
            limits['vpcs'] = {
                'current_count': len(vpcs['Vpcs']),
                'description': 'Total VPCs'
            }
            
            # Get Security Groups
            security_groups = self.ec2_client.describe_security_groups()
            limits['security_groups'] = {
                'current_count': len(security_groups['SecurityGroups']),
                'description': 'Total Security Groups'
            }
            
            # Get Elastic IPs
            addresses = self.ec2_client.describe_addresses()
            limits['elastic_ips'] = {
                'current_count': len(addresses['Addresses']),
                'description': 'Total Elastic IPs'
            }
            
            # Get Volumes
            volumes = self.ec2_client.describe_volumes()
            limits['ebs_volumes'] = {
                'current_count': len(volumes['Volumes']),
                'total_size_gb': sum(v['Size'] for v in volumes['Volumes']),
                'description': 'Total EBS Volumes'
            }
            
            # Get Snapshots
            snapshots = self.ec2_client.describe_snapshots(OwnerIds=['self'])
            limits['ebs_snapshots'] = {
                'current_count': len(snapshots['Snapshots']),
                'description': 'Total EBS Snapshots'
            }
            
        except ClientError as e:
            limits['error'] = str(e)
        
        return limits
    
    def get_iam_limits(self) -> Dict[str, Any]:
        """Get IAM service limits and current usage."""
        limits = {}
        
        try:
            # Get account summary
            summary = self.iam_client.get_account_summary()
            summary_map = summary['SummaryMap']
            
            limits['users'] = {
                'current_count': summary_map.get('Users', 0),
                'limit': summary_map.get('UsersQuota', 'N/A'),
                'description': 'IAM Users'
            }
            
            limits['groups'] = {
                'current_count': summary_map.get('Groups', 0),
                'limit': summary_map.get('GroupsQuota', 'N/A'),
                'description': 'IAM Groups'
            }
            
            limits['roles'] = {
                'current_count': summary_map.get('Roles', 0),
                'limit': summary_map.get('RolesQuota', 'N/A'),
                'description': 'IAM Roles'
            }
            
            limits['policies'] = {
                'current_count': summary_map.get('Policies', 0),
                'limit': summary_map.get('PoliciesQuota', 'N/A'),
                'description': 'IAM Policies'
            }
            
            limits['server_certificates'] = {
                'current_count': summary_map.get('ServerCertificates', 0),
                'limit': summary_map.get('ServerCertificatesQuota', 'N/A'),
                'description': 'Server Certificates'
            }
            
        except ClientError as e:
            limits['error'] = str(e)
        
        return limits
    
    def get_service_quotas(self, service_code: str) -> List[Dict[str, Any]]:
        """
        Get service quotas for a specific service.
        
        Args:
            service_code: AWS service code (e.g., 'ec2', 's3', 'lambda')
        """
        quotas = []
        
        try:
            paginator = self.service_quotas_client.get_paginator('list_service_quotas')
            
            for page in paginator.paginate(ServiceCode=service_code):
                for quota in page['Quotas']:
                    quotas.append({
                        'quota_name': quota['QuotaName'],
                        'quota_code': quota['QuotaCode'],
                        'value': quota.get('Value', 'N/A'),
                        'unit': quota.get('Unit', 'N/A'),
                        'adjustable': quota.get('Adjustable', False)
                    })
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchResourceException':
                quotas.append({'error': str(e)})
        
        return quotas
    
    def get_region_limits(self) -> Dict[str, Any]:
        """Get region-specific information."""
        try:
            regions = self.ec2_client.describe_regions()
            return {
                'available_regions': [r['RegionName'] for r in regions['Regions']],
                'current_region': self.region,
                'total_regions': len(regions['Regions'])
            }
        except ClientError as e:
            return {'error': str(e)}
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate a comprehensive report of AWS limits and information."""
        report = {
            'timestamp': datetime.now().isoformat(),
            'region': self.region,
            'account_info': self.get_account_info(),
            'ec2_limits': self.get_ec2_limits(),
            'iam_limits': self.get_iam_limits(),
            'region_info': self.get_region_limits()
        }
        
        return report
    
    def print_report(self, report: Dict[str, Any]):
        """Print the report in a readable format."""
        print("\n" + "="*80)
        print("AWS LIMITS AND INFORMATION REPORT")
        print("="*80)
        print(f"\nTimestamp: {report['timestamp']}")
        print(f"Region: {report['region']}")
        
        # Account Info
        print("\n" + "-"*80)
        print("ACCOUNT INFORMATION")
        print("-"*80)
        for key, value in report['account_info'].items():
            print(f"{key.replace('_', ' ').title()}: {value}")
        
        # EC2 Limits
        print("\n" + "-"*80)
        print("EC2 LIMITS AND USAGE")
        print("-"*80)
        if 'error' in report['ec2_limits']:
            print(f"Error: {report['ec2_limits']['error']}")
        else:
            for resource, info in report['ec2_limits'].items():
                if isinstance(info, dict):
                    print(f"\n{resource.replace('_', ' ').title()}:")
                    for k, v in info.items():
                        print(f"  {k.replace('_', ' ').title()}: {v}")
        
        # IAM Limits
        print("\n" + "-"*80)
        print("IAM LIMITS AND USAGE")
        print("-"*80)
        if 'error' in report['iam_limits']:
            print(f"Error: {report['iam_limits']['error']}")
        else:
            for resource, info in report['iam_limits'].items():
                if isinstance(info, dict):
                    print(f"\n{resource.replace('_', ' ').title()}:")
                    for k, v in info.items():
                        print(f"  {k.replace('_', ' ').title()}: {v}")
        
        # Region Info
        print("\n" + "-"*80)
        print("REGION INFORMATION")
        print("-"*80)
        if 'error' in report['region_info']:
            print(f"Error: {report['region_info']['error']}")
        else:
            print(f"Current Region: {report['region_info']['current_region']}")
            print(f"Total Available Regions: {report['region_info']['total_regions']}")
        
        print("\n" + "="*80)


def main():
    """Main function to run the AWS limits checker."""
    print("AWS Limits and Information Checker")
    print("="*80)
    
    # Get credentials from user
    access_key = input("\nEnter AWS Access Key ID: ").strip()
    secret_key = input("Enter AWS Secret Access Key: ").strip()
    region = input("Enter AWS Region (default: us-east-1): ").strip() or 'us-east-1'
    
    try:
        # Initialize checker
        checker = AWSLimitsChecker(access_key, secret_key, region)
        
        # Generate and print report
        print("\nFetching AWS information...")
        report = checker.generate_report()
        checker.print_report(report)
        
        # Ask if user wants to save report
        save = input("\nDo you want to save the report to a JSON file? (y/n): ").strip().lower()
        if save == 'y':
            filename = f"aws_limits_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\nReport saved to: {filename}")
        
        # Ask if user wants to check specific service quotas
        check_quotas = input("\nDo you want to check specific service quotas? (y/n): ").strip().lower()
        if check_quotas == 'y':
            print("\nAvailable services: ec2, vpc, lambda, s3, rds, dynamodb, etc.")
            service_code = input("Enter service code: ").strip()
            
            print(f"\nFetching quotas for {service_code}...")
            quotas = checker.get_service_quotas(service_code)
            
            if quotas:
                print(f"\n{'-'*80}")
                print(f"SERVICE QUOTAS FOR {service_code.upper()}")
                print(f"{'-'*80}")
                for quota in quotas[:10]:  # Show first 10 quotas
                    if 'error' in quota:
                        print(f"Error: {quota['error']}")
                        break
                    print(f"\nQuota: {quota['quota_name']}")
                    print(f"  Code: {quota['quota_code']}")
                    print(f"  Value: {quota['value']} {quota['unit']}")
                    print(f"  Adjustable: {quota['adjustable']}")
                
                if len(quotas) > 10:
                    print(f"\n... and {len(quotas) - 10} more quotas")
            else:
                print(f"No quotas found for service: {service_code}")
        
    except NoCredentialsError:
        print("\nError: No AWS credentials provided.")
    except PartialCredentialsError:
        print("\nError: Incomplete AWS credentials provided.")
    except ClientError as e:
        print(f"\nAWS Error: {e}")
    except Exception as e:
        print(f"\nUnexpected error: {e}")


if __name__ == "__main__":
    main()
