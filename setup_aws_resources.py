#!/usr/bin/env python3
"""
AWS Key Management Script

This script handles AWS key management operations:
1. Creates access keys for existing IAM users
2. Stores keys in Secrets Manager
3. Manages key rotation

Usage:
    python3 setup_aws_resources.py --username <username> [--action create|rotate]

Requirements:
    - Python 3.9+
    - boto3
    - AWS credentials with appropriate permissions
"""

import boto3
import json
import logging
import argparse
from datetime import datetime
import time
from botocore.exceptions import ClientError
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Setup AWS resources for key rotation')
    parser.add_argument('--admin-email', required=True, help='Admin email address for notifications')
    parser.add_argument('--sender-email', required=True, help='Sender email address for notifications')
    parser.add_argument('--stack-name', default='iam-key-rotation', help='CloudFormation stack name')
    parser.add_argument('--region', default='us-east-1', help='AWS region')
    return parser.parse_args()

def verify_ses_email(ses_client, email):
    """Verify an email address in SES."""
    try:
        response = ses_client.verify_email_identity(EmailAddress=email)
        logger.info(f"Verification email sent to {email}")
        return True
    except ClientError as e:
        logger.error(f"Error verifying email {email}: {str(e)}")
        return False

def create_test_user(iam_client, username, email):
    """Create a test IAM user with email tag."""
    try:
        # Create user
        response = iam_client.create_user(UserName=username)
        logger.info(f"Created IAM user: {username}")
        
        # Add email tag
        iam_client.tag_user(
            UserName=username,
            Tags=[{'Key': 'email', 'Value': email}]
        )
        logger.info(f"Added email tag to user: {username}")
        
        # Create access key
        key_response = iam_client.create_access_key(UserName=username)
        logger.info(f"Created access key for user: {username}")
        
        return key_response['AccessKey']
    except ClientError as e:
        logger.error(f"Error creating test user {username}: {str(e)}")
        raise

def store_credentials(secrets_client, username, credentials):
    """Store credentials in Secrets Manager."""
    try:
        secret_value = {
            'AccessKeyId': credentials['AccessKeyId'],
            'SecretAccessKey': credentials['SecretAccessKey'],
            'CreatedDate': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        }
        
        secrets_client.create_secret(
            Name=username,
            SecretString=str(secret_value),
            Description=f'AWS credentials for {username}'
        )
        logger.info(f"Stored credentials in Secrets Manager for: {username}")
    except ClientError as e:
        logger.error(f"Error storing credentials for {username}: {str(e)}")
        raise

def deploy_cloudformation(cfn_client, stack_name, admin_email, sender_email):
    """Deploy the CloudFormation stack."""
    try:
        with open('key_rotation_template.yaml', 'r') as template_file:
            template_body = template_file.read()
        
        response = cfn_client.create_stack(
            StackName=stack_name,
            TemplateBody=template_body,
            Parameters=[
                {
                    'ParameterKey': 'AdminEmail',
                    'ParameterValue': admin_email
                },
                {
                    'ParameterKey': 'SenderEmail',
                    'ParameterValue': sender_email
                }
            ],
            Capabilities=['CAPABILITY_IAM']
        )
        
        logger.info(f"Started CloudFormation stack creation: {stack_name}")
        
        # Wait for stack creation
        waiter = cfn_client.get_waiter('stack_create_complete')
        waiter.wait(StackName=stack_name)
        
        logger.info(f"CloudFormation stack created successfully: {stack_name}")
        
        # Get stack outputs
        response = cfn_client.describe_stacks(StackName=stack_name)
        outputs = response['Stacks'][0]['Outputs']
        
        for output in outputs:
            logger.info(f"{output['Description']}: {output['OutputValue']}")
            
    except ClientError as e:
        logger.error(f"Error deploying CloudFormation stack: {str(e)}")
        raise

def main():
    """Main function."""
    args = parse_args()
    
    try:
        # Initialize AWS clients
        ses = boto3.client('ses', region_name=args.region)
        iam = boto3.client('iam', region_name=args.region)
        secrets = boto3.client('secretsmanager', region_name=args.region)
        cfn = boto3.client('cloudformation', region_name=args.region)
        
        # Verify email addresses
        logger.info("Verifying email addresses...")
        if not verify_ses_email(ses, args.admin_email):
            sys.exit(1)
        if not verify_ses_email(ses, args.sender_email):
            sys.exit(1)
        
        # Create test user
        logger.info("Creating test user...")
        test_user = 'test-user-1'
        credentials = create_test_user(iam, test_user, args.admin_email)
        
        # Store credentials
        logger.info("Storing credentials...")
        store_credentials(secrets, test_user, credentials)
        
        # Deploy CloudFormation stack
        logger.info("Deploying CloudFormation stack...")
        deploy_cloudformation(cfn, args.stack_name, args.admin_email, args.sender_email)
        
        logger.info("Setup completed successfully!")
        
    except Exception as e:
        logger.error(f"Setup failed: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main() 