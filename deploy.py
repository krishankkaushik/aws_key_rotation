#!/usr/bin/env python3
import boto3
import json
import logging
import os
import time
import argparse
import sys
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class KeyRotationDeployer:
    def __init__(self, admin_email, sender_email, stack_name='iam-key-rotation'):
        self.admin_email = admin_email
        self.sender_email = sender_email
        self.stack_name = stack_name
        self.region = boto3.session.Session().region_name
        
        # Initialize AWS clients
        self.ses = boto3.client('ses', region_name=self.region)
        self.iam = boto3.client('iam')
        self.cf = boto3.client('cloudformation')
        self.secrets = boto3.client('secretsmanager')
        
        # Load CloudFormation template
        with open('key_rotation_simple.yaml', 'r') as f:
            self.template_body = f.read()
    
    def verify_ses_email(self, email):
        """Verify email address in SES"""
        try:
            self.ses.verify_email_identity(EmailAddress=email)
            logger.info(f"Verification email sent to {email}")
        except ClientError as e:
            if 'Throttling' in str(e):
                logger.warning(f"Email verification skipped for {email} due to SES throttling. Please verify manually in AWS Console.")
            else:
                logger.error(f"Error verifying email {email}: {str(e)}")
                raise
    
    def list_existing_users(self):
        """List existing IAM users"""
        try:
            response = self.iam.list_users()
            users = response['Users']
            logger.info(f"Found {len(users)} existing IAM users")
            for user in users:
                logger.info(f"User: {user['UserName']}")
            return users
        except ClientError as e:
            logger.error(f"Error listing users: {str(e)}")
            raise
    
    def deploy_cloudformation(self):
        """Deploy CloudFormation stack"""
        try:
            # Check if stack exists
            try:
                self.cf.describe_stacks(StackName=self.stack_name)
                logger.info(f"Stack {self.stack_name} exists, updating...")
                self.cf.update_stack(
                    StackName=self.stack_name,
                    TemplateBody=self.template_body,
                    Parameters=[
                        {'ParameterKey': 'AdminEmail', 'ParameterValue': self.admin_email},
                        {'ParameterKey': 'SenderEmail', 'ParameterValue': self.sender_email}
                    ],
                    Capabilities=['CAPABILITY_IAM']
                )
            except ClientError as e:
                if 'does not exist' in str(e):
                    logger.info(f"Stack {self.stack_name} does not exist, creating...")
                    self.cf.create_stack(
                        StackName=self.stack_name,
                        TemplateBody=self.template_body,
                        Parameters=[
                            {'ParameterKey': 'AdminEmail', 'ParameterValue': self.admin_email},
                            {'ParameterKey': 'SenderEmail', 'ParameterValue': self.sender_email}
                        ],
                        Capabilities=['CAPABILITY_IAM']
                    )
                else:
                    raise
            
            # Wait for stack to complete
            waiter = self.cf.get_waiter('stack_create_complete')
            waiter.wait(StackName=self.stack_name)
            logger.info("Stack deployment completed successfully")
            
        except ClientError as e:
            logger.error(f"Error deploying stack: {str(e)}")
            raise
    
    def cleanup(self):
        """Clean up resources"""
        try:
            # Delete CloudFormation stack
            logger.info(f"Deleting stack {self.stack_name}...")
            self.cf.delete_stack(StackName=self.stack_name)
            waiter = self.cf.get_waiter('stack_delete_complete')
            waiter.wait(StackName=self.stack_name)
            logger.info("Stack deleted successfully")
            
            # Delete API endpoint secret
            logger.info("Deleting API endpoint secret...")
            try:
                self.secrets.delete_secret(SecretId='api-endpoint', ForceDeleteWithoutRecovery=True)
                logger.info("API endpoint secret deleted successfully")
            except ClientError as e:
                if 'ResourceNotFoundException' not in str(e):
                    raise
            
            # Delete API key secret
            logger.info("Deleting API key secret...")
            try:
                self.secrets.delete_secret(SecretId='api-key', ForceDeleteWithoutRecovery=True)
                logger.info("API key secret deleted successfully")
            except ClientError as e:
                if 'ResourceNotFoundException' not in str(e):
                    raise
            
            logger.info("Cleanup completed successfully")
            
        except ClientError as e:
            logger.error(f"Error during cleanup: {str(e)}")
            raise

def main():
    parser = argparse.ArgumentParser(description='Deploy AWS IAM key rotation system')
    parser.add_argument('--admin-email', required=True, help='Admin email address')
    parser.add_argument('--sender-email', required=True, help='Sender email address')
    parser.add_argument('--cleanup', action='store_true', help='Clean up resources before deployment')
    parser.add_argument('--skip-email-verification', action='store_true', help='Skip email verification')
    args = parser.parse_args()
    
    deployer = KeyRotationDeployer(args.admin_email, args.sender_email)
    
    if args.cleanup:
        deployer.cleanup()
    
    # Verify email addresses if not skipped
    if not args.skip_email_verification:
        deployer.verify_ses_email(args.admin_email)
        deployer.verify_ses_email(args.sender_email)
    else:
        logger.info("Skipping email verification as requested")
    
    # List existing users
    deployer.list_existing_users()
    
    # Deploy CloudFormation stack
    deployer.deploy_cloudformation()

if __name__ == '__main__':
    main() 