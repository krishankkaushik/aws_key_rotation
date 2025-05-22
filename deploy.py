#!/usr/bin/env python3
import boto3
import json
import logging
import os
import time
import argparse
import sys
from botocore.exceptions import ClientError
import random
import string

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
        self.ssm = boto3.client('ssm')
        
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
    
    def store_api_key(self):
        """Store API key in Secrets Manager"""
        try:
            # Generate a random API key
            api_key = ''.join(random.choices(string.ascii_letters + string.digits, k=20))
            
            # Store in Secrets Manager
            self.ssm.put_parameter(
                Name='/apigateway/key-rotation/api-key',
                Value=api_key,
                Type='String',
                Overwrite=True
            )
            logger.info("API key stored in Secrets Manager")
            return api_key
        except ClientError as e:
            logger.error(f"Error storing API key: {str(e)}")
            raise
    
    def deploy_cloudformation(self):
        """Deploy CloudFormation stack"""
        try:
            # Store API key first
            self.store_api_key()
            
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
            
            # Get API credentials
            self.display_api_credentials()
            
        except ClientError as e:
            logger.error(f"Error deploying stack: {str(e)}")
            raise
    
    def display_api_credentials(self):
        """Fetch and display API credentials"""
        try:
            # Get API key from CloudFormation outputs
            response = self.cf.describe_stacks(StackName=self.stack_name)
            outputs = response['Stacks'][0]['Outputs']
            
            api_key = None
            api_endpoint = None
            
            for output in outputs:
                if output['OutputKey'] == 'ApiKey':
                    api_key = output['OutputValue']
                elif output['OutputKey'] == 'ApiEndpoint':
                    api_endpoint = output['OutputValue']
            
            if not api_key or not api_endpoint:
                raise Exception("Could not find API credentials in stack outputs")

            # Print API credentials
            logger.info("\nAPI Credentials:")
            logger.info("===============")
            logger.info(f"API Key: {api_key}")
            logger.info(f"API Endpoint: {api_endpoint}")
            logger.info("\nTo get active credentials for a user, follow these steps:")
            logger.info("\n1. First, generate a token:")
            logger.info(f'curl -X POST -H "x-api-key: {api_key}" "{api_endpoint.replace("/active-key", "/generate-token")}"')
            logger.info("\n2. Then, use the token to get active credentials:")
            logger.info(f'curl -H "x-api-key: {api_key}" -H "Authorization: Bearer YOUR_TOKEN" "{api_endpoint}?username=test-user-1"')
            logger.info("\nReplace 'test-user-1' with any of your IAM users to get their active credentials.")

        except ClientError as e:
            logger.error(f"Error fetching API credentials: {str(e)}")
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