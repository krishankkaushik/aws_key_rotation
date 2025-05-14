#!/usr/bin/env python3

import boto3
import logging
import sys
import time
import argparse
from botocore.exceptions import ClientError
from botocore.config import Config
import json
from datetime import datetime, timedelta, timezone
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Configure AWS clients with retries
config = Config(
    retries = dict(
        max_attempts = 10,
        mode = 'adaptive'
    )
)

class KeyRotationManager:
    def __init__(self, sender_email):
        """Initialize AWS clients."""
        self.iam = boto3.client('iam', config=config)
        self.secrets = boto3.client('secretsmanager', config=config)
        self.events = boto3.client('events', config=config)
        self.lambda_client = boto3.client('lambda', config=config)
        self.apigw = boto3.client('apigateway', config=config)
        self.cloudformation = boto3.client('cloudformation', config=config)
        self.ses = boto3.client('ses', config=config)
        self.region = boto3.session.Session().region_name
        self.api_id = None
        self.api_key = None
        self.sender_email = sender_email

    def cleanup(self):
        """Clean up all AWS resources."""
        logger.info("Starting cleanup...")
        
        # 1. Delete API Gateway
        logger.info("Cleaning up API Gateway...")
        apis = self.apigw.get_rest_apis()
        for api in apis['items']:
            if api['name'] == 'KeyRotationApi':
                try:
                    self.apigw.delete_rest_api(restApiId=api['id'])
                    logger.info(f"Deleting API Gateway: {api['id']}")
                    time.sleep(10)
                except ClientError as e:
                    if e.response['Error']['Code'] == 'TooManyRequestsException':
                        logger.warning("Rate limit hit, waiting 30 seconds...")
                        time.sleep(30)
                        continue
                    raise

        # 2. Delete EventBridge rules
        logger.info("Cleaning up EventBridge rules...")
        rules = self.events.list_rules()
        for rule in rules['Rules']:
            if rule['Name'].startswith('KeyRotation'):
                try:
                    targets = self.events.list_targets_by_rule(Rule=rule['Name'])
                    if targets['Targets']:
                        self.events.remove_targets(
                            Rule=rule['Name'],
                            Ids=[target['Id'] for target in targets['Targets']]
                        )
                    self.events.delete_rule(Name=rule['Name'])
                    logger.info(f"Deleted EventBridge rule: {rule['Name']}")
                    time.sleep(5)
                except ClientError as e:
                    if e.response['Error']['Code'] == 'TooManyRequestsException':
                        logger.warning("Rate limit hit, waiting 30 seconds...")
                        time.sleep(30)
                        continue
                    raise

        # 3. Delete Lambda function
        logger.info("Cleaning up Lambda function...")
        try:
            self.lambda_client.delete_function(
                FunctionName='iam-key-rotation-KeyRotationFunction-tSqkEMN96R3N'
            )
            logger.info("Deleted Lambda function")
            time.sleep(5)
        except ClientError as e:
            if e.response['Error']['Code'] not in ['ResourceNotFoundException', 'TooManyRequestsException']:
                raise

        # 4. Delete Secrets Manager secrets
        logger.info("Cleaning up Secrets Manager secrets...")
        secrets = self.secrets.list_secrets()
        for secret in secrets['SecretList']:
            if secret['Name'].startswith('iam-key-rotation/') or secret['Name'] == 'key-rotation-api-key':
                try:
                    self.secrets.delete_secret(
                        SecretId=secret['Name'],
                        ForceDeleteWithoutRecovery=True
                    )
                    logger.info(f"Deleted secret: {secret['Name']}")
                    time.sleep(5)
                except ClientError as e:
                    if e.response['Error']['Code'] == 'TooManyRequestsException':
                        logger.warning("Rate limit hit, waiting 30 seconds...")
                        time.sleep(30)
                        continue
                    raise

        # 5. Delete IAM access keys
        logger.info("Cleaning up IAM access keys...")
        users = self.iam.list_users()['Users']
        for user in users:
            if user['UserName'].startswith('test-user-'):
                try:
                    keys = self.iam.list_access_keys(UserName=user['UserName'])
                    for key in keys['AccessKeyMetadata']:
                        self.iam.delete_access_key(
                            UserName=user['UserName'],
                            AccessKeyId=key['AccessKeyId']
                        )
                        logger.info(f"Deleted access key for {user['UserName']}")
                        time.sleep(5)
                except ClientError as e:
                    if e.response['Error']['Code'] == 'TooManyRequestsException':
                        logger.warning("Rate limit hit, waiting 30 seconds...")
                        time.sleep(30)
                        continue
                    raise

        # 6. Delete CloudFormation stack
        logger.info("Cleaning up CloudFormation stack...")
        try:
            self.cloudformation.delete_stack(StackName='iam-key-rotation')
            logger.info("Deleting CloudFormation stack...")
            waiter = self.cloudformation.get_waiter('stack_delete_complete')
            waiter.wait(StackName='iam-key-rotation')
            logger.info("CloudFormation stack deleted")
        except ClientError as e:
            if e.response['Error']['Code'] not in ['ValidationError', 'TooManyRequestsException']:
                raise

        logger.info("Cleanup completed successfully")

    def deploy(self):
        """Deploy the CloudFormation stack."""
        logger.info("Starting deployment...")
        
        # Read the template file
        with open('key_rotation_minimal.yaml', 'r') as f:
            template_body = f.read()
        
        # Create or update the stack
        try:
            self.cloudformation.create_stack(
                StackName='iam-key-rotation',
                TemplateBody=template_body,
                Parameters=[
                    {
                        'ParameterKey': 'SenderEmail',
                        'ParameterValue': self.sender_email
                    },
                    {
                        'ParameterKey': 'RotationPeriod',
                        'ParameterValue': '10'
                    },
                    {
                        'ParameterKey': 'InactivePeriod',
                        'ParameterValue': '12'
                    },
                    {
                        'ParameterKey': 'DeletionPeriod',
                        'ParameterValue': '15'
                    }
                ],
                Capabilities=['CAPABILITY_IAM']
            )
            logger.info("Stack creation initiated")
        except self.cloudformation.exceptions.AlreadyExistsException:
            self.cloudformation.update_stack(
                StackName='iam-key-rotation',
                TemplateBody=template_body,
                Parameters=[
                    {
                        'ParameterKey': 'SenderEmail',
                        'ParameterValue': self.sender_email
                    },
                    {
                        'ParameterKey': 'RotationPeriod',
                        'ParameterValue': '10'
                    },
                    {
                        'ParameterKey': 'InactivePeriod',
                        'ParameterValue': '12'
                    },
                    {
                        'ParameterKey': 'DeletionPeriod',
                        'ParameterValue': '15'
                    }
                ],
                Capabilities=['CAPABILITY_IAM']
            )
            logger.info("Stack update initiated")
        
        # Wait for stack to complete
        waiter = self.cloudformation.get_waiter('stack_create_complete')
        waiter.wait(StackName='iam-key-rotation')
        logger.info("Stack deployment completed successfully")

    def setup_api(self):
        """Set up API Gateway and store API key."""
        try:
            # Get Lambda function ARN from CloudFormation stack
            stack = self.cloudformation.describe_stacks(StackName='iam-key-rotation')
            lambda_arn = None
            for output in stack['Stacks'][0]['Outputs']:
                if output['OutputKey'] == 'KeyRotationFunction':
                    lambda_arn = output['OutputValue']
                    break
            
            if not lambda_arn:
                raise Exception("Could not find Lambda function ARN in stack outputs")

            # Create API Gateway
            api = self.apigw.create_rest_api(
                name='KeyRotationApi',
                description='API for IAM key rotation'
            )
            logger.info(f"Created API Gateway: {api['id']}")

            # Create API key
            api_key = self.apigw.create_api_key(
                name='KeyRotationApiKey',
                description='API key for key rotation system',
                enabled=True
            )
            logger.info(f"Created new permanent API key: {api_key['id']}")

            # Store API key in Secrets Manager
            self.secrets.create_secret(
                Name='key-rotation-api-key',
                SecretString=json.dumps({'api_key': api_key['value']})
            )
            logger.info("Stored API key in Secrets Manager")

            # Create usage plan and associate with API key
            usage_plan = self.apigw.create_usage_plan(
                name='KeyRotationUsagePlan',
                apiStages=[
                    {
                        'apiId': api['id'],
                        'stage': 'prod'
                    }
                ]
            )
            self.apigw.create_usage_plan_key(
                usagePlanId=usage_plan['id'],
                keyId=api_key['id'],
                keyType='API_KEY'
            )

            logger.info("API Gateway setup completed successfully")
            logger.info(f"API Key: {api_key['value']}")
            return True
        except Exception as e:
            logger.error(f"Failed to set up API Gateway: {str(e)}")
            return False

    def setup_initial_keys(self):
        """Set up initial access keys for all IAM users."""
        logger.info("Setting up initial access keys...")
        
        # Get all IAM users
        paginator = self.iam.get_paginator('list_users')
        users = []
        for page in paginator.paginate():
            users.extend(page['Users'])

        logger.info(f"Found {len(users)} IAM users")
        success_count = 0

        for user in users:
            username = user['UserName']
            logger.info(f"Processing user: {username}")

            # Skip users in exemption group
            if self.is_user_exempt(username):
                logger.info(f"Skipping exempt user: {username}")
                continue

            try:
                # List existing keys
                existing_keys = self.iam.list_access_keys(UserName=username)
                
                # Delete existing keys
                for key in existing_keys['AccessKeyMetadata']:
                    logger.info(f"Deleting existing key {key['AccessKeyId']} for user {username}")
                    self.iam.delete_access_key(
                        UserName=username,
                        AccessKeyId=key['AccessKeyId']
                    )
                    time.sleep(1)  # Small delay to avoid rate limits

                # Create new access key
                new_key = self.iam.create_access_key(UserName=username)
                access_key = new_key['AccessKey']['AccessKeyId']
                secret_key = new_key['AccessKey']['SecretAccessKey']

                # Store in Secrets Manager
                if self.store_in_secrets_manager(username, access_key, secret_key, user.get('Email')):
                    # Send email notification
                    self.send_email(
                        user.get('Email', self.sender_email),
                        'AWS IAM Access Key Created',
                        f'New IAM access key has been created for your account: {access_key}'
                    )
                    success_count += 1
                    logger.info(f"Successfully set up new key for user {username}")

            except Exception as e:
                logger.error(f"Failed to process user {username}: {str(e)}")
                continue

        logger.info(f"Successfully set up credentials for {success_count} users")

    def get_account_id(self):
        """Get AWS account ID."""
        sts = boto3.client('sts')
        return sts.get_caller_identity()['Account']

    def is_user_exempt(self, username):
        """Check if user is in exemption group."""
        try:
            response = self.iam.list_groups_for_user(UserName=username)
            for group in response['Groups']:
                if group['GroupName'] == 'IAMKeyRotationExemptionGroup':
                    return True
            return False
        except Exception as e:
            logger.error(f"Failed to check user exemption: {str(e)}")
            return False

    def store_in_secrets_manager(self, username, access_key, secret_key, email=None):
        """Store credentials in Secrets Manager with state tracking."""
        try:
            secret_name = f'iam-key-rotation/{username}'
            secret_value = {
                'AccessKeyId': access_key,
                'SecretAccessKey': secret_key,
                'CreationDate': datetime.now(timezone.utc).isoformat(),
                'State': 'ACTIVE',
                'Email': email or self.sender_email
            }
            
            try:
                # Try to create new secret
                self.secrets.create_secret(
                    Name=secret_name,
                    SecretString=json.dumps(secret_value)
                )
                logger.info(f"Created new secret in Secrets Manager for {username}")
            except ClientError as e:
                if e.response['Error']['Code'] == 'ResourceExistsException':
                    # Update existing secret
                    self.secrets.update_secret(
                        SecretId=secret_name,
                        SecretString=json.dumps(secret_value)
                    )
                    logger.info(f"Updated existing secret in Secrets Manager for {username}")
                else:
                    raise
            
            return True
        except Exception as e:
            logger.error(f"Failed to store credentials for {username}: {str(e)}")
            return False

    def send_email(self, to_email, subject, body):
        """Send email notification."""
        try:
            response = self.ses.send_email(
                Source=self.sender_email,
                Destination={'ToAddresses': [to_email]},
                Message={
                    'Subject': {'Data': subject},
                    'Body': {'Text': {'Data': body}}
                }
            )
            logger.info(f"Email sent successfully: {response['MessageId']}")
            return True
        except Exception as e:
            logger.error(f"Failed to send email: {str(e)}")
            return False

def deploy_stack(sender_email):
    try:
        logger.info("Starting deployment...")
        cf = boto3.client('cloudformation')
        
        # Read the template file
        with open('key_rotation_minimal.yaml', 'r') as f:
            template_body = f.read()
        
        # Check if stack exists
        try:
            cf.describe_stacks(StackName='iam-key-rotation')
            logger.info("Stack exists, updating...")
            cf.update_stack(
                StackName='iam-key-rotation',
                TemplateBody=template_body,
                Parameters=[
                    {
                        'ParameterKey': 'SenderEmail',
                        'ParameterValue': sender_email
                    }
                ],
                Capabilities=['CAPABILITY_IAM']
            )
        except cf.exceptions.ClientError as e:
            if 'does not exist' in str(e):
                logger.info("Stack does not exist, creating...")
                cf.create_stack(
                    StackName='iam-key-rotation',
                    TemplateBody=template_body,
                    Parameters=[
                        {
                            'ParameterKey': 'SenderEmail',
                            'ParameterValue': sender_email
                        }
                    ],
                    Capabilities=['CAPABILITY_IAM']
                )
            else:
                raise
        
        logger.info("Deployment completed successfully")
    except Exception as e:
        logger.error(f"Error in deploy_stack: {str(e)}")
        raise

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--sender-email', required=True, help='Email address to send notifications from')
    parser.add_argument('action', choices=['cleanup', 'deploy', 'setup', 'all'], help='Action to perform')
    args = parser.parse_args()
    
    try:
        if args.action in ['deploy', 'all']:
            deploy_stack(args.sender_email)
    except Exception as e:
        logger.error(f"Error in main: {str(e)}")
        raise

if __name__ == '__main__':
    main() 