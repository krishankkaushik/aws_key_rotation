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
    def __init__(self, admin_email, sender_email, stack_name, region):
        self.admin_email = admin_email
        self.sender_email = sender_email
        self.stack_name = stack_name
        self.region = region
        
        # Initialize AWS clients
        self.cf = boto3.client('cloudformation', region_name=region)
        self.iam = boto3.client('iam', region_name=region)
        self.ses = boto3.client('ses', region_name=region)
        self.secrets = boto3.client('secretsmanager', region_name=region)
        self.apigateway = boto3.client('apigateway', region_name=region)

    def verify_ses_email(self, email):
        """Verify email address in SES."""
        try:
            self.ses.verify_email_identity(EmailAddress=email)
            logger.info(f"Verification email sent to {email}")
            return True
        except ClientError as e:
            logger.error(f"Error verifying email {email}: {str(e)}")
            return False

    def create_test_user(self, username):
        """Create a test IAM user."""
        try:
            self.iam.create_user(UserName=username)
            logger.info(f"Created IAM user: {username}")
            return True
        except ClientError as e:
            if e.response['Error']['Code'] == 'EntityAlreadyExists':
                logger.info(f"User {username} already exists")
                return True
            logger.error(f"Error creating user {username}: {str(e)}")
            return False

    def deploy_cloudformation(self):
        """Deploy or update the CloudFormation stack."""
        try:
            # Read the template file
            with open('key_rotation.yaml', 'r') as f:
                template_body = f.read()

            # Check if stack exists
            try:
                self.cf.describe_stacks(StackName=self.stack_name)
                stack_exists = True
                logger.info(f"Stack {self.stack_name} exists, updating...")
            except ClientError:
                stack_exists = False
                logger.info(f"Stack {self.stack_name} does not exist, creating...")

            # Prepare parameters
            parameters = [
                {
                    'ParameterKey': 'AdminEmail',
                    'ParameterValue': self.admin_email
                },
                {
                    'ParameterKey': 'SenderEmail',
                    'ParameterValue': self.sender_email
                }
            ]

            if stack_exists:
                # Update existing stack
                response = self.cf.update_stack(
                    StackName=self.stack_name,
                    TemplateBody=template_body,
                    Parameters=parameters,
                    Capabilities=['CAPABILITY_IAM']
                )
                logger.info(f"Updating stack {self.stack_name}...")
                waiter = self.cf.get_waiter('stack_update_complete')
            else:
                # Create new stack
                response = self.cf.create_stack(
                    StackName=self.stack_name,
                    TemplateBody=template_body,
                    Parameters=parameters,
                    Capabilities=['CAPABILITY_IAM']
                )
                logger.info(f"Creating stack {self.stack_name}...")
                waiter = self.cf.get_waiter('stack_create_complete')

            # Wait for stack operation to complete
            waiter.wait(StackName=self.stack_name)
            logger.info("Stack operation completed")

            # Get stack outputs
            response = self.cf.describe_stacks(StackName=self.stack_name)
            outputs = response['Stacks'][0]['Outputs']
            
            # Store API endpoint in Secrets Manager
            api_endpoint = next((o['OutputValue'] for o in outputs if o['OutputKey'] == 'ApiEndpoint'), None)
            if api_endpoint:
                try:
                    self.secrets.create_secret(
                        Name='api-endpoint',
                        SecretString=json.dumps({'endpoint': api_endpoint}),
                        Description='API Gateway endpoint for key rotation'
                    )
                except ClientError as e:
                    if e.response['Error']['Code'] == 'ResourceExistsException':
                        # Update existing secret
                        self.secrets.put_secret_value(
                            SecretId='api-endpoint',
                            SecretString=json.dumps({'endpoint': api_endpoint})
                        )
                logger.info(f"Stored API endpoint in Secrets Manager")

            return True
        except ClientError as e:
            if e.response['Error']['Code'] == 'ValidationError' and 'No updates are to be performed' in str(e):
                logger.info("No updates needed for the stack")
                return True
            logger.error(f"Error deploying stack: {str(e)}")
            return False

    def setup_api_gateway(self):
        """Set up API Gateway with API key requirement."""
        try:
            # Create API
            api = self.apigateway.create_rest_api(
                name='KeyRotationAPI',
                description='API for AWS IAM key rotation'
            )
            
            # Get root resource
            resources = self.apigateway.get_resources(restApiId=api['id'])
            root_id = resources['items'][0]['id']
            
            # Create resource
            resource = self.apigateway.create_resource(
                restApiId=api['id'],
                parentId=root_id,
                pathPart='credentials'
            )
            
            # Create method
            self.apigateway.put_method(
                restApiId=api['id'],
                resourceId=resource['id'],
                httpMethod='GET',
                authorizationType='NONE',
                apiKeyRequired=True
            )
            
            # Create integration with Lambda
            lambda_arn = f"arn:aws:apigateway:{self.region}:lambda:path/2015-03-31/functions/{self.get_lambda_function_arn()}/invocations"
            self.apigateway.put_integration(
                restApiId=api['id'],
                resourceId=resource['id'],
                httpMethod='GET',
                type='AWS_PROXY',
                integrationHttpMethod='POST',
                uri=lambda_arn
            )
            
            # Create deployment
            deployment = self.apigateway.create_deployment(
                restApiId=api['id'],
                stageName='prod'
            )
            
            # Create API key
            api_key = self.apigateway.create_api_key(
                name='KeyRotationAPIKey',
                description='API key for key rotation',
                enabled=True
            )
            
            # Create usage plan
            usage_plan = self.apigateway.create_usage_plan(
                name='KeyRotationUsagePlan',
                description='Usage plan for key rotation API',
                apiStages=[
                    {
                        'apiId': api['id'],
                        'stage': 'prod'
                    }
                ]
            )
            
            # Associate API key with usage plan
            self.apigateway.create_usage_plan_key(
                usagePlanId=usage_plan['id'],
                keyId=api_key['id'],
                keyType='API_KEY'
            )
            
            # Store API key in Secrets Manager
            try:
                self.secrets.create_secret(
                    Name='api-key',
                    SecretString=json.dumps({'key': api_key['value']}),
                    Description='API key for key rotation API'
                )
            except ClientError as e:
                if e.response['Error']['Code'] == 'ResourceExistsException':
                    self.secrets.put_secret_value(
                        SecretId='api-key',
                        SecretString=json.dumps({'key': api_key['value']})
                    )
            
            logger.info("API Gateway setup completed")
            return True
        except ClientError as e:
            logger.error(f"Error setting up API Gateway: {str(e)}")
            return False

    def get_lambda_function_arn(self):
        """Get the ARN of the Lambda function from CloudFormation stack outputs."""
        try:
            response = self.cf.describe_stacks(StackName=self.stack_name)
            outputs = response['Stacks'][0]['Outputs']
            lambda_arn = next((o['OutputValue'] for o in outputs if o['OutputKey'] == 'LambdaFunctionArn'), None)
            if not lambda_arn:
                raise ValueError("Lambda function ARN not found in stack outputs")
            return lambda_arn
        except Exception as e:
            logger.error(f"Error getting Lambda function ARN: {str(e)}")
            raise

    def list_iam_users(self):
        """List existing IAM users."""
        try:
            response = self.iam.list_users()
            users = response['Users']
            logger.info(f"Found {len(users)} existing IAM users")
            for user in users:
                logger.info(f"User: {user['UserName']}")
            return users
        except ClientError as e:
            logger.error(f"Error listing IAM users: {str(e)}")
            return []

    def deploy(self):
        """Deploy the entire solution."""
        try:
            # List existing users
            existing_users = self.list_iam_users()
            if not existing_users:
                logger.warning("No existing IAM users found. Please create IAM users before deploying.")
                return False

            # Deploy CloudFormation stack
            if not self.deploy_cloudformation():
                return False

            # Setup API Gateway
            if not self.setup_api_gateway():
                return False

            logger.info("Deployment completed successfully!")
            logger.info("The key rotation system will now manage access keys for your existing IAM users.")
            return True
        except Exception as e:
            logger.error(f"Error during deployment: {str(e)}")
            return False

    def cleanup(self):
        """Clean up all resources."""
        try:
            # Delete CloudFormation stack
            try:
                logger.info(f"Deleting stack {self.stack_name}...")
                self.cf.delete_stack(StackName=self.stack_name)
                waiter = self.cf.get_waiter('stack_delete_complete')
                waiter.wait(StackName=self.stack_name)
                logger.info("Stack deleted successfully")
            except ClientError as e:
                if e.response['Error']['Code'] == 'ValidationError' and 'does not exist' in str(e):
                    logger.info("Stack does not exist")
                else:
                    raise

            # Delete API endpoint secret
            try:
                logger.info("Deleting API endpoint secret...")
                self.secrets.delete_secret(
                    SecretId='api-endpoint',
                    ForceDeleteWithoutRecovery=True
                )
                logger.info("API endpoint secret deleted successfully")
            except ClientError as e:
                if e.response['Error']['Code'] == 'ResourceNotFoundException':
                    logger.info("API endpoint secret does not exist")
                else:
                    raise

            # Delete API key secret
            try:
                logger.info("Deleting API key secret...")
                self.secrets.delete_secret(
                    SecretId='api-key',
                    ForceDeleteWithoutRecovery=True
                )
                logger.info("API key secret deleted successfully")
            except ClientError as e:
                if e.response['Error']['Code'] == 'ResourceNotFoundException':
                    logger.info("API key secret does not exist")
                else:
                    raise

            logger.info("Cleanup completed successfully")
            return True
        except Exception as e:
            logger.error(f"Error during cleanup: {str(e)}")
            return False

def main():
    parser = argparse.ArgumentParser(description='Deploy AWS IAM Key Rotation Solution')
    parser.add_argument('--admin-email', required=True, help='Admin email address')
    parser.add_argument('--sender-email', required=True, help='Sender email address')
    parser.add_argument('--stack-name', default='iam-key-rotation', help='CloudFormation stack name')
    parser.add_argument('--region', default='us-east-1', help='AWS region')
    parser.add_argument('--cleanup', action='store_true', help='Clean up all resources before deployment')
    
    args = parser.parse_args()
    
    deployer = KeyRotationDeployer(
        admin_email=args.admin_email,
        sender_email=args.sender_email,
        stack_name=args.stack_name,
        region=args.region
    )
    
    if args.cleanup:
        if not deployer.cleanup():
            sys.exit(1)
    
    if not deployer.deploy():
        sys.exit(1)

if __name__ == '__main__':
    main() 