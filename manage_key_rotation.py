#!/usr/bin/env python3

import boto3
import logging
import sys
import time
import argparse
from botocore.exceptions import ClientError
from botocore.config import Config
import json

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
    def __init__(self):
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

    def cleanup(self):
        """Clean up all AWS resources."""
        logger.info("Starting cleanup...")
        
        # 1. Delete API Gateway
        logger.info("Cleaning up API Gateway...")
        apis = self.apigw.get_rest_apis()
        for api in apis['items']:
            if api['name'] == 'key-rotation-api':
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
        rules = self.events.list_rules(NamePrefix='key-rotation')
        for rule in rules['Rules']:
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
        secrets_list = self.secrets.list_secrets()
        for secret in secrets_list['SecretList']:
            if secret['Name'].startswith('test-user-'):
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
        with open('key_rotation.yaml', 'r') as f:
            template_body = f.read()
        
        # Create or update the stack
        try:
            self.cloudformation.create_stack(
                StackName='iam-key-rotation',
                TemplateBody=template_body,
                Capabilities=['CAPABILITY_IAM'],
                Parameters=[
                    {
                        'ParameterKey': 'RotationInterval',
                        'ParameterValue': '10'
                    },
                    {
                        'ParameterKey': 'DeactivationInterval',
                        'ParameterValue': '12'
                    },
                    {
                        'ParameterKey': 'DeletionInterval',
                        'ParameterValue': '15'
                    },
                    {
                        'ParameterKey': 'SenderEmail',
                        'ParameterValue': 'krishank.kaushik.1@gmail.com'
                    }
                ]
            )
            logger.info("Creating CloudFormation stack...")
        except ClientError as e:
            if e.response['Error']['Code'] == 'AlreadyExistsException':
                self.cloudformation.update_stack(
                    StackName='iam-key-rotation',
                    TemplateBody=template_body,
                    Capabilities=['CAPABILITY_IAM'],
                    Parameters=[
                        {
                            'ParameterKey': 'RotationInterval',
                            'ParameterValue': '10'
                        },
                        {
                            'ParameterKey': 'DeactivationInterval',
                            'ParameterValue': '12'
                        },
                        {
                            'ParameterKey': 'DeletionInterval',
                            'ParameterValue': '15'
                        },
                        {
                            'ParameterKey': 'SenderEmail',
                            'ParameterValue': 'krishank.kaushik.1@gmail.com'
                        }
                    ]
                )
                logger.info("Updating CloudFormation stack...")
            else:
                raise

        # Wait for stack creation/update
        try:
            waiter = self.cloudformation.get_waiter('stack_create_complete')
            waiter.wait(StackName='iam-key-rotation')
            logger.info("CloudFormation stack created successfully")
        except:
            waiter = self.cloudformation.get_waiter('stack_update_complete')
            waiter.wait(StackName='iam-key-rotation')
            logger.info("CloudFormation stack updated successfully")

        # Get the Lambda function name
        resources = self.cloudformation.list_stack_resources(StackName='iam-key-rotation')
        lambda_function = next((r for r in resources['StackResourceSummaries'] 
                              if r['ResourceType'] == 'AWS::Lambda::Function'), None)
        
        if lambda_function:
            logger.info(f"Lambda function created: {lambda_function['PhysicalResourceId']}")
        else:
            logger.error("Lambda function not found in stack resources")
            return False

        return True

    def setup_api(self):
        """Set up API Gateway."""
        logger.info("Setting up API Gateway...")
        
        # Get Lambda function ARN
        lambda_function = self.lambda_client.get_function(
            FunctionName='iam-key-rotation-KeyRotationFunction-tSqkEMN96R3N'
        )
        lambda_arn = lambda_function['Configuration']['FunctionArn']
        
        # Create REST API
        api = self.apigw.create_rest_api(
            name='key-rotation-api',
            description='API for AWS key rotation system'
        )
        self.api_id = api['id']
        logger.info(f"Created API Gateway: {self.api_id}")
        
        # Get root resource ID
        resources = self.apigw.get_resources(restApiId=self.api_id)
        root_id = resources['items'][0]['id']
        
        # Create /credentials resource
        credentials_resource = self.apigw.create_resource(
            restApiId=self.api_id,
            parentId=root_id,
            pathPart='credentials'
        )
        credentials_id = credentials_resource['id']
        
        # Create /credentials/{username} resource
        username_resource = self.apigw.create_resource(
            restApiId=self.api_id,
            parentId=credentials_id,
            pathPart='{username}'
        )
        username_id = username_resource['id']
        
        # Create /export-credentials resource
        export_resource = self.apigw.create_resource(
            restApiId=self.api_id,
            parentId=root_id,
            pathPart='export-credentials'
        )
        export_id = export_resource['id']
        
        # Create Lambda permission for API Gateway
        try:
            source_arn = f'arn:aws:execute-api:{self.region}:{self.get_account_id()}:{self.api_id}/*/*/*'
            self.lambda_client.add_permission(
                FunctionName=lambda_arn,
                StatementId='apigateway-invoke',
                Action='lambda:InvokeFunction',
                Principal='apigateway.amazonaws.com',
                SourceArn=source_arn
            )
            logger.info(f"Added Lambda permission with source ARN: {source_arn}")
        except ClientError as e:
            if e.response['Error']['Code'] != 'ResourceConflictException':
                raise
            logger.info("Lambda permission already exists")
        
        # Create methods and integrations
        # GET /credentials/{username}
        self.apigw.put_method(
            restApiId=self.api_id,
            resourceId=username_id,
            httpMethod='GET',
            authorizationType='NONE',
            apiKeyRequired=True
        )
        
        # Add CORS configuration
        self.apigw.put_method_response(
            restApiId=self.api_id,
            resourceId=username_id,
            httpMethod='GET',
            statusCode='200',
            responseParameters={
                'method.response.header.Access-Control-Allow-Origin': True,
                'method.response.header.Access-Control-Allow-Headers': True
            }
        )
        
        self.apigw.put_integration(
            restApiId=self.api_id,
            resourceId=username_id,
            httpMethod='GET',
            type='AWS_PROXY',
            integrationHttpMethod='POST',
            uri=f'arn:aws:apigateway:{self.region}:lambda:path/2015-03-31/functions/{lambda_arn}/invocations'
        )
        
        # POST /credentials/{username}
        self.apigw.put_method(
            restApiId=self.api_id,
            resourceId=username_id,
            httpMethod='POST',
            authorizationType='NONE',
            apiKeyRequired=True
        )
        
        # Add CORS configuration
        self.apigw.put_method_response(
            restApiId=self.api_id,
            resourceId=username_id,
            httpMethod='POST',
            statusCode='200',
            responseParameters={
                'method.response.header.Access-Control-Allow-Origin': True,
                'method.response.header.Access-Control-Allow-Headers': True
            }
        )
        
        self.apigw.put_integration(
            restApiId=self.api_id,
            resourceId=username_id,
            httpMethod='POST',
            type='AWS_PROXY',
            integrationHttpMethod='POST',
            uri=f'arn:aws:apigateway:{self.region}:lambda:path/2015-03-31/functions/{lambda_arn}/invocations'
        )
        
        # POST /export-credentials
        self.apigw.put_method(
            restApiId=self.api_id,
            resourceId=export_id,
            httpMethod='POST',
            authorizationType='NONE',
            apiKeyRequired=True
        )
        
        # Add CORS configuration
        self.apigw.put_method_response(
            restApiId=self.api_id,
            resourceId=export_id,
            httpMethod='POST',
            statusCode='200',
            responseParameters={
                'method.response.header.Access-Control-Allow-Origin': True,
                'method.response.header.Access-Control-Allow-Headers': True
            }
        )
        
        self.apigw.put_integration(
            restApiId=self.api_id,
            resourceId=export_id,
            httpMethod='POST',
            type='AWS_PROXY',
            integrationHttpMethod='POST',
            uri=f'arn:aws:apigateway:{self.region}:lambda:path/2015-03-31/functions/{lambda_arn}/invocations'
        )
        
        # Create deployment
        deployment = self.apigw.create_deployment(
            restApiId=self.api_id,
            stageName='prod'
        )
        
        # Wait for deployment to complete
        logger.info("Waiting for API deployment to complete...")
        time.sleep(10)
        
        # Create new permanent API key
        api_key = self.apigw.create_api_key(
            name='key-rotation-api-key',
            enabled=True,
            description='Permanent API key for key rotation system'
        )
        logger.info(f"Created new permanent API key: {api_key['id']}")
        api_key_id = api_key['id']
        
        # Get API key value
        api_key_details = self.apigw.get_api_key(
            apiKey=api_key['id'],
            includeValue=True
        )
        self.api_key = api_key_details['value']
        
        # Store API key in Secrets Manager
        try:
            self.secrets.create_secret(
                Name='key-rotation-api-key',
                SecretString=json.dumps({'api_key': self.api_key}),
                Description='Permanent API key for key rotation system'
            )
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceExistsException':
                self.secrets.update_secret(
                    SecretId='key-rotation-api-key',
                    SecretString=json.dumps({'api_key': self.api_key})
                )
        logger.info("Stored API key in Secrets Manager")
        
        # Create usage plan
        usage_plan = self.apigw.create_usage_plan(
            name='key-rotation-usage-plan',
            apiStages=[
                {
                    'apiId': self.api_id,
                    'stage': 'prod'
                }
            ],
            throttle={
                'rateLimit': 1000,
                'burstLimit': 2000
            }
        )
        
        # Associate API key with usage plan
        self.apigw.create_usage_plan_key(
            usagePlanId=usage_plan['id'],
            keyId=api_key_id,
            keyType='API_KEY'
        )
        
        # Enable API key for the stage
        self.apigw.update_stage(
            restApiId=self.api_id,
            stageName='prod',
            patchOperations=[
                {
                    'op': 'replace',
                    'path': '/*/*/throttling/rateLimit',
                    'value': '1000'
                },
                {
                    'op': 'replace',
                    'path': '/*/*/throttling/burstLimit',
                    'value': '2000'
                }
            ]
        )
        
        logger.info("API Gateway setup completed successfully")
        logger.info(f"API Key: {self.api_key}")
        return self.api_id, self.api_key

    def setup_initial_keys(self):
        """Set up initial access keys for all users."""
        logger.info("Setting up initial access keys...")
        
        # List all IAM users
        users = self.iam.list_users()['Users']
        logger.info(f"Found {len(users)} IAM users")
        
        success_count = 0
        for user in users:
            username = user['UserName']
            if not username.startswith('test-user-'):
                continue
                
            logger.info(f"Processing user: {username}")
            
            # Get user's email
            email = self.get_user_email(username)
            
            # Create access key
            access_key = self.create_access_key(username)
            if not access_key:
                continue
                
            # Store in Secrets Manager
            if not self.store_in_secrets_manager(
                username, 
                access_key['AccessKeyId'], 
                access_key['SecretAccessKey'],
                email
            ):
                continue
                
            # Send email
            if self.send_credentials_email(
                email,
                username,
                access_key['AccessKeyId'],
                access_key['SecretAccessKey']
            ):
                success_count += 1
                
        logger.info(f"Successfully set up credentials for {success_count} users")

    def get_account_id(self):
        """Get AWS account ID."""
        sts = boto3.client('sts')
        return sts.get_caller_identity()['Account']

    def get_user_email(self, username):
        """Get user's email from IAM tags."""
        try:
            response = self.iam.get_user(UserName=username)
            email = next((tag['Value'] for tag in response['User']['Tags'] 
                         if tag['Key'] == 'email'), None)
            return email
        except ClientError as e:
            logger.error(f"Error getting email for {username}: {str(e)}")
            return None

    def create_access_key(self, username):
        """Create a new access key for the user."""
        try:
            response = self.iam.create_access_key(UserName=username)
            return response['AccessKey']
        except ClientError as e:
            logger.error(f"Error creating access key for {username}: {str(e)}")
            return None

    def store_in_secrets_manager(self, username, access_key, secret_key, email):
        """Store credentials in Secrets Manager."""
        try:
            secret_value = {
                'AccessKeyId': access_key,
                'SecretAccessKey': secret_key,
                'CreatedDate': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'Email': email
            }
            
            try:
                self.secrets.create_secret(
                    Name=username,
                    SecretString=json.dumps(secret_value),
                    Description=f'AWS credentials for {username}'
                )
            except ClientError as e:
                if e.response['Error']['Code'] == 'ResourceExistsException':
                    self.secrets.update_secret(
                        SecretId=username,
                        SecretString=json.dumps(secret_value)
                    )
                else:
                    raise
                    
            logger.info(f"Stored credentials in Secrets Manager for {username}")
            return True
        except ClientError as e:
            logger.error(f"Error storing credentials for {username}: {str(e)}")
            return False

    def send_credentials_email(self, email, username, access_key, secret_key):
        """Send credentials email to user."""
        if not email:
            logger.warning(f"No email found for {username}, skipping email notification")
            return False
            
        try:
            # Get API Gateway endpoint and key
            api_endpoint = f"https://{self.api_id}.execute-api.{self.region}.amazonaws.com/prod"
            
            # Create email body
            body = f"""Hello,

Your AWS credentials have been set up successfully.

You can use these credentials to access AWS services. The credentials are also stored in AWS Secrets Manager.

To access your credentials programmatically, you can use the following API endpoint:
{api_endpoint}

Your API Key: {self.api_key}

Example API calls:

1. Get your credentials:
curl -H "X-API-Key: {self.api_key}" {api_endpoint}/credentials/{username}

2. Create new credentials (if needed):
curl -X POST -H "X-API-Key: {self.api_key}" {api_endpoint}/credentials/{username}

3. Export all credentials:
curl -X POST -H "X-API-Key: {self.api_key}" {api_endpoint}/export-credentials

Important Security Notes:
1. Keep these credentials secure and never share them
2. The system will automatically rotate your keys every 10 minutes
3. You will receive email notifications for key rotation events
4. Old keys will be automatically deactivated after 12 minutes
5. Deactivated keys will be deleted after 15 minutes

If you have any questions, please contact your system administrator.

Best regards,
AWS Key Rotation System
"""
            
            # Send email
            self.ses.send_email(
                Source='krishank.kaushik.1@gmail.com',
                Destination={'ToAddresses': [email]},
                Message={
                    'Subject': {'Data': f'AWS Credentials for {username}'},
                    'Body': {'Text': {'Data': body}}
                }
            )
            
            logger.info(f"Sent credentials email to {email}")
            return True
            
        except ClientError as e:
            logger.error(f"Error sending email to {email}: {str(e)}")
            return False

def main():
    """Main function."""
    parser = argparse.ArgumentParser(description='Manage AWS Key Rotation System')
    parser.add_argument('action', choices=['cleanup', 'deploy', 'setup', 'all'],
                      help='Action to perform: cleanup, deploy, setup, or all')
    parser.add_argument('--sender-email', required=True, help='Email address for sending notifications')
    args = parser.parse_args()
    
    try:
        manager = KeyRotationManager()
        
        if args.action == 'cleanup':
            manager.cleanup()
        elif args.action == 'deploy':
            manager.deploy()
        elif args.action == 'setup':
            manager.setup_api()
            manager.setup_initial_keys()
        elif args.action == 'all':
            manager.cleanup()
            if manager.deploy():
                manager.setup_api()
                manager.setup_initial_keys()
        
    except Exception as e:
        logger.error(f"Error in main: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main() 