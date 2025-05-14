import json
import boto3
import os
import logging
from datetime import datetime, timedelta
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

iam = boto3.client('iam')
secrets = boto3.client('secretsmanager')
ses = boto3.client('ses')

def send_email(to_email, subject, body):
    try:
        # Get API details from Secrets Manager
        api_key_secret = json.loads(secrets.get_secret_value(SecretId='key-rotation-api-key')['SecretString'])
        api_key = api_key_secret['api_key']
        
        # Get API endpoint from CloudFormation stack
        cf = boto3.client('cloudformation')
        stack = cf.describe_stacks(StackName='iam-key-rotation')
        api_endpoint = None
        for output in stack['Stacks'][0]['Outputs']:
            if output['OutputKey'] == 'ApiEndpoint':
                api_endpoint = output['OutputValue']
                break
        
        if subject == 'AWS IAM Access Key Created':
            body = f"""Hello,

Your AWS credentials have been set up successfully.

You can use these credentials to access AWS services. The credentials are also stored in AWS Secrets Manager.

To access your credentials programmatically, you can use the following API endpoint:
{api_endpoint}

Your API Key: {api_key}

Example API calls:

1. Get your credentials:
curl -H "X-API-Key: {api_key}" {api_endpoint}/credentials/{body.split(': ')[-1]}

2. Create new credentials (if needed):
curl -X POST -H "X-API-Key: {api_key}" {api_endpoint}/credentials/{body.split(': ')[-1]}

3. Export all credentials:
curl -X POST -H "X-API-Key: {api_key}" {api_endpoint}/export-credentials

Important Security Notes:
1. Keep these credentials secure and never share them
2. The system will automatically rotate your keys every 10 minutes
3. You will receive email notifications for key rotation events
4. Old keys will be automatically deactivated after 12 minutes
5. Deactivated keys will be deleted after 15 minutes

If you have any questions, please contact your system administrator.

Best regards,
AWS Key Rotation System"""
        elif subject == 'AWS IAM Access Key Rotation':
            body = f"""Hello,

Your IAM access key has been rotated.

New key: {body.split(': ')[-1]}

You can access your new credentials using the API endpoint:
{api_endpoint}

Your API Key: {api_key}

Important Security Notes:
1. Your old key will be deactivated in 2 minutes
2. The deactivated key will be deleted after 3 more minutes
3. Please update your applications with the new credentials

Best regards,
AWS Key Rotation System"""
        elif subject == 'AWS IAM Access Key Deactivated':
            body = f"""Hello,

Your old IAM access key has been deactivated.

Key ID: {body.split(': ')[-1]}

Important Security Notes:
1. The deactivated key will be deleted in 3 minutes
2. Please ensure you are using your new active key

Best regards,
AWS Key Rotation System"""
        elif subject == 'AWS IAM Access Key Deleted':
            body = f"""Hello,

Your old IAM access key has been deleted.

Important Security Notes:
1. Please ensure you are using your new active key
2. If you need to create new credentials, use the API endpoint:
{api_endpoint}

Your API Key: {api_key}

Best regards,
AWS Key Rotation System"""

        response = ses.send_email(
            Source=os.environ['SENDER_EMAIL'],
            Destination={'ToAddresses': [to_email]},
            Message={
                'Subject': {'Data': subject},
                'Body': {'Text': {'Data': body}}
            }
        )
        logger.info(f"Email sent successfully: {response['MessageId']}")
    except Exception as e:
        logger.error(f"Failed to send email: {str(e)}")

def get_user_email(username):
    try:
        response = iam.get_user(UserName=username)
        return response['User'].get('Email', os.environ['SENDER_EMAIL'])
    except Exception as e:
        logger.error(f"Failed to get user email: {str(e)}")
        return os.environ['SENDER_EMAIL']

def handler(event, context):
    logger.info(f"Received event: {json.dumps(event)}")
    
    # Handle API Gateway events
    if 'httpMethod' in event:
        return handle_api_request(event)
    
    # Handle scheduled rotation events
    return handle_rotation_event()

def handle_api_request(event):
    try:
        http_method = event['httpMethod']
        path = event['path']
        
        if http_method == 'GET' and path == '/status':
            return {
                'statusCode': 200,
                'body': json.dumps({'status': 'healthy'})
            }
        
        if http_method == 'POST' and path == '/rotate':
            body = json.loads(event['body'])
            username = body.get('username')
            
            if not username:
                return {
                    'statusCode': 400,
                    'body': json.dumps({'error': 'username is required'})
                }
            
            # Force immediate rotation
            rotate_user_key(username, force=True)
            return {
                'statusCode': 200,
                'body': json.dumps({'message': f'Rotation initiated for {username}'})
            }
        
        return {
            'statusCode': 404,
            'body': json.dumps({'error': 'Not found'})
        }
    except Exception as e:
        logger.error(f"API request failed: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def handle_rotation_event():
    try:
        # Get all secrets
        paginator = secrets.get_paginator('list_secrets')
        for page in paginator.paginate():
            for secret in page['SecretList']:
                if not secret['Name'].startswith('iam-key-rotation/'):
                    continue
                
                username = secret['Name'].split('/')[-1]
                secret_value = json.loads(secrets.get_secret_value(SecretId=secret['Name'])['SecretString'])
                
                # Check if user is exempt
                if is_user_exempt(username):
                    continue
                
                # Get key creation time
                key_creation_time = datetime.fromisoformat(secret_value.get('CreationDate', datetime.now().isoformat()))
                current_time = datetime.now()
                
                # Calculate time differences in minutes
                minutes_since_creation = (current_time - key_creation_time).total_seconds() / 60
                
                logger.info(f"Processing {username}: {minutes_since_creation} minutes since creation")
                
                # Handle rotation based on time thresholds
                if minutes_since_creation >= float(os.environ['DELETION_PERIOD']):
                    # Delete old key
                    logger.info(f"Deleting key for {username} after {minutes_since_creation} minutes")
                    delete_old_key(username, secret_value)
                elif minutes_since_creation >= float(os.environ['INACTIVE_PERIOD']):
                    # Deactivate old key
                    logger.info(f"Deactivating key for {username} after {minutes_since_creation} minutes")
                    deactivate_old_key(username, secret_value)
                elif minutes_since_creation >= float(os.environ['ROTATION_PERIOD']):
                    # Rotate key
                    logger.info(f"Rotating key for {username} after {minutes_since_creation} minutes")
                    rotate_user_key(username)
        
        return {'statusCode': 200, 'body': 'Rotation cycle completed'}
    except Exception as e:
        logger.error(f"Rotation event failed: {str(e)}")
        return {'statusCode': 500, 'body': str(e)}

def is_user_exempt(username):
    try:
        response = iam.list_groups_for_user(UserName=username)
        for group in response['Groups']:
            if group['GroupName'] == 'IAMKeyRotationExemptionGroup':
                return True
        return False
    except Exception as e:
        logger.error(f"Failed to check user exemption: {str(e)}")
        return False

def rotate_user_key(username, force=False):
    try:
        # Get current secret
        secret_name = f'iam-key-rotation/{username}'
        secret_value = json.loads(secrets.get_secret_value(SecretId=secret_name)['SecretString'])
        
        # Create new key
        new_key = iam.create_access_key(UserName=username)
        
        # Update secret with new key and mark old key for deactivation
        secret_value.update({
            'OldAccessKeyId': secret_value['AccessKeyId'],
            'OldSecretAccessKey': secret_value['SecretAccessKey'],
            'AccessKeyId': new_key['AccessKey']['AccessKeyId'],
            'SecretAccessKey': new_key['AccessKey']['SecretAccessKey'],
            'CreationDate': datetime.now().isoformat(),
            'State': 'ROTATED'
        })
        
        secrets.update_secret(
            SecretId=secret_name,
            SecretString=json.dumps(secret_value)
        )
        
        # Send notification
        user_email = get_user_email(username)
        send_email(
            user_email,
            'AWS IAM Access Key Rotation',
            f'Your IAM access key has been rotated. New key: {new_key["AccessKey"]["AccessKeyId"]}'
        )
        
        logger.info(f"Rotated key for user {username}")
        return True
    except Exception as e:
        logger.error(f"Failed to rotate key for {username}: {str(e)}")
        return False

def deactivate_old_key(username, secret_value):
    try:
        if 'OldAccessKeyId' not in secret_value:
            return
        
        # Deactivate old key
        iam.update_access_key(
            UserName=username,
            AccessKeyId=secret_value['OldAccessKeyId'],
            Status='Inactive'
        )
        
        # Update secret state
        secret_value['State'] = 'DEACTIVATED'
        secrets.update_secret(
            SecretId=f'iam-key-rotation/{username}',
            SecretString=json.dumps(secret_value)
        )
        
        # Send notification
        user_email = get_user_email(username)
        send_email(
            user_email,
            'AWS IAM Access Key Deactivated',
            f'Your old IAM access key {secret_value["OldAccessKeyId"]} has been deactivated.'
        )
        
        logger.info(f"Deactivated old key for user {username}")
        return True
    except Exception as e:
        logger.error(f"Failed to deactivate old key for {username}: {str(e)}")
        return False

def delete_old_key(username, secret_value):
    try:
        if 'OldAccessKeyId' not in secret_value:
            return
        
        # Delete old key
        iam.delete_access_key(
            UserName=username,
            AccessKeyId=secret_value['OldAccessKeyId']
        )
        
        # Remove old key from secret
        secret_value.pop('OldAccessKeyId', None)
        secret_value.pop('OldSecretAccessKey', None)
        secret_value['State'] = 'ACTIVE'
        
        secrets.update_secret(
            SecretId=f'iam-key-rotation/{username}',
            SecretString=json.dumps(secret_value)
        )
        
        # Send notification
        user_email = get_user_email(username)
        send_email(
            user_email,
            'AWS IAM Access Key Deleted',
            f'Your old IAM access key has been deleted.'
        )
        
        logger.info(f"Deleted old key for user {username}")
        return True
    except Exception as e:
        logger.error(f"Failed to delete old key for {username}: {str(e)}")
        return False 