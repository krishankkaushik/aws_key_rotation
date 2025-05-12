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

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('key_management.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def create_access_key(iam_client, username):
    """Create access key for an IAM user"""
    try:
        response = iam_client.create_access_key(
            UserName=username
        )
        key = response['AccessKey']
        logger.info(f"Created access key for user: {username}")
        return key
    except Exception as e:
        logger.error(f"Error creating access key for {username}: {str(e)}")
        raise

def store_key_in_secrets_manager(secretsmanager_client, username, key):
    """Store access key in Secrets Manager"""
    secret_name = username  # Using username directly as secret name
    secret_value = {
        'AccessKeyId': key['AccessKeyId'],
        'SecretAccessKey': key['SecretAccessKey'],
        'CreatedDate': datetime.now().isoformat()
    }
    try:
        # Check if secret exists
        try:
            secretsmanager_client.describe_secret(SecretId=secret_name)
            # Update existing secret
            secretsmanager_client.update_secret(
                SecretId=secret_name,
                SecretString=json.dumps(secret_value)
            )
            logger.info(f"Updated credentials in Secrets Manager for: {username}")
        except secretsmanager_client.exceptions.ResourceNotFoundException:
            # Create new secret
            secretsmanager_client.create_secret(
                Name=secret_name,
                SecretString=json.dumps(secret_value),
                Description=f'AWS credentials for {username}'
            )
            logger.info(f"Stored credentials in Secrets Manager for: {username}")
    except Exception as e:
        logger.error(f"Error storing credentials for {username}: {str(e)}")
        raise

def rotate_access_key(iam_client, username):
    """Rotate access key for an IAM user"""
    try:
        # List existing keys
        response = iam_client.list_access_keys(UserName=username)
        keys = response['AccessKeyMetadata']
        
        # Delete old keys
        for key in keys:
            iam_client.delete_access_key(
                UserName=username,
                AccessKeyId=key['AccessKeyId']
            )
            logger.info(f"Deleted old access key {key['AccessKeyId']} for {username}")
        
        # Create new key
        new_key = create_access_key(iam_client, username)
        return new_key
    except Exception as e:
        logger.error(f"Error rotating access key for {username}: {str(e)}")
        raise

def main():
    """Main function to manage AWS keys"""
    parser = argparse.ArgumentParser(description='Manage AWS access keys')
    parser.add_argument('--username', required=True, help='IAM username')
    parser.add_argument('--action', choices=['create', 'rotate'], default='create',
                      help='Action to perform (create new key or rotate existing key)')
    args = parser.parse_args()

    logger.info(f"Starting key management for user: {args.username}")
    
    try:
        # Initialize AWS clients
        iam = boto3.client('iam')
        secretsmanager = boto3.client('secretsmanager')
        
        # Perform requested action
        if args.action == 'rotate':
            key = rotate_access_key(iam, args.username)
        else:
            key = create_access_key(iam, args.username)
        
        # Store key in Secrets Manager
        store_key_in_secrets_manager(secretsmanager, args.username, key)
        
        logger.info(f"Key management completed successfully for {args.username}")
        
    except Exception as e:
        logger.error(f"Error in key management process: {str(e)}")
        raise

if __name__ == '__main__':
    main() 