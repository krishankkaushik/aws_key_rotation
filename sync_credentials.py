#!/usr/bin/env python3
"""
AWS Key Rotation - Local Credential Sync Script

This script syncs AWS credentials from Secrets Manager to local configuration files.
It should be run periodically (e.g., via cron) to keep local credentials up to date.

Usage:
    python3 sync_credentials.py

Requirements:
    - Python 3.9+
    - boto3
    - AWS credentials with appropriate permissions
"""

import boto3
import json
import os
import configparser
import logging
from pathlib import Path
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('sync.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def get_credentials_from_secrets_manager(secretsmanager_client, username):
    """Get credentials from Secrets Manager"""
    try:
        response = secretsmanager_client.get_secret_value(
            SecretId=f'iam-key-{username}'
        )
        return json.loads(response['SecretString'])
    except Exception as e:
        logger.error(f"Error getting credentials for {username}: {str(e)}")
        return None

def update_json_config(username, credentials):
    """Update credentials in JSON config file"""
    config_path = Path(f'test-apps/app1/config.json')
    config_path.parent.mkdir(parents=True, exist_ok=True)
    
    try:
        if config_path.exists():
            with open(config_path, 'r') as f:
                config = json.load(f)
        else:
            config = {
                "aws": {
                    "access_key_id": "",
                    "secret_access_key": "",
                    "region": "us-east-1"
                }
            }
        
        config['aws']['access_key_id'] = credentials['AccessKeyId']
        config['aws']['secret_access_key'] = credentials['SecretAccessKey']
        
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=4)
        logger.info(f"Updated JSON config for {username}")
    except Exception as e:
        logger.error(f"Error updating JSON config for {username}: {str(e)}")

def update_env_file(username, credentials):
    """Update credentials in .env file"""
    env_path = Path(f'test-apps/app2/.env')
    env_path.parent.mkdir(parents=True, exist_ok=True)
    
    try:
        if env_path.exists():
            with open(env_path, 'r') as f:
                lines = f.readlines()
        else:
            lines = [
                "AWS_ACCESS_KEY_ID=\n",
                "AWS_SECRET_ACCESS_KEY=\n",
                "AWS_REGION=us-east-1\n"
            ]
        
        new_lines = []
        for line in lines:
            if line.startswith('AWS_ACCESS_KEY_ID='):
                new_lines.append(f'AWS_ACCESS_KEY_ID={credentials["AccessKeyId"]}\n')
            elif line.startswith('AWS_SECRET_ACCESS_KEY='):
                new_lines.append(f'AWS_SECRET_ACCESS_KEY={credentials["SecretAccessKey"]}\n')
            else:
                new_lines.append(line)
        
        with open(env_path, 'w') as f:
            f.writelines(new_lines)
        logger.info(f"Updated .env file for {username}")
    except Exception as e:
        logger.error(f"Error updating .env file for {username}: {str(e)}")

def update_ini_config(username, credentials):
    """Update credentials in INI config file"""
    config_path = Path(f'test-apps/app3/credentials.ini')
    config_path.parent.mkdir(parents=True, exist_ok=True)
    
    try:
        config = configparser.ConfigParser()
        if config_path.exists():
            config.read(config_path)
        else:
            config['default'] = {
                'aws_access_key_id': '',
                'aws_secret_access_key': '',
                'region': 'us-east-1'
            }
        
        config['default']['aws_access_key_id'] = credentials['AccessKeyId']
        config['default']['aws_secret_access_key'] = credentials['SecretAccessKey']
        
        with open(config_path, 'w') as f:
            config.write(f)
        logger.info(f"Updated INI config for {username}")
    except Exception as e:
        logger.error(f"Error updating INI config for {username}: {str(e)}")

def main():
    """Main function to sync credentials"""
    logger.info("Starting credential sync process")
    
    try:
        # Initialize AWS clients
        iam = boto3.client('iam')
        secretsmanager = boto3.client('secretsmanager')
        
        # Get all IAM users
        users = iam.list_users()['Users']
        
        for user in users:
            username = user['UserName']
            if username.startswith('test-user-'):
                logger.info(f"\nProcessing user: {username}")
                credentials = get_credentials_from_secrets_manager(secretsmanager, username)
                if credentials:
                    update_json_config(username, credentials)
                    update_env_file(username, credentials)
                    update_ini_config(username, credentials)
                    logger.info(f"Successfully updated all configurations for {username}")
                else:
                    logger.warning(f"Skipping {username} - no credentials found")
        
        logger.info("Credential sync process completed")
        
    except Exception as e:
        logger.error(f"Error in sync process: {str(e)}")
        raise

if __name__ == '__main__':
    main() 