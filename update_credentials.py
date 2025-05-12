#!/usr/bin/env python3
"""
AWS IAM Key Rotation - Credential Update Script

This script is responsible for updating AWS credentials in various application configuration files
when new keys are rotated. It supports multiple configuration formats (JSON, ENV, INI) and
handles the update process for all test users in the system.

The script follows these steps:
1. Retrieves new credentials from AWS Secrets Manager
2. Updates configuration files for each supported format
3. Maintains a log of all updates
4. Handles errors gracefully

Usage:
    python3 update_credentials.py

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
        logging.FileHandler('credential_updates.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def get_new_credentials(username):
    """
    Retrieve new credentials from AWS Secrets Manager.
    
    Args:
        username (str): The IAM username to get credentials for
        
    Returns:
        dict: Dictionary containing AccessKeyId and SecretAccessKey
        None: If credentials cannot be retrieved
    """
    secretsmanager = boto3.client('secretsmanager')
    try:
        response = secretsmanager.get_secret_value(
            SecretId=f'iam-key-{username}'
        )
        return json.loads(response['SecretString'])
    except Exception as e:
        logger.error(f"Error getting credentials for {username}: {str(e)}")
        return None

def update_json_config(username, credentials):
    """
    Update credentials in JSON configuration file.
    
    Args:
        username (str): The IAM username being updated
        credentials (dict): Dictionary containing new credentials
    """
    config_path = Path(f'test-apps/app1/config.json')
    if config_path.exists():
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            config['aws']['access_key_id'] = credentials['AccessKeyId']
            config['aws']['secret_access_key'] = credentials['SecretAccessKey']
            
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=4)
            logger.info(f"Updated JSON config for {username}")
        except Exception as e:
            logger.error(f"Error updating JSON config for {username}: {str(e)}")

def update_env_file(username, credentials):
    """
    Update credentials in environment variables file.
    
    Args:
        username (str): The IAM username being updated
        credentials (dict): Dictionary containing new credentials
    """
    env_path = Path(f'test-apps/app2/.env')
    if env_path.exists():
        try:
            with open(env_path, 'r') as f:
                lines = f.readlines()
            
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
    """
    Update credentials in INI configuration file.
    
    Args:
        username (str): The IAM username being updated
        credentials (dict): Dictionary containing new credentials
    """
    config_path = Path(f'test-apps/app3/credentials.ini')
    if config_path.exists():
        try:
            config = configparser.ConfigParser()
            config.read(config_path)
            
            config['default']['aws_access_key_id'] = credentials['AccessKeyId']
            config['default']['aws_secret_access_key'] = credentials['SecretAccessKey']
            
            with open(config_path, 'w') as f:
                config.write(f)
            logger.info(f"Updated INI config for {username}")
        except Exception as e:
            logger.error(f"Error updating INI config for {username}: {str(e)}")

def main():
    """
    Main function to update credentials for all test users.
    
    The function:
    1. Lists all IAM users
    2. Filters for test users
    3. Updates credentials in all supported formats
    4. Logs the results
    """
    logger.info("Starting credential update process")
    
    try:
        # Get all IAM users
        iam = boto3.client('iam')
        users = iam.list_users()['Users']
        
        for user in users:
            username = user['UserName']
            if username.startswith('test-user-'):
                logger.info(f"\nProcessing user: {username}")
                credentials = get_new_credentials(username)
                if credentials:
                    update_json_config(username, credentials)
                    update_env_file(username, credentials)
                    update_ini_config(username, credentials)
                    logger.info(f"Successfully updated all configurations for {username}")
                else:
                    logger.warning(f"Skipping {username} - no credentials found")
        
        logger.info("Credential update process completed")
    except Exception as e:
        logger.error(f"Error in main process: {str(e)}")
        raise

if __name__ == '__main__':
    main() 