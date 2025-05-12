import boto3
import json
import logging
from cachetools import TTLCache
from typing import Dict, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class CredentialManager:
    def __init__(self, secret_name: str, cache_ttl: int = 3600):
        """
        Initialize the credential manager.
        
        Args:
            secret_name: Name of the secret in AWS Secrets Manager
            cache_ttl: Time to live for cached credentials in seconds (default: 1 hour)
        """
        self.secret_name = secret_name
        self.secrets_client = boto3.client('secretsmanager')
        self.cache = TTLCache(maxsize=1, ttl=cache_ttl)
        
    def get_credentials(self) -> Dict[str, str]:
        """
        Get AWS credentials from cache or Secrets Manager.
        
        Returns:
            Dict containing access_key_id and secret_access_key
        """
        try:
            # Try to get from cache first
            if 'credentials' in self.cache:
                logger.debug("Retrieved credentials from cache")
                return self.cache['credentials']
            
            # If not in cache, fetch from Secrets Manager
            response = self.secrets_client.get_secret_value(SecretId=self.secret_name)
            secret_string = response['SecretString']
            credentials = json.loads(secret_string)
            
            # Store in cache
            self.cache['credentials'] = credentials
            logger.info("Retrieved fresh credentials from Secrets Manager")
            
            return credentials
            
        except Exception as e:
            logger.error(f"Error retrieving credentials: {str(e)}")
            raise
    
    def get_boto3_session(self) -> boto3.Session:
        """
        Get a boto3 session using the current credentials.
        
        Returns:
            boto3.Session object
        """
        credentials = self.get_credentials()
        return boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey']
        )
    
    def clear_cache(self) -> None:
        """Clear the credentials cache."""
        self.cache.clear()
        logger.debug("Credentials cache cleared") 