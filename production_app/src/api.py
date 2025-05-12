from fastapi import FastAPI, HTTPException, Security, Depends
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from typing import Dict, Optional
import boto3
import json
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="AWS Credential API",
    description="API for fetching AWS credentials from Secrets Manager",
    version="1.0.0"
)

# Security
API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME)

class Credentials(BaseModel):
    AccessKeyId: str
    SecretAccessKey: str
    LastRotated: datetime

async def verify_api_key(api_key: str = Security(api_key_header)):
    """Verify the API key against a list of valid keys."""
    # TODO: Implement proper API key validation
    # For now, we'll just check if it's not empty
    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="Invalid API key"
        )
    return api_key

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}

@app.get("/credentials/{username}", response_model=Credentials)
async def get_credentials(
    username: str,
    api_key: str = Depends(verify_api_key)
):
    """
    Get AWS credentials for a specific IAM user.
    
    Args:
        username: IAM username
        api_key: API key for authentication
    
    Returns:
        Credentials object containing AccessKeyId and SecretAccessKey
    """
    try:
        # Initialize Secrets Manager client
        secrets_client = boto3.client('secretsmanager')
        
        # Get secret (using username directly as secret name)
        response = secrets_client.get_secret_value(SecretId=username)
        secret_string = response['SecretString']
        
        # Parse secret
        credentials = json.loads(secret_string)
        
        # Add last rotated timestamp
        credentials['LastRotated'] = response['LastModifiedDate']
        
        return credentials
        
    except secrets_client.exceptions.ResourceNotFoundException:
        raise HTTPException(
            status_code=404,
            detail=f"Credentials not found for user: {username}"
        )
    except Exception as e:
        logger.error(f"Error fetching credentials: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Internal server error"
        )

@app.get("/users", response_model=Dict[str, datetime])
async def list_users(api_key: str = Depends(verify_api_key)):
    """
    List all IAM users with credentials in Secrets Manager.
    
    Returns:
        Dictionary mapping usernames to their last rotation time
    """
    try:
        # Initialize Secrets Manager client
        secrets_client = boto3.client('secretsmanager')
        
        # List all secrets
        response = secrets_client.list_secrets()
        
        # Extract usernames and last modified dates
        users = {}
        for secret in response['SecretList']:
            # Only include secrets that look like IAM credentials
            if 'AccessKeyId' in json.loads(secret['SecretString']):
                users[secret['Name']] = secret['LastModifiedDate']
            
        return users
        
    except Exception as e:
        logger.error(f"Error listing users: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Internal server error"
        ) 