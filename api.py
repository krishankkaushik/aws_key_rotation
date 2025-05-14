from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.security import APIKeyHeader
from typing import Dict, Optional
import logging
import boto3
import json
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(title="AWS Credential Manager API")

# Initialize AWS clients
secrets_client = boto3.client('secretsmanager')

# API key security
API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME)

# Default API key for testing
DEFAULT_API_KEY = "test-api-key-123"

async def verify_api_key(api_key: str = Depends(api_key_header)):
    """Verify the API key."""
    expected_key = os.getenv('API_KEY', DEFAULT_API_KEY)
    if api_key != expected_key:
        raise HTTPException(
            status_code=401,
            detail="Invalid API key"
        )
    return api_key

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}

@app.get("/credentials/{username}")
async def get_credentials(username: str, api_key: str = Depends(verify_api_key)):
    """Get credentials for a specific user."""
    try:
        response = secrets_client.get_secret_value(SecretId=username)
        creds = json.loads(response['SecretString'])
        return {
            "username": username,
            "access_key_id": creds['AccessKeyId'],
            "secret_access_key": creds['SecretAccessKey']
        }
    except Exception as e:
        logger.error(f"Error getting credentials for {username}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error getting credentials: {str(e)}"
        )

@app.get("/credentials")
async def get_all_credentials(api_key: str = Depends(verify_api_key)):
    """Get all credentials."""
    try:
        all_creds = {}
        paginator = secrets_client.get_paginator('list_secrets')
        
        for page in paginator.paginate():
            for secret in page['SecretList']:
                try:
                    response = secrets_client.get_secret_value(SecretId=secret['Name'])
                    creds = json.loads(response['SecretString'])
                    all_creds[secret['Name']] = {
                        'access_key_id': creds['AccessKeyId'],
                        'secret_access_key': creds['SecretAccessKey']
                    }
                except Exception as e:
                    logger.error(f"Error getting secret {secret['Name']}: {str(e)}")
        
        return all_creds
    except Exception as e:
        logger.error(f"Error getting all credentials: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error getting credentials: {str(e)}"
        )

@app.post("/refresh/{username}")
async def refresh_credentials(username: str, api_key: str = Depends(verify_api_key)):
    """Refresh credentials for a specific user."""
    try:
        response = secrets_client.get_secret_value(SecretId=username)
        creds = json.loads(response['SecretString'])
        return {
            "username": username,
            "access_key_id": creds['AccessKeyId'],
            "secret_access_key": creds['SecretAccessKey']
        }
    except Exception as e:
        logger.error(f"Error refreshing credentials for {username}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error refreshing credentials: {str(e)}"
        )

@app.post("/refresh")
async def refresh_all_credentials(api_key: str = Depends(verify_api_key)):
    """Refresh all credentials."""
    try:
        all_creds = {}
        paginator = secrets_client.get_paginator('list_secrets')
        
        for page in paginator.paginate():
            for secret in page['SecretList']:
                try:
                    response = secrets_client.get_secret_value(SecretId=secret['Name'])
                    creds = json.loads(response['SecretString'])
                    all_creds[secret['Name']] = {
                        'access_key_id': creds['AccessKeyId'],
                        'secret_access_key': creds['SecretAccessKey']
                    }
                except Exception as e:
                    logger.error(f"Error refreshing secret {secret['Name']}: {str(e)}")
        
        return all_creds
    except Exception as e:
        logger.error(f"Error refreshing all credentials: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error refreshing credentials: {str(e)}"
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 