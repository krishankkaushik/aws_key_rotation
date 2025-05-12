from fastapi import FastAPI, HTTPException, Security, Depends, Header
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from typing import Dict, List, Optional
import boto3
import json
import logging
from datetime import datetime
import os
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="AWS Key Management API")

# Security
API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME)

# AWS Clients
iam = boto3.client('iam')
secrets = boto3.client('secretsmanager')

# Models
class Credentials(BaseModel):
    access_key_id: str
    secret_access_key: str
    created_date: str
    email: Optional[str] = None

class UserCredentials(BaseModel):
    username: str
    credentials: Credentials

async def verify_api_key(api_key: str = Security(api_key_header)):
    """Verify the API key."""
    if api_key != os.getenv('API_KEY'):
        raise HTTPException(status_code=403, detail="Invalid API key")
    return api_key

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}

@app.get("/users", response_model=List[str])
async def list_users(api_key: str = Depends(verify_api_key)):
    """List all IAM users with access keys."""
    try:
        response = iam.list_users()
        users = [user['UserName'] for user in response['Users']]
        return users
    except ClientError as e:
        logger.error(f"Error listing users: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/credentials/{username}", response_model=UserCredentials)
async def create_credentials(username: str, api_key: str = Depends(verify_api_key)):
    """Create new access key for a user and store in Secrets Manager."""
    try:
        # Get user email from tags
        user = iam.get_user(UserName=username)
        email = next((tag['Value'] for tag in user['User']['Tags'] if tag['Key'] == 'email'), None)
        
        # Create new access key
        key_response = iam.create_access_key(UserName=username)
        credentials = key_response['AccessKey']
        
        # Store in Secrets Manager
        secret_value = {
            'AccessKeyId': credentials['AccessKeyId'],
            'SecretAccessKey': credentials['SecretAccessKey'],
            'CreatedDate': datetime.now().isoformat(),
            'Email': email
        }
        
        secrets.create_secret(
            Name=username,
            SecretString=json.dumps(secret_value),
            Description=f'AWS credentials for {username}'
        )
        
        return UserCredentials(
            username=username,
            credentials=Credentials(
                access_key_id=credentials['AccessKeyId'],
                secret_access_key=credentials['SecretAccessKey'],
                created_date=credentials['CreateDate'].isoformat(),
                email=email
            )
        )
    except ClientError as e:
        logger.error(f"Error creating credentials for {username}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/credentials/{username}", response_model=UserCredentials)
async def get_credentials(username: str, api_key: str = Depends(verify_api_key)):
    """Get credentials for a user from Secrets Manager."""
    try:
        response = secrets.get_secret_value(SecretId=username)
        secret_value = json.loads(response['SecretString'])
        
        return UserCredentials(
            username=username,
            credentials=Credentials(
                access_key_id=secret_value['AccessKeyId'],
                secret_access_key=secret_value['SecretAccessKey'],
                created_date=secret_value['CreatedDate'],
                email=secret_value.get('Email')
            )
        )
    except ClientError as e:
        logger.error(f"Error getting credentials for {username}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/export-credentials")
async def export_credentials(api_key: str = Depends(verify_api_key)):
    """Export all user credentials to files."""
    try:
        users = await list_users(api_key)
        exported_files = []
        
        for username in users:
            try:
                credentials = await get_credentials(username, api_key)
                if credentials.credentials.email:
                    # Create directory if it doesn't exist
                    os.makedirs('credentials', exist_ok=True)
                    
                    # Write credentials to file
                    filename = f"credentials/{username}_credentials.json"
                    with open(filename, 'w') as f:
                        json.dump(credentials.dict(), f, indent=2)
                    
                    exported_files.append(filename)
            except Exception as e:
                logger.error(f"Error exporting credentials for {username}: {str(e)}")
                continue
        
        return {
            "message": f"Exported credentials for {len(exported_files)} users",
            "files": exported_files
        }
    except Exception as e:
        logger.error(f"Error exporting credentials: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e)) 