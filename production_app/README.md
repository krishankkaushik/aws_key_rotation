# AWS Credential API

This API service provides secure access to AWS credentials stored in AWS Secrets Manager. It's designed to be used by developers and CI/CD pipelines to fetch their AWS credentials.

## Features

- Secure credential retrieval with API key authentication
- Automatic updates when credentials are rotated
- Support for multiple IAM users
- Health check endpoint
- List all available users

## API Endpoints

### Health Check
```
GET /health
```
Returns the health status of the API.

### Get Credentials
```
GET /credentials/{username}
Headers:
  X-API-Key: your-api-key
```
Returns AWS credentials for the specified IAM user.

Response:
```json
{
    "AccessKeyId": "AKIA...",
    "SecretAccessKey": "...",
    "LastRotated": "2024-02-14T12:00:00Z"
}
```

### List Users
```
GET /users
Headers:
  X-API-Key: your-api-key
```
Returns a list of all IAM users with credentials in Secrets Manager.

Response:
```json
{
    "username1": "2024-02-14T12:00:00Z",
    "username2": "2024-02-14T12:00:00Z"
}
```

## Usage Examples

### Python
```python
import requests

API_KEY = "your-api-key"
API_URL = "http://your-api-url"

# Get credentials
response = requests.get(
    f"{API_URL}/credentials/your-username",
    headers={"X-API-Key": API_KEY}
)
credentials = response.json()

# Use credentials
import boto3
session = boto3.Session(
    aws_access_key_id=credentials["AccessKeyId"],
    aws_secret_access_key=credentials["SecretAccessKey"]
)
```

### Shell
```bash
# Get credentials
curl -H "X-API-Key: your-api-key" \
     http://your-api-url/credentials/your-username

# List users
curl -H "X-API-Key: your-api-key" \
     http://your-api-url/users
```

### Jenkins Pipeline
```groovy
pipeline {
    agent any
    stages {
        stage('Get AWS Credentials') {
            steps {
                script {
                    def response = httpRequest \
                        url: 'http://your-api-url/credentials/your-username',
                        customHeaders: [[name: 'X-API-Key', value: 'your-api-key']]
                    
                    def credentials = readJSON text: response.content
                    
                    withAWS(credentials: [
                        [credentialsId: 'aws-credentials',
                         accessKeyVariable: 'AWS_ACCESS_KEY_ID',
                         secretKeyVariable: 'AWS_SECRET_ACCESS_KEY',
                         accessKey: credentials.AccessKeyId,
                         secretKey: credentials.SecretAccessKey]
                    ]) {
                        // Your AWS operations here
                    }
                }
            }
        }
    }
}
```

## Security

- All endpoints require API key authentication
- Credentials are stored securely in AWS Secrets Manager
- API keys should be rotated regularly
- HTTPS should be used in production

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Set environment variables:
```bash
export API_KEY=your-api-key
```

3. Run the API:
```bash
uvicorn src.api:app --host 0.0.0.0 --port 8000
```

## Development

- The API is built with FastAPI
- Uses Pydantic for data validation
- Includes comprehensive error handling
- Logs all operations for audit purposes

## Project Structure

```
production_app/
├── Dockerfile
├── README.md
├── requirements.txt
└── src/
    └── api.py
```

## Deployment

1. Build the Docker image:
```bash
docker build -t aws-credential-api .
```

2. Run the container:
```bash
docker run -p 8000:8000 \
  -e API_KEY=your-secure-api-key \
  aws-credential-api
``` 