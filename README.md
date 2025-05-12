# AWS IAM Key Rotation System

A production-grade system for automatic rotation of AWS IAM access keys with monitoring, notifications, and a REST API for credential management.

## Features

- Automatic key rotation every 30 minutes
- Key deactivation after 1 hour
- Key deletion after 1.5 hours
- Email notifications for key events
- CloudWatch dashboard for monitoring
- Secrets Manager integration for key storage
- REST API for credential management
- Credential caching with TTL
- Secure API key authentication

## Project Structure

```
aws_key_rotation_task/
├── src/
│   ├── api.py              # FastAPI application for credential management
│   └── credential_manager.py # Credential caching and management
├── key_rotation_template.yaml  # CloudFormation template
├── setup_aws_resources.py  # AWS resource setup script
├── requirements.txt        # Python dependencies
└── README.md              # This file
```

## Prerequisites

1. AWS CLI configured with appropriate permissions
2. SES verified email addresses for notifications
3. Python 3.9 or later
4. Virtual environment (recommended)

## Setup

1. Create and activate virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Configure AWS credentials:
   ```bash
   aws configure
   ```

4. Deploy the CloudFormation stack:
   ```bash
   python setup_aws_resources.py --admin-email your-admin@example.com --sender-email your-sender@example.com
   ```

## API Usage

The system provides a REST API for credential management:

1. Get credentials for a user:
   ```bash
   curl -H "X-API-Key: your-api-key" http://localhost:8000/credentials/username
   ```

2. List all users with credentials:
   ```bash
   curl -H "X-API-Key: your-api-key" http://localhost:8000/users
   ```

3. Health check:
   ```bash
   curl http://localhost:8000/health
   ```

## Monitoring

The system includes a CloudWatch dashboard with:
- Key rotation status metrics
- Email notification metrics
- Error tracking
- API usage metrics

Access the dashboard through the CloudFormation stack outputs.

## Key Rotation Process

1. Every 5 minutes, the Lambda function checks for keys that need rotation
2. Keys older than 30 minutes are rotated:
   - Old keys are deactivated
   - New keys are created
   - Keys are stored in Secrets Manager
3. Inactive keys older than 1 hour are deleted
4. Email notifications are sent for all key events

## Security

- Only users with prefix `test-user-` are included in rotation
- Keys are stored securely in Secrets Manager
- All operations are logged and monitored
- Email notifications include key status changes
- API endpoints are protected with API key authentication
- Credentials are cached with TTL for performance

## Troubleshooting

1. Check CloudWatch Logs for the Lambda function
2. Verify SES email configuration
3. Ensure IAM permissions are correct
4. Check Secrets Manager for key storage
5. Monitor API logs for credential access issues

## Development

1. Run the API locally:
   ```bash
   uvicorn src.api:app --reload
   ```

2. Run tests:
   ```bash
   pytest
   ```

## License

This project is licensed under the MIT License - see the LICENSE file for details. 