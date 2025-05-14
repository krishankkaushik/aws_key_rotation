# AWS IAM Key Rotation System

This system provides automated rotation of AWS IAM access keys with the following features:

1. **Automated Key Rotation**:
   - Keys are rotated every 5 minutes
   - Old keys are deactivated after 2 minutes
   - Deactivated keys are deleted after 1 minute
   - Email notifications for all key events

2. **Secure Key Storage**:
   - Keys are stored in AWS Secrets Manager
   - No hardcoding of keys in code
   - Proper access controls and encryption

3. **Flexible Access Patterns**:
   - Direct API access for CI/CD pipelines
   - REST API for programmatic access
   - Email notifications with API usage instructions

## Prerequisites

- Python 3.9+
- AWS CLI configured with appropriate permissions
- AWS SES configured for email notifications

## Setup

1. **Install Dependencies**:
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Deploy CloudFormation Stack**:
   ```bash
   aws cloudformation deploy \
     --template-file key_rotation.yaml \
     --stack-name iam-key-rotation \
     --parameter-overrides \
       SenderEmail=your-email@example.com \
       AdminEmail=admin@example.com \
     --capabilities CAPABILITY_IAM
   ```

3. **Configure Environment Variables**:
   ```bash
   export API_KEY=your-secure-api-key
   ```

4. **Start the API Server**:
   ```bash
   python api.py
   ```

## Usage

### API Endpoints

1. **Get Credentials for a User**:
   ```bash
   curl -H "X-API-Key: your-api-key" http://localhost:8000/credentials/username
   ```

2. **Get All Credentials**:
   ```bash
   curl -H "X-API-Key: your-api-key" http://localhost:8000/credentials
   ```

### Email Notifications

The system sends email notifications for the following events:
1. New key creation
2. Key deactivation
3. Key deletion

Each email includes:
- Event details
- Timestamp
- API usage instructions
- Security best practices

## Security Considerations

1. **API Security**:
   - All API endpoints require an API key
   - API key should be rotated regularly
   - Use HTTPS in production

2. **Key Storage**:
   - Keys are encrypted at rest in Secrets Manager
   - Access is controlled via IAM policies
   - No hardcoded credentials in code

3. **Monitoring**:
   - CloudWatch logs for Lambda function
   - API access logs
   - Key rotation events

## Troubleshooting

1. **Key Rotation Issues**:
   - Check CloudWatch logs for Lambda function
   - Verify IAM permissions
   - Check SES configuration

2. **API Issues**:
   - Verify API key
   - Check Secrets Manager access
   - Review API logs

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details. 