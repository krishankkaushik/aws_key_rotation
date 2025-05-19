# AWS IAM Key Rotation System

A secure and automated system for rotating AWS IAM access keys with API access to retrieve active credentials.

## 🌟 Features

- **Automated Key Rotation**: Automatically rotates IAM access keys every 10 minutes
- **Multiple Active Keys**: Maintains two active keys per user for zero-downtime rotation
- **Secure Key Management**: 
  - Keys are deactivated after 12 minutes
  - Keys are deleted after 15 minutes
  - All operations are logged
- **API Access**: REST API to retrieve active credentials for any IAM user
- **Email Notifications**: Configurable email notifications for key rotation events
- **CloudFormation Deployment**: Easy deployment using AWS CloudFormation

## 🚀 Quick Start

### Prerequisites

- Python 3.9 or higher
- AWS CLI configured with appropriate permissions
- AWS SES verified email addresses (for notifications)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/aws-key-rotation.git
   cd aws-key-rotation
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Deployment

1. Deploy the stack using the deployment script:
   ```bash
   python deploy.py --admin-email your-admin@email.com --sender-email your-sender@email.com
   ```

   Optional flags:
   - `--cleanup`: Clean up existing resources before deployment
   - `--skip-email-verification`: Skip SES email verification (not recommended for production)

2. The script will:
   - Verify email addresses in AWS SES
   - List existing IAM users
   - Deploy the CloudFormation stack
   - Display API credentials for testing

## 🔑 Using the API

After deployment, you'll receive API credentials. Use them to retrieve active credentials for any IAM user:

```bash
curl -H "x-api-key: YOUR_API_KEY" "YOUR_API_ENDPOINT?username=USERNAME"
```

Example response:
```json
{
    "AccessKeyId": "AKIAXXXXXXXXXXXXXXXX",
    "SecretAccessKey": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
}
```

## 🔄 Key Rotation Schedule

- **Every 10 minutes**: New key is created
- **After 12 minutes**: Old key is deactivated
- **After 15 minutes**: Old key is deleted
- **Always**: Two active keys are maintained per user

## 🏗️ Architecture

The system consists of the following AWS resources:

- **Lambda Function**: Handles key rotation and API requests
- **EventBridge Rule**: Triggers key rotation every 10 minutes
- **API Gateway**: Provides REST API access
- **Secrets Manager**: Securely stores API credentials
- **IAM Roles**: Manages permissions for the Lambda function
- **CloudWatch Logs**: Logs all operations

## 🔒 Security Considerations

- API access is protected with API keys
- IAM roles follow the principle of least privilege
- Keys are automatically rotated and cleaned up
- All operations are logged for audit purposes
- Email notifications for important events

## 🧪 Testing

1. Create test IAM users:
   ```bash
   aws iam create-user --user-name test-user-1
   ```

2. Test the API:
   ```bash
   curl -H "x-api-key: YOUR_API_KEY" "YOUR_API_ENDPOINT?username=test-user-1"
   ```

3. Monitor key rotation:
   ```bash
   aws iam list-access-keys --user-name test-user-1
   ```

## 🧹 Cleanup

To remove all resources:

```bash
python deploy.py --admin-email your-admin@email.com --sender-email your-sender@email.com --cleanup
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📧 Support

For support, please open an issue in the GitHub repository. 