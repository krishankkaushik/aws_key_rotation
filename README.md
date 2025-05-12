# AWS IAM Key Rotation System

This project implements an automated AWS IAM access key rotation system with monitoring and notifications. It's designed to enhance security by regularly rotating access keys and ensuring applications are updated with new credentials.

## Features

- **Automated Key Rotation**: Rotates IAM access keys every 2 hours
- **Graceful Key Management**:
  - Creates new keys before deactivating old ones
  - Maintains a 1-hour grace period between rotation and deactivation
  - Provides a 1-hour recovery window before key deletion
- **Secure Storage**: Stores new keys in AWS Secrets Manager
- **Email Notifications**: Sends detailed notifications for:
  - New key creation
  - Key deactivation
  - Key deletion
- **Monitoring**: CloudWatch dashboard for tracking:
  - Key rotation status
  - Email notification delivery
  - System health metrics

## Architecture

The system consists of the following components:

1. **Lambda Function**: Core rotation logic
2. **CloudWatch Events**: Triggers rotation every hour
3. **Secrets Manager**: Stores new credentials
4. **SES**: Handles email notifications
5. **CloudWatch Dashboard**: Monitoring and metrics

## Prerequisites

- AWS Account with appropriate permissions
- Verified SES email address for notifications
- Python 3.9 or later
- AWS CLI configured with appropriate credentials

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd aws-key-rotation-task
```

2. Update the CloudFormation parameters in `key_rotation_template.yaml`:
   - `AdminEmail`: Your admin email address
   - `SenderEmail`: Your verified SES sender email

3. Deploy the CloudFormation stack:
```bash
aws cloudformation create-stack \
  --stack-name key-rotation-stack \
  --template-body file://key_rotation_template.yaml \
  --parameters \
    ParameterKey=AdminEmail,ParameterValue=your-admin-email@example.com \
    ParameterKey=SenderEmail,ParameterValue=your-sender-email@example.com
```

4. Add email tags to IAM users:
```bash
aws iam tag-user \
  --user-name test-user-1 \
  --tags Key=email,Value=user-email@example.com
```

## Configuration

### Key Rotation Parameters

The system uses the following timing parameters (configurable in CloudFormation):

- `RotationPeriod`: Time before creating new keys (default: 2 hours)
- `InactivePeriod`: Time before deactivating old keys (default: 3 hours)
- `InactiveBuffer`: Grace period between rotation and deactivation (default: 1 hour)
- `RecoveryGracePeriod`: Time before deleting deactivated keys (default: 1 hour)

### Application Integration

The system supports three types of configuration files:

1. **JSON Configuration** (`test-apps/app1/config.json`):
```json
{
    "aws": {
        "access_key_id": "YOUR_ACCESS_KEY",
        "secret_access_key": "YOUR_SECRET_KEY",
        "region": "us-east-1"
    }
}
```

2. **Environment Variables** (`test-apps/app2/.env`):
```env
AWS_ACCESS_KEY_ID=YOUR_ACCESS_KEY
AWS_SECRET_ACCESS_KEY=YOUR_SECRET_KEY
AWS_REGION=us-east-1
```

3. **INI Configuration** (`test-apps/app3/credentials.ini`):
```ini
[default]
aws_access_key_id = YOUR_ACCESS_KEY
aws_secret_access_key = YOUR_SECRET_KEY
region = us-east-1
```

## Usage

### Manual Key Update

To manually update application credentials:

```bash
python3 update_credentials.py
```

### Monitoring

Access the CloudWatch dashboard at:
```
https://<region>.console.aws.amazon.com/cloudwatch/home?region=<region>#dashboards:name=IAMKeyRotationDashboard
```

## Security Considerations

1. **Least Privilege**: The Lambda function uses minimal IAM permissions
2. **Secure Storage**: Credentials are stored in AWS Secrets Manager
3. **Grace Periods**: Multiple grace periods prevent service disruption
4. **Audit Trail**: All actions are logged in CloudWatch

## Troubleshooting

1. **Email Notifications Not Received**:
   - Verify SES email addresses
   - Check IAM user email tags
   - Review CloudWatch logs

2. **Key Rotation Issues**:
   - Check Lambda function logs
   - Verify IAM permissions
   - Review CloudWatch metrics

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details. 