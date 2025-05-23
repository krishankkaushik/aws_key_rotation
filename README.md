# AWS IAM Key Rotation System

A secure and automated system for rotating AWS IAM access keys with API-based access control.

## Features

- 🔐 Automatic key rotation every 10 minutes
- 🔑 JWT-based authentication (2-minute token expiry)
- 🌐 IP whitelisting for API access
- 🔒 API key protection
- 📊 CloudWatch logging and monitoring
- 🔄 Zero-downtime key rotation

## Prerequisites

- Python 3.9 or higher
- AWS CLI configured with appropriate permissions
- AWS account with IAM access
- Public IP for whitelisting

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/aws-key-rotation.git
cd aws-key-rotation
```

2. Create and activate virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Configure AWS credentials:
```bash
aws configure
```

## Deployment

1. Deploy the stack with your email addresses:
```bash
python deploy.py --admin-email your.admin@email.com --sender-email your.sender@email.com
```

2. For cleanup (if needed):
```bash
python deploy.py --cleanup
```

## Usage

### 1. Get API Credentials

After deployment, you'll receive:
- API Key
- API Endpoint URL
- JWT Token

### 2. Generate JWT Token

```bash
curl -X POST -H "x-api-key: YOUR_API_KEY" "YOUR_API_ENDPOINT/generate-token"
```

### 3. Get Active Credentials

```bash
curl -H "x-api-key: YOUR_API_KEY" \
     -H "Authorization: Bearer YOUR_JWT_TOKEN" \
     "YOUR_API_ENDPOINT/active-key?username=YOUR_IAM_USER"
```

## Security Features

1. **IP Whitelisting**
   - Only whitelisted IPs can access the API
   - Configure in `key_rotation_simple.yaml`

2. **JWT Authentication**
   - 2-minute token expiry
   - Secure token generation and validation

3. **API Key Protection**
   - Required for all API calls
   - Rate limiting enabled

4. **IAM Security**
   - Automatic key rotation
   - Zero-downtime updates
   - Secure key storage in Secrets Manager

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  API Gateway│────▶│   Lambda    │────▶│  IAM/Secrets│
└─────────────┘     └─────────────┘     └─────────────┘
       │                   │                   │
       │                   │                   │
       ▼                   ▼                   ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  JWT Auth   │     │  Key Rotation│     │  CloudWatch │
└─────────────┘     └─────────────┘     └─────────────┘
```

## Monitoring

- CloudWatch Logs for all operations
- Error tracking and alerting
- Rotation status monitoring

## Troubleshooting

1. **API Access Issues**
   - Verify IP whitelisting
   - Check API key validity
   - Validate JWT token

2. **Key Rotation Issues**
   - Check CloudWatch logs
   - Verify IAM permissions
   - Check Secrets Manager access

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support, please:
1. Check the [troubleshooting guide](#troubleshooting)
2. Review CloudWatch logs
3. Open an issue in GitHub

## Authors

- Your Name - Initial work

## Acknowledgments

- AWS Documentation
- Serverless Framework
- Python Community 