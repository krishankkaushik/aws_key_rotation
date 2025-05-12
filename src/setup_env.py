import os
import secrets
import argparse

def generate_api_key():
    """Generate a secure API key."""
    return secrets.token_urlsafe(32)

def setup_environment():
    """Set up the environment for the application."""
    parser = argparse.ArgumentParser(description='Set up environment for AWS Key Management API')
    parser.add_argument('--region', default='us-east-1', help='AWS region')
    args = parser.parse_args()
    
    # Generate API key
    api_key = generate_api_key()
    
    # Create .env file
    env_content = f"""# API Configuration
API_KEY={api_key}

# AWS Configuration
AWS_REGION={args.region}

# Application Configuration
LOG_LEVEL=INFO
"""
    
    with open('.env', 'w') as f:
        f.write(env_content)
    
    print("Environment setup complete!")
    print(f"API Key: {api_key}")
    print("Please keep this API key secure and do not share it.")
    print("You can now run the API using: python src/run_api.py")

if __name__ == "__main__":
    setup_environment() 