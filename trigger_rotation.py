#!/usr/bin/env python3
import boto3
import logging
import json
import argparse
from datetime import datetime, timezone
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def trigger_rotation(force=False):
    """
    Trigger the key rotation Lambda function
    Args:
        force (bool): If True, force rotation for all users regardless of key age
    """
    try:
        # Initialize Lambda client
        lambda_client = boto3.client('lambda')
        
        # Get the function name from CloudFormation stack
        cloudformation = boto3.client('cloudformation')
        stack_name = 'iam-key-rotation'
        
        try:
            # Get the function name from stack outputs
            response = cloudformation.describe_stacks(StackName=stack_name)
            outputs = response['Stacks'][0]['Outputs']
            
            # Find the Lambda function ARN
            function_arn = None
            for output in outputs:
                if output['OutputKey'] == 'LambdaFunctionArn':
                    function_arn = output['OutputValue']
                    break
            
            if not function_arn:
                raise Exception("Could not find Lambda function ARN in stack outputs")
            
            function_name = function_arn.split(':')[-1]
            logger.info(f"Found Lambda function: {function_name}")
            
            # Prepare the event payload
            event = {
                'source': 'manual-rotation',
                'force': force
            }
            
            # Invoke the Lambda function
            response = lambda_client.invoke(
                FunctionName=function_name,
                InvocationType='RequestResponse',
                Payload=json.dumps(event)
            )
            
            # Parse the response
            response_payload = json.loads(response['Payload'].read())
            logger.info(f"Rotation response: {response_payload}")
            
            if response['StatusCode'] == 200:
                logger.info("Key rotation triggered successfully")
            else:
                logger.error(f"Failed to trigger key rotation: {response_payload}")
                
        except Exception as e:
            logger.error(f"Error getting function name from stack: {str(e)}")
            return
            
    except Exception as e:
        logger.error(f"Error triggering rotation: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description='Trigger IAM key rotation')
    parser.add_argument('--force', action='store_true', help='Force rotation for all users')
    args = parser.parse_args()
    
    trigger_rotation(force=args.force)

if __name__ == '__main__':
    main() 