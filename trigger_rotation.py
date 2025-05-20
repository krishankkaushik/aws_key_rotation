#!/usr/bin/env python3
import boto3
import logging
import json
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def trigger_rotation():
    """Trigger the key rotation Lambda function"""
    try:
        # Initialize Lambda client
        lambda_client = boto3.client('lambda')
        
        # Get the function name from CloudFormation
        cf = boto3.client('cloudformation')
        response = cf.describe_stacks(StackName='iam-key-rotation')
        outputs = response['Stacks'][0]['Outputs']
        
        # Find the Lambda function ARN
        lambda_arn = None
        for output in outputs:
            if output['OutputKey'] == 'LambdaFunctionArn':
                lambda_arn = output['OutputValue']
                break
        
        if not lambda_arn:
            raise Exception("Could not find Lambda function ARN in stack outputs")
        
        # Extract function name from ARN
        function_name = lambda_arn.split(':')[-1]
        
        # Invoke the Lambda function
        logger.info(f"Invoking Lambda function: {function_name}")
        response = lambda_client.invoke(
            FunctionName=function_name,
            InvocationType='RequestResponse'
        )
        
        # Parse and log the response
        response_payload = json.loads(response['Payload'].read())
        logger.info("Lambda function response:")
        logger.info(json.dumps(response_payload, indent=2))
        
        logger.info("\nWaiting for keys to be created...")
        logger.info("Please wait a few minutes and then try the API call again.")
        
    except ClientError as e:
        logger.error(f"Error triggering rotation: {str(e)}")
        raise

if __name__ == '__main__':
    trigger_rotation() 