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

def test_rotation():
    """Test the key rotation by directly invoking the Lambda function"""
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
        
        # Create test event
        test_event = {
            "source": "manual-test",
            "detail-type": "Scheduled Event",
            "time": "2024-01-01T00:00:00Z"
        }
        
        # Invoke the Lambda function
        logger.info(f"Invoking Lambda function: {function_name}")
        response = lambda_client.invoke(
            FunctionName=function_name,
            InvocationType='RequestResponse',
            Payload=json.dumps(test_event)
        )
        
        # Parse and log the response
        response_payload = json.loads(response['Payload'].read())
        logger.info("Lambda function response:")
        logger.info(json.dumps(response_payload, indent=2))
        
        # Check CloudWatch logs
        logs_client = boto3.client('logs')
        try:
            log_streams = logs_client.describe_log_streams(
                logGroupName=f'/aws/lambda/{function_name}',
                orderBy='LastEventTime',
                descending=True,
                limit=1
            )
            
            if log_streams['logStreams']:
                latest_stream = log_streams['logStreams'][0]['logStreamName']
                logs = logs_client.get_log_events(
                    logGroupName=f'/aws/lambda/{function_name}',
                    logStreamName=latest_stream,
                    limit=50
                )
                
                logger.info("\nLatest CloudWatch logs:")
                for event in logs['events']:
                    logger.info(event['message'])
            else:
                logger.info("No log streams found")
                
        except ClientError as e:
            logger.error(f"Error getting CloudWatch logs: {str(e)}")
        
    except Exception as e:
        logger.error(f"Error testing rotation: {str(e)}")
        raise

if __name__ == '__main__':
    test_rotation() 