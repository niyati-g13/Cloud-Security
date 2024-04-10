import json
import boto3
from sqs_helper import *
from log_helper import *
from dynamodb_helper import *
from datetime import datetime
'''
Flags for switching on the respective evaluation mechanism. 
If "ON" then evaluation will happen based on that workflow.
'''
CONFIG_RULE_FLAG = "OFF"
EVENT_BRIDGE_FLAG= "ON"

configdb = ConfigDb()
logger = Logger()

def lambda_handler(event, context):
    '''
    Check whether flag for config rule is ON and 
    event has been generated via config rule
    '''
    start_time = datetime.now().isoformat()
    if (CONFIG_RULE_FLAG == "ON" and 'invokingEvent' in event):
        logger.info("Evaluating via Config rule")
        configRuleName = event['configRuleName']
        sqsName = getSQS("configRule",configRuleName)
    elif (EVENT_BRIDGE_FLAG == "ON" and 'invokingEvent' not in event):
        logger.info("Evaluating via Event Bridge")
        eventName = event['detail']['eventName']
        sqsName = getSQS("eventBridge",eventName)
    else:
        logger.info("Check FLAG for Config rule or Event Bridge and Try Again.")
        sqsName = []
    '''
    Publish the event to corresponding Worker Lambda via SQS
    '''
    if len(sqsName) > 0:
        for sqs in sqsName:
            response = publishToSQS(sqs,event)   
            logger.info(f"{response['message']} - {response['queue_name']}")
            end_time = datetime.now().isoformat()
            configdb.insertAuditEntryLL(event['id'],event['account'],event['detail']['eventSource'],event['detail']['eventName'],start_time,end_time,response['queue_name'],response['message'],logger)
        
def getSQS(sourceType,sourceKey):
    '''
    Function for reaching the corresponding file from S3 and fetching the SQS 
    for respective config rule or event(in case of event bridge)
    '''
    sqs_queues = configdb.get_sqs_from_event("event_to_sqs_mapping",sourceKey,logger)
    if sqs_queues:
        sqs_list = sqs_queues.split(",")
        return (sqs_list)
    else:
        return []
