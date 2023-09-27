import boto3
import sys
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError
import json
import ast

def publish_to_sns(message, subject):
    print('subject: ', subject)
    client = boto3.client('sns')
    response = client.publish(
        TopicArn = "arn:aws:sns:us-east-1:296475046815:testDynamo",
        Message = message,
        MessageStructure = "json"
        #Subject = subject
    )
    print('Email Sent :)')
    print(response)

def get_email(accountID):
    print('getacc: ',accountID)
    dynamo_db = boto3.client('dynamodb')
    #table = dynamo_db.Table("test")
    try:
        response = dynamo_db.get_item( 
            TableName= 'test',
            Key={'accountNum': {'N': accountID}})
    except:
        response = "Email not found"
        return response
    #print('EMAIL: ', response)
    print(response.get('Item').get('Security_Emailid').get('S'))
    return (response.get('Item').get('Security_Emailid').get('S'))

def lambda_handler(event, context):
    
    # TODO implement
    # account_number = 296475046815
    
    #sqs = boto3.client('sqs')
    #response = sqs.receive_message(
    #    QueueUrl='https://sqs.us-east-1.amazonaws.com/296475046815/Redlock_alerts',
    #    MaxNumberOfMessages=1,
    #    VisibilityTimeout=123,
    #    WaitTimeSeconds=10
    #)
    print(event)
    for message in event.get('Records'):
        print('Original Message: ', message)
        try:
            messageDict = json.loads(message.get('body'))
            #messageDict = ast.literal_eval(message.get('body'))
        except: 
            messageDict = json.loads(message.get('Body'))
            #messageDict = ast.literal_eval(message.get('Body'))
        #messageDict = json.loads(messageDict.get('Body'))
        print('Final Message: ', messageDict)
        email = get_email(accountID=messageDict.get('accountId'))
        message = {
            "AccountID": messageDict.get('accountId'), 
            "AccountName": messageDict.get('accountName'), 
            "Resource": messageDict.get('resourceId'), 
            "actualMessage": messageDict.get('policyDescription'), 
            "thisEmailWIllbeSentTo": email
        }
        subject = "REDLOCK ALERT: {0}".format(messageDict.get('policyName'))
        Message = json.dumps({'default': json.dumps(message)})
        publish_to_sns(Message, subject)
        #print(get_email(accountID='120357612572'))
        #print(messageDict.get('accountId'),messageDict.get('accountName'),c,messageDict.get('policyName'),messageDict.get('policyDescription'))
      