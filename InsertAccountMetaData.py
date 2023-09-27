import json
import boto3


def lambda_handler(event, context):
    #TODO: Implement varaibles from actual event dict
    # Assume CIPKrakenRole with sts client to get credentials for account
    account_id = "296475046815"
    sts_client = boto3.client('sts')
    #arnToUse = "arn:aws:iam::" + account_id + ":role/CIPKrakenRole"
    #try:
    #    assumedRoleObject = sts_client.assume_role(
     #       RoleArn=arnToUse,
      #      RoleSessionName="CIP-Kraken")
    #except Exception as error:
     #   print(str(error))
    #credentials = assumedRoleObject['Credentials']
    #print(credentials)
    
   
    # Get dynamo DB client to insert account metadata
    dynamo_client = boto3.client('dynamodb')
    print(event)
    
    response = dynamo_client.put_item(
    Item={
        'Account_Id': {
            'S': str(event.get('account_id')),
        },
        'Account_Name': {
            'S': event.get('account_name'),
        },
        'Environmanet': {
            'S': event.get('env'),
        },
        'Group_Email_Id': {
            'S': event.get('email')
        }
    },
    ReturnConsumedCapacity='TOTAL',
    TableName='AccountMetaData2',
    )
    
    
    #print("Table Response: ", resposne)
    
