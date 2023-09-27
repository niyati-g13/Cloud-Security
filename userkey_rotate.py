import boto3
import sys
from botocore.exceptions import ClientError


def lambda_handler(event, context):
    # Create IAM client
    iam=boto3.client('iam')
    
    # List users with the pagination interface
    users = iam.list_users()
    for user in users['Users']:
        try:
            print "Getting UserName"
            username=user['UserName']
            print(username)
            print "Getting Accesskey"
            response=iam.list_access_keys(UserName=username)
            
            #print "Deleting AccessKey for " + username
            accesskey=response['AccessKeyMetadata'][0]['AccessKeyId']
            #response = iam.delete_access_key(UserName=username,AccessKeyId=accesskey)
            #print "Old access key (" + accesskey + ") has been deleted for " + username
            
            iam.update_access_key(UserName=username, AccessKeyId=accesskey, Status="Inactive")
            print "Old access key (" + accesskey + ") has been disabled for " + username
            response = iam.create_access_key(
                UserName=username
            )
            print "Creating New AccessKey for " + username
            accesskey=response['AccessKey'][0]['AccessKeyId']
            print "New access key (" + accesskey + ") has been created for " + username
        
        except Exception as error:
            exception_message = str(error)
            print(exception_message)

        
