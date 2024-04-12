import botocore

from cc import Rule, AwsResource, TEST_MODE, Status
from cc import Config
from utils import *
from logging_helpers import logger
import time

class DynamoDBTableResource(AwsResource):
    def initialize(self):
        dynamodb_table_arn = self.payload['detail'].get('tableName')
        if 'requestParameters' in self.payload['detail'] and 'tableName' in self.payload['detail']['requestParameters']:
            self.resource_name = self.payload['detail']['requestParameters']['tableName']
            self.resource_id = self.resource_name
            self.version = 'dynamodb'
            self.resource_type = 'dynamodb'
            self.account_id = self.payload['account']
            self.session_id = self.payload['id']

    def describe(self):
            return self.client.describe_table(TableName=self.resource_name)

    def is_ready_for_remediation(self):
        return True

class CMKEnablementCheck(Rule):
    rule_id = 'status_dynamo'
    rule_name = 'CMK Encryption Enabled'
    rule_description = 'CMK Encryption Enabled'

    def remediate_next(self) -> bool:
        """
        We do not want to remediate for next rule since this rule remediation will delete the resource
        """
        return False

    def get_notification_msg(self) -> str:
        return "Dynamodb tables should be CMK Encrypted"


    def remediate(self):
        try:
            kwargs = {'TableName': self.resource.resource_name}
            
            if TEST_MODE:
                response = {"msg": "Test MODE On, fake/pretend deleted dynamodb"}
            else:
                logger.info("Ensuring delete protection is switched off for dynamodb table")
                response = self.client.update_table(TableName=self.resource.resource_name,DeletionProtectionEnabled=False)
                logger.info("Delete protection has been disabled from dynamodb table. Proceeding to delete now.")
                while(True):
                    logger.info("Wait for 5s until table is in UPDATE state")
                    time.sleep(5)
                    response = self.client.describe_table(TableName=self.resource.resource_name)
                    if response['Table']['TableStatus'] == 'ACTIVE':
                        break;
                response = self.client.delete_table(**kwargs)

            logger.info(
                f"Dynamo DB table ({self.resource.resource_name}) kwargs={kwargs} was non-compliant and has been deleted successfully! "
                f"Response: {response}"
            )
            self.remediation_status = Status.DELETED

        except botocore.exceptions.ClientError as e:
            logger.error(f"Failed to delete dynamodb table: {self.resource.resource_name}. Error: {e}")
            logger.exception(e)
            self.remediation_status = Status.FAILED

        return self.remediation_status == Status.DELETED

    def check_compliance(self) -> bool:
        logger.info(f"Fetching DynamoDb table attributes...")
        cmk_enabled = True
        if self.resource.version == 'dynamodb':
            attributes = self.client.describe_table(TableName=self.resource.resource_name)
            logger.info(f"Fetched Table attributes. {attributes}")
            logger.info(attributes['Table']['DeletionProtectionEnabled'])
            if 'Table' in attributes and 'SSEDescription' in attributes['Table'] and 'SSEType' in attributes['Table']['SSEDescription']:
                cmk_type = attributes['Table']['SSEDescription']['SSEType']
                if (cmk_type != 'KMS'):
                    cmk_enabled = False
                elif (cmk_type == 'KMS'):
                    cmk_arn = attributes['Table']['SSEDescription']['KMSMasterKeyArn']
                    #role_arn = get_execution_role(self.account_id,self.resource.resource_type)
                    #credentials = get_temporary_credentials(role_arn, self.resource.session_id)
                    credentials = self.resource.get_context('credentials')
                    kms_client = get_boto_client_with_temporary_credentials(credentials, service='kms')       
                    
                    try:
                        response = kms_client.describe_key(KeyId=cmk_arn)
                        print(response)
                        if ('KeyMetadata' in response and 'KeyManager' in response['KeyMetadata'] and response['KeyMetadata']['KeyManager'] == 'AWS'):
                            cmk_enabled = False

                        elif ('KeyMetadata' in response and 'KeyManager' in response['KeyMetadata'] and response['KeyMetadata']['KeyManager'] == 'CUSTOMER'):
                            cmk_enabled = True
                        else:
                            cmk_enabled = False 
                    except kms_client.exceptions.NotFoundException:
                        cmk_enabled = False
            else:
                cmk_enabled = False
        return cmk_enabled

Config.register_rule(CMKEnablementCheck)
Config.register_resource_class(DynamoDBTableResource)
