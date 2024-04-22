import boto3
import botocore
import json
from datetime import datetime
from utils import *
from log_helper import *
from notify import *
from dynamodbhelper import *
from ec2_helper import *
from sqs_helper import *

COMPLIANT = "COMPLIANT"
NON_COMPLIANT = "NON_COMPLIANT"
NOT_APPLICABLE = "NOT_APPLICABLE"

configdb = ConfigDb()
logger = Logger()

RISKY_PORTS = [21,12345,12346,23]    
def lambda_handler(event, context):
    
    logger.info(event)
    
    deleteMessage(event['Records'][0])
    payloadId = event['Records'][0]['messageId']
    start_time = datetime.now().isoformat()

    payload_in_json = json.loads(event['Records'][0]['body'])
    

    accountId = getAccountIdFromEventPayload(payload_in_json)
    logger.info(f'Retrieved account id - {accountId}')
    event_type = getEventNameFromPayload(payload_in_json)
    logger.info(f'Retrieved event type - {event_type}')
    if not accountId:
        logger.error("Account Id not present in Payload. Contact GSC Security Team")
        return

    executionRole = configdb.get_execution_role(accountId,"security_group",logger)

  
    try:
      credentials = getTemporaryCredentials(executionRole,payloadId)
    except:
      logger.error("Cannot retrieve credentials to access source account", accountId)  

    if (event_type == "ModifySecurityGroupRules"):
        logger.info(f'Processing security rule for event - {event_type}')
        workflowForModifyIngress(payload_in_json, executionRole, accountId, start_time, credentials)
    elif (event_type == "AuthorizeSecurityGroupIngress"):
        logger.info(f'Processing security rule for event - {event_type}')
        workflowForAuthorizeIngress(payload_in_json, executionRole, accountId, start_time, credentials)
        

def workflowForAuthorizeIngress(payload_in_json,executionRole, accountId, start_time, credentials):
    security_group = getSecurityGroupEventPayload(payload_in_json)
    list_of_remediated_rules = ""
    transformed_string = ""
    security_group_list = payload_in_json['detail']['responseElements']['securityGroupRuleSet']['items']
    
    if payload_in_json['detail']['responseElements'] is None:
        logger.error("Request not processed by AWS. Existing now")
        return

    for rules in security_group_list:
        logger.info(f'Beginning to evaluate rule - {rules}')
        securityGroupRuleId = rules['securityGroupRuleId']
        transformed_rule = convertRuleToGenericFormat(rules)
        isCompliant = evaluateSecurityGroupRule(transformed_rule,securityGroupRuleId)
        if isCompliant:
            logger.info(f'Security Group Rule {securityGroupRuleId} is compliant.Exiting')
        elif not isCompliant:
            logger.info(f'Security Group Rule {securityGroupRuleId} is not compliant. Checking exemption')
            isExempted = isRemediationExemptedViaTag(security_group,credentials,accountId)
            if isExempted:
                logger.info(f'Security Group {security_group} is exempted from deletion. Exiting.')
                return 
            else:
                logger.info(f'Security Group {security_group} is not exempted. Checking if ingress rule or not')
                if rules['isEgress'] == True:
                    logger.info(f'Rule is egress. Exiting')
                else:
                    isCompliantAgain = evaluateSecurityGroup(security_group,securityGroupRuleId,accountId,credentials)
                    isExemptedInDB = isRemediationExemptedInDB(security_group,credentials,accountId)
                    isExemptedViaList = isSecurityGroupInExemptedList(security_group)
                    logger.info(f'isCompliantAgain - {isCompliantAgain}')
                    logger.info(f'isExemptedInDB - {isExemptedInDB}')
                    logger.info(f'isSecurityGroupInExemptionList - {isExemptedViaList}')
                    if isCompliantAgain:
                        logger.info(f'Security Group {security_group} found compliant on re-evaluation')
                    elif not isCompliantAgain and not isExemptedInDB and not isExemptedViaList:
                        transformed_string = transformed_string + '\n  '+str(transform_string_for_notification(securityGroupRuleId,security_group,credentials))
                        remediateSecurityGroupRule(security_group,securityGroupRuleId,credentials,accountId)
                        list_of_remediated_rules = securityGroupRuleId+","+list_of_remediated_rules
                        logger.info("Inserting entry into audit db.")
                        end_time = datetime.now().isoformat()
                        try:
                            configdb.insertAuditEntryWL(payload_in_json['id'],security_group,accountId,executionRole,rules,isExemptedInDB,start_time,end_time,logger)
                        except:
                            logger.error("Could not insert entry into Audit DB")
                        logger.info("Entry inserted into Audit DB")                           
                    elif not isCompliantAgain and isExemptedInDB:
                        logger.info(f'Security group {security_group} will not be remediated as account {accountId} is exempted')
                    elif not isCompliantAgain and isExemptedViaList:
                        logger.info(f'Security Group {security_group} will not be remediated as it is in exemption list')
                        
    if (len(list_of_remediated_rules) > 0): 
        receipent_list = configdb.get_receipents(accountId,logger)
        sendNotification(receipent_list,security_group,transformed_string,accountId,credentials,payload_in_json,logger)

    
def workflowForModifyIngress(payload_in_json,executionRole, accountId, start_time, credentials):
    security_group = getSecurityGroupEventPayload(payload_in_json)
    
    security_group_list = payload_in_json['detail']['requestParameters']['ModifySecurityGroupRulesRequest']['SecurityGroupRule']

    securityGroupRuleId = security_group_list['SecurityGroupRuleId']
    rules = security_group_list['SecurityGroupRule']
    isCompliant = evaluateSecurityGroupRule(rules,securityGroupRuleId)
    if isCompliant:
        logger.info(f'Security Group Rule {rules} is compliant.Existing')
    elif not isCompliant:
        logger.info(f'Security Group Rule {rules} is not compliant. checking exemption')
        isExempted = isRemediationExemptedViaTag(security_group,credentials,accountId)
        if isExempted:
            logger.info(f'Security Group {security_group} is exempted from deletion. Exiting.')
            return
        else:
            logger.info(f'Security Group {security_group} is not exempted. checking if ingress rule or not')
            if (isSecurityRuleEgress(securityGroupRuleId,security_group,credentials)):
                logger.info(f'Rule is egress. Exiting')
            else:
                isCompliantAgain = evaluateSecurityGroup(security_group,securityGroupRuleId,accountId,credentials)
                isExemptedInDB = isRemediationExemptedInDB(security_group,credentials,accountId)
                isExemptedViaList = isSecurityGroupInExemptedList(security_group)
                logger.info(f'isCompliantAgain - {isCompliantAgain}')
                logger.info(f'isExemptedInDB - {isExemptedInDB}')
                logger.info(f'isSecurityGroupInExemptionList - {isExemptedViaList}')                
                if isCompliantAgain:
                    logger.info(f'Security Group {security_group} found compliant on re-evaluation')
                elif not isCompliantAgain and not isExemptedInDB and not isExemptedViaList:
                    transformed_string = transform_string_for_notification(securityGroupRuleId,security_group,credentials)
                    remediateSecurityGroupRule(security_group,securityGroupRuleId,credentials,accountId)
                    receipent_list = configdb.get_receipents(accountId,logger)
                    sendNotification(receipent_list,security_group,transformed_string,accountId,credentials,payload_in_json,logger)
                    end_time = datetime.now().isoformat()
                    try:
                        configdb.insertAuditEntryWL(payload_in_json['id'],security_group,accountId,executionRole,rules,isExemptedInDB,start_time,end_time,logger)
                    except:
                        logger.info("Could not insert entry into Audit DB")
                    logger.info("Entry inserted into Audit DB")
                elif not isCompliantAgain and isExemptedInDB:
                    logger.info(f'Security group {security_group} will not be remdiated as account {accountId} is exempted')
                elif not isCompliantAgain and isExemptedViaList:
                    logger.info(f'Security Group {security_group} will not be remediated as it is in exemption list')                    

def transform_string_for_notification(ruleIds,security_group,credentials):
    #Creating EC2 object in origin account
    ec2 = getEC2(credentials)

    security_group_rules  = ec2.describe_security_group_rules(
        Filters=[
            {
                'Name': 'group-id',
                'Values' : [security_group]
            }
        ],
         SecurityGroupRuleIds=[ruleIds]        
    )    
    string = "Security Rule ID:: "+security_group_rules['SecurityGroupRules'][0]['SecurityGroupRuleId']
    string = string+", FromPort: "+str(security_group_rules['SecurityGroupRules'][0]['FromPort'])
    string = string+", ToPort: "+str(security_group_rules['SecurityGroupRules'][0]['ToPort'])
    if ('CidrIpv6' in security_group_rules['SecurityGroupRules'][0]):
        string = string+", CidrIpv6: "+str(security_group_rules['SecurityGroupRules'][0]['CidrIpv6'])
    else:
        string = string+", CidrIpv4: "+str(security_group_rules['SecurityGroupRules'][0]['CidrIpv4'])
    string = string + "\n  "
    return(string)
        
    
def convertRuleToGenericFormat(rule):
    transformed_rule = {}
    
    if (rule['ipProtocol'] != -1):  #Condition to check for all ports access
        transformed_rule['FromPort'] = rule['fromPort']
        transformed_rule['ToPort'] = rule['toPort']
    if ('cidrIpv4' in rule):
        transformed_rule['CidrIpv4'] = rule['cidrIpv4']
    elif ('cidrIpv6' in rule):
        transformed_rule['CidrIpv6'] = rule['cidrIpv6']
    transformed_rule['IpProtocol'] = rule['ipProtocol']
    return transformed_rule
    
def isSecurityRuleEgress(securityGroupRuleId,security_group,credentials):
    logger.info("Checking if security group rule is egress or not")

    #Creating EC2 object in origin account
    ec2 = getEC2(credentials)
    
    #Fetching the inbound and outbound rules for security group
    security_group_rules  = ec2.describe_security_group_rules(
        Filters=[
            {
                'Name': 'group-id',
                'Values' : [security_group]
            }
        ],
         SecurityGroupRuleIds=[securityGroupRuleId]        
    )
    isEgress = security_group_rules['SecurityGroupRules'][0]['IsEgress']
    
    if isEgress is True:
        return True
    else:
        return False
    
def evaluateSecurityGroupRule(rules,securityGroupRuleId):
    isCompliant = True
    logger.info(f'Starting to evaluate security group rule id - {securityGroupRuleId}')
    logger.info(f'{securityGroupRuleId} :: {rules}')
    if ('CidrIpv4' in rules):
        ipAddress = rules['CidrIpv4'].split('/')
        if (ipAddress[0] == "0.0.0.0" or str(rules['IpProtocol']) == '-1'):
            isCompliant = False
        elif (str(rules['IpProtocol']) != '-1'):
            for port in RISKY_PORTS:
                if (rules['FromPort'] <= port and rules['ToPort'] >= port and rules['IpProtocol'] == 'tcp'):
                    isCompliant = False
            if (rules['FromPort'] <= 113 and rules['ToPort'] >= 113 and rules['IpProtocol'] == 'udp'):
                isCompliant = False
     
    elif ('CidrIpv6' in rules):
        ipAddress = rules['CidrIpv6'].split('/')
        if (ipAddress[0] == "::" or str(rules['IpProtocol']) == '-1'):
            isCompliant = False  
        elif (str(rules['IpProtocol']) != '-1'):
            for port in RISKY_PORTS:
                if (rules['FromPort'] <= port and rules['ToPort'] >= port and rules['IpProtocol'] == 'tcp'):
                    isCompliant = False
            if (rules['FromPort'] <= 113 and rules['ToPort'] >= 113 and rules['IpProtocol'] == 'udp'):
                isCompliant = False    
                
    logger.info(f'Compliance status of security group rule id {securityGroupRuleId} - {isCompliant}')
            
    return isCompliant
    
def evaluateSecurityGroup(security_group,securityGroupRuleId,accountId,credentials):
    logger.info(f'Evaluating Security Group Again')

    #Creating EC2 object in origin account
    ec2 = getEC2(credentials)
    
    #Fetching the inbound and outbound rules for security group
    security_group_rules  = ec2.describe_security_group_rules(
        Filters=[
            {
                'Name': 'group-id',
                'Values' : [security_group]
            }
        ],
         SecurityGroupRuleIds=[securityGroupRuleId]        
    )

    logger.info(f'Retrieved security group rule {security_group_rules}')
    
    sgr_violations = []
    for rules in security_group_rules['SecurityGroupRules']:
        if ('CidrIpv4' in rules):
            ipAddress = rules['CidrIpv4'].split('/')
            if (rules['IpProtocol'] == '-1'):
                sgr_violations.append(rules['SecurityGroupRuleId'])
            else:
                if ((rules['IsEgress'] == False ) and ipAddress[0] == "0.0.0.0" ):
                    sgr_violations.append(rules['SecurityGroupRuleId'])  
                if (rules['IsEgress'] == False ):
                    for port in RISKY_PORTS:
                        if (rules['FromPort'] <= port and rules['ToPort'] >= port and rules['IpProtocol'] == 'tcp'):
                             sgr_violations.append(rules['SecurityGroupRuleId'])
                    if (rules['FromPort'] <= 113 and rules['ToPort'] >= 113 and rules['IpProtocol'] == 'udp'):
                        sgr_violations.append(rules['SecurityGroupRuleId'])
               
        elif ('CidrIpv6' in rules):
            ipAddress = rules['CidrIpv6'].split('/')
            if (rules['IpProtocol'] == '-1'):
                sgr_violations.append(rules['SecurityGroupRuleId'])
            else:
                if ((rules['IsEgress'] == False ) and ipAddress[0] == "::" ):
                    sgr_violations.append(rules['SecurityGroupRuleId'])  
                if (rules['IsEgress'] == False ):
                    for port in RISKY_PORTS:
                        if (rules['FromPort'] <= port and rules['ToPort'] >= port and rules['IpProtocol'] == 'tcp'):
                             sgr_violations.append(rules['SecurityGroupRuleId'])
                    if (rules['FromPort'] <= 113 and rules['ToPort'] >= 113 and rules['IpProtocol'] == 'udp'):
                        sgr_violations.append(rules['SecurityGroupRuleId'])    

    if (len(sgr_violations) > 0):
        logger.info("Violation found in security group")
        return False
    else:
        logger.info("No Violations found in security group")
        return True
        
    
def isRemediationExemptedViaTag(security_group,credentials,accountId):
    ec2 = getEC2(credentials)
    isExemptd = "No"
    response = ec2.describe_security_groups(GroupIds=[security_group])
    if 'Tags' in response['SecurityGroups'][0]:
        for tag in response['SecurityGroups'][0]['Tags']:
            if tag['Key'] == "scpxception" and tag['Value'] == "true":
                isExemptd = "Yes"
                
    logger.info(f'Exemption Status after evaluating rules - {isExemptd}') 
    
    if isExemptd == "Yes":
       return True
    else:
       return False   

def isRemediationExemptedInDB(security_group,credentials,accountId):
    '''
    Check exception for remediation at account level
    using dynamodb 
    '''
    logger.info("Retreving remediation status from DB") 
    try:
      status = configdb.get_remediation_status(accountId,logger)
    except:
      logger.error("Could not get remediation status from Database.")

    logger.info(f'Fetched status from remediation table {status}')
    if status == "No":
        return True
    elif status == "Yes":
        return False
    elif not status:
        return

def isSecurityGroupInExemptedList(security_group):
    '''
    Check exception for remediation if security group is in exempted list in dynamodb 
    '''
    logger.info("Checking security group against exemption list") 
    try:
      status = configdb.is_security_group_in_exemption_list(security_group,logger)
    except:
      logger.error("Could not get exempted status from Database.")

    logger.info(f'Fetched status from exemptioned table - {status}')
    if status == "True":
        return True
    elif status == "False":
        return False
    
def remediateSecurityGroupRule(security_group,security_group_rule_id,credentials,accountId):
    logger.info("Starting to remediate security group by deleting the non compliant rules")
    ec2 = getEC2(credentials)
    rule_id = security_group_rule_id.split()
    response = ec2.revoke_security_group_ingress(GroupId=security_group,SecurityGroupRuleIds=rule_id)
    logger.info(f'Non compliant security group rule {security_group_rule_id} has been deleted')
    
def getEventNameFromPayload(payload_in_json):
    if 'eventName' in payload_in_json['detail']:
        return(payload_in_json['detail']['eventName'])
    else:
        return null
    
def getSecurityGroupEventPayload(payload_in_json):
    if ('AuthorizeSecurityGroupIngress' == payload_in_json['detail']['eventName']):
      logger.info("Retrieving security group id from AuthorizeSecurityGroupIngress event payload")
      security_group_id = payload_in_json['detail']['requestParameters']['groupId']
      logger.info(f'Security group id retrieved from AuthorizeSecurityGroupIngress payload - {security_group_id}')
      return(payload_in_json['detail']['requestParameters']['groupId'])
    elif ('ModifySecurityGroupRulesRequest' in payload_in_json['detail']['requestParameters']):
      logger.info("Retrieving security group id from ModifySecurityGroupRules event payload")
      security_group_id = payload_in_json['detail']['requestParameters']['ModifySecurityGroupRulesRequest']['GroupId'] 
      logger.info(f'Security group id retrieved from ModifySecurityGroupRulesRequest event payload - {security_group_id}')
      return(payload_in_json['detail']['requestParameters']['ModifySecurityGroupRulesRequest']['GroupId'])

