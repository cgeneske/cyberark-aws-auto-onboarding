import json
import time
import random
import boto3
from log_mechanism import LogMechanism
from dynamo_lock import LockerClient

DEBUG_LEVEL_DEBUG = 'debug' # Outputs all information
logger = LogMechanism()


# return ec2 instance relevant data:
# keyPair_name, instance_address, platform
def get_account_details(solution_account_id, event_account_id, event_region):
    logger.trace(solution_account_id, event_region, event_account_id, caller_name='get_account_details')
    if event_account_id == solution_account_id:
        logger.info('Event occurred in the AOB solution account')
        try:
            ec2_resource = boto3.resource('ec2', event_region)
        except Exception as e:
            logger.error(f'Error on creating boto3 session: {str(e)}')
    else:
        logger.info('Event occurred in different account')
        try:
            logger.info('Assuming Role')
            sts_connection = boto3.client('sts')
            acct_b = sts_connection.assume_role(
                RoleArn=f"arn:aws:iam::{event_account_id}:role/CyberArk-AOB-AssumeRoleForElasticityLambda-{event_region}",
                RoleSessionName="cross_acct_lambda"
            )

            access_key = acct_b['Credentials']['AccessKeyId']
            secret_key = acct_b['Credentials']['SecretAccessKey']
            session_token = acct_b['Credentials']['SessionToken']

            # create service client using the assumed role credentials, e.g. S3
            ec2_resource = boto3.resource(
                'ec2',
                region_name=event_region,
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                aws_session_token=session_token,
            )
        except Exception as e:
            logger.error(f'Error on getting token from account: {event_account_id}')
    return ec2_resource


def get_ec2_details(instance_id, ec2_object, event_account_id):
    logger.trace(instance_id, ec2_object, event_account_id, caller_name='get_ec2_details')
    logger.info(f'Gathering details about EC2 - {instance_id}')
    try:
        instance_resource = ec2_object.Instance(instance_id)
        instance_image = ec2_object.Image(instance_resource.image_id)
        logger.info(f'Image Detected: {str(instance_image)}')
        image_description = instance_image.description
        # If we don't see an image description, use the image name instead
        if not image_description:
            image_description = instance_image.name
        # If we don't see an image name either, set image_description to "None" which will match to ec2_user
        if not image_description:
            image_description = "None"
    except Exception as e:
        logger.error(f'Error on getting instance details: {str(e)}')
        raise e

    #  We take the instance address in the order of: public dns -> public ip -> private ip ##
    if instance_resource.private_ip_address:
        address = instance_resource.private_ip_address
    else:  # unable to retrieve address from aws
        address = None

    details = dict()
    details['key_name'] = instance_resource.key_name
    details['address'] = address
    details['platform'] = instance_resource.platform
    details['image_description'] = image_description
    details['aws_account_id'] = event_account_id
    if instance_resource.tags:
        for tag in instance_resource.tags:
            if tag["Key"] == 'CyberArk-Safe':
                details['safe_name'] = tag["Value"]

    return details


# Check on DynamoDB if instance exists
# Return False when not found, or row data from table
def get_instance_data_from_dynamo_table(instance_id):
    logger.trace(instance_id, caller_name='get_instance_data_from_dynamo_table')
    logger.info(f'Check with DynamoDB if instance {instance_id} exists')
    dynamo_resource = boto3.client('dynamodb')

    try:
        dynamo_response = dynamo_resource.get_item(TableName='Instances', Key={"InstanceId": {"S": instance_id}})
    except Exception as e:
        logger.error(f"Error occurred when trying to call DynamoDB: {e}")
        return False
    # DynamoDB "Item" response: {'Address': {'S': 'xxx.xxx.xxx.xxx'}, 'instance_id': {'S': 'i-xxxxxyyyyzzz'},
    #               'Status': {'S': 'on-boarded'}, 'Error': {'S': 'Some Error'}}
    if 'Item' in dynamo_response:
        if dynamo_response["Item"]["InstanceId"]["S"] == instance_id:
            logger.info(f'{instance_id} exists in DynamoDB')
            return dynamo_response["Item"]
    return False


def get_params_from_param_store():
    # Parameters that will be retrieved from parameter store
    logger.info('aws_services - Getting parameters from parameter store')
    UNIX_SAFE_NAME_PARAM = "AOB_Unix_Safe_Name"
    WINDOWS_SAFE_NAME_PARAM = "AOB_Windows_Safe_Name"
    VAULT_USER_PARAM = "AOB_Vault_User"
    PVWA_IP_PARAM = "AOB_PVWA_IP"
    AWS_KEYPAIR_SAFE = "AOB_KeyPair_Safe"
    AWS_KEYPAIR_NAME = "AOB_KeyPair_Name"
    AWS_KEYPAIR_PLATFORM = "AOB_KeyPair_Platform"
    VAULT_PASSWORD_PARAM_ = "AOB_Vault_Pass"
    PVWA_VERIFICATION_KEY = "AOB_PVWA_Verification_Key"
    AOB_MODE = "AOB_mode"
    AOB_DEBUG_LEVEL = "AOB_Debug_Level"
    VAULT_USER_SOURCE_PARAM = "AOB_Vault_User_Source"
    CONJUR_VERIFICATION_KEY = "AOB_Conjur_Verification_Key"
    CONJUR_HOSTNAME_PARAM = "AOB_Conjur_Hostname"
    CONJUR_ACCOUNT_PARAM = "AOB_Conjur_Account"
    CONJUR_AUTHN_SERVICE_ID_PARAM = "AOB_Conjur_Authn_Service_ID"
    CONJUR_AUTHN_HOST_NAMESPACE_PARAM = "AOB_Conjur_Authn_Host_Namespace"
    CONJUR_VAULT_USERNAME_ID_PARAM = "AOB_Conjur_Vault_Username_ID"
    CONJUR_VAULT_PASSWORD_ID_PARAM = "AOB_Conjur_Vault_Password_ID"

    lambda_client = boto3.client('lambda')
    lambda_request_data = dict()
    lambda_request_data["Parameters"] = [UNIX_SAFE_NAME_PARAM, WINDOWS_SAFE_NAME_PARAM, VAULT_USER_PARAM, PVWA_IP_PARAM,
                                         AWS_KEYPAIR_SAFE, VAULT_PASSWORD_PARAM_, PVWA_VERIFICATION_KEY, AOB_MODE,
                                         AOB_DEBUG_LEVEL, VAULT_USER_SOURCE_PARAM]

    try:
        response = lambda_client.invoke(FunctionName='TrustMechanism',
                                        InvocationType='RequestResponse',
                                        Payload=json.dumps(lambda_request_data))
    except Exception as e:
        logger.error(f"Error retrieving parameters from parameter parameter store:\n{str(e)}")
        raise Exception(f"Error retrieving parameters from parameter parameter store: {str(e)}")

    should_retrieve_conjur_params = False
    json_parsed_response = json.load(response['Payload'])
    # parsing the parameters, json_parsed_response is a list of dictionaries
    for ssm_store_item in json_parsed_response:
        if ssm_store_item['Name'] == UNIX_SAFE_NAME_PARAM:
            unix_safe_name = ssm_store_item['Value']
        elif ssm_store_item['Name'] == WINDOWS_SAFE_NAME_PARAM:
            windows_safe_name = ssm_store_item['Value']
        elif ssm_store_item['Name'] == VAULT_USER_PARAM:
            vault_username = ssm_store_item['Value']
        elif ssm_store_item['Name'] == PVWA_IP_PARAM:
            pvwa_ip = ssm_store_item['Value']
        elif ssm_store_item['Name'] == AWS_KEYPAIR_SAFE:
            key_pair_safe_name = ssm_store_item['Value']
        elif ssm_store_item['Name'] == VAULT_PASSWORD_PARAM_:
            vault_password = ssm_store_item['Value']
        elif ssm_store_item['Name'] == PVWA_VERIFICATION_KEY:
            pvwa_verification_key = ssm_store_item['Value']
        elif ssm_store_item['Name'] == VAULT_USER_SOURCE_PARAM:
            vault_user_source = ssm_store_item['Value']
            if vault_user_source == 'CyberArk Conjur':
                vault_username = ''
                vault_password = ''
                should_retrieve_conjur_params = True
        elif ssm_store_item['Name'] == AOB_DEBUG_LEVEL:
            debug_level = ssm_store_item['Value']
        elif ssm_store_item['Name'] == AOB_MODE:
            aob_mode = ssm_store_item['Value']
            if aob_mode == 'POC':
                pvwa_verification_key = ''
                conjur_verification_key = ''
        else:
            continue

    # Max 10 parameters per request, looking up remaining parameters
    lambda_request_data["Parameters"] = [AWS_KEYPAIR_NAME, AWS_KEYPAIR_PLATFORM]

    try:
        response = lambda_client.invoke(FunctionName='TrustMechanism',
                                        InvocationType='RequestResponse',
                                        Payload=json.dumps(lambda_request_data))
    except Exception as e:
        logger.error(f"Error retrieving parameters from parameter parameter store:\n{str(e)}")
        raise Exception(f"Error retrieving parameters from parameter parameter store: {str(e)}")

    json_parsed_response = json.load(response['Payload'])
    # parsing the parameters, json_parsed_response is a list of dictionaries
    for ssm_store_item in json_parsed_response:
        if ssm_store_item['Name'] == AWS_KEYPAIR_NAME:
            key_pair_name = ssm_store_item['Value']
        elif ssm_store_item['Name'] == AWS_KEYPAIR_PLATFORM:
            key_pair_platform = ssm_store_item['Value']
        else:
            continue

    # Key Pair name and platform are optional and may not exist; setting defaults here if not defined in SSM
    if 'key_pair_name' not in locals():
        key_pair_name = ''
    if 'key_pair_platform' not in locals():
        key_pair_platform = 'UnixSSHKeys'

    if not should_retrieve_conjur_params:
        store_parameters_class = StoreParameters(unix_safe_name, windows_safe_name, vault_username, vault_password,
                                                 pvwa_ip, key_pair_safe_name, key_pair_name, key_pair_platform,
                                                 pvwa_verification_key, aob_mode, debug_level, vault_user_source)
        return store_parameters_class

    lambda_request_data_conjur = dict()
    lambda_request_data_conjur["Parameters"] = [CONJUR_VERIFICATION_KEY, CONJUR_HOSTNAME_PARAM, CONJUR_ACCOUNT_PARAM,
                                                CONJUR_AUTHN_SERVICE_ID_PARAM, CONJUR_AUTHN_HOST_NAMESPACE_PARAM,
                                                CONJUR_VAULT_USERNAME_ID_PARAM, CONJUR_VAULT_PASSWORD_ID_PARAM]

    try:
        response_conjur = lambda_client.invoke(FunctionName='TrustMechanism',
                                               InvocationType='RequestResponse',
                                               Payload=json.dumps(lambda_request_data_conjur))
    except Exception as e:
        logger.error(f"Error retrieving parameters from parameter parameter store:\n{str(e)}")
        raise Exception(f"Error retrieving parameters from parameter parameter store: {str(e)}")

    json_parsed_response_conjur = json.load(response_conjur['Payload'])
    # parsing the parameters, json_parsed_response is a list of dictionaries
    for ssm_store_item in json_parsed_response_conjur:
        if ssm_store_item['Name'] == CONJUR_VERIFICATION_KEY:
            conjur_verification_key = ssm_store_item['Value']
        elif ssm_store_item['Name'] == CONJUR_HOSTNAME_PARAM:
            conjur_hostname = ssm_store_item['Value']
        elif ssm_store_item['Name'] == CONJUR_ACCOUNT_PARAM:
            conjur_account = ssm_store_item['Value']
        elif ssm_store_item['Name'] == CONJUR_AUTHN_SERVICE_ID_PARAM:
            conjur_authn_service_id = ssm_store_item['Value']
        elif ssm_store_item['Name'] == CONJUR_AUTHN_HOST_NAMESPACE_PARAM:
            conjur_authn_host_namespace = ssm_store_item['Value']
        elif ssm_store_item['Name'] == CONJUR_VAULT_USERNAME_ID_PARAM:
            conjur_vault_username_id = ssm_store_item['Value']
        elif ssm_store_item['Name'] == CONJUR_VAULT_PASSWORD_ID_PARAM:
            conjur_vault_password_id = ssm_store_item['Value']
        else:
            continue

    store_parameters_class = StoreParameters(unix_safe_name, windows_safe_name, vault_username, vault_password, pvwa_ip,
                                             key_pair_safe_name, key_pair_name, key_pair_platform,
                                             pvwa_verification_key, aob_mode, debug_level, vault_user_source,
                                             conjur_verification_key, conjur_hostname, conjur_account,
                                             conjur_authn_service_id, conjur_authn_host_namespace,
                                             conjur_vault_username_id, conjur_vault_password_id)
    return store_parameters_class


def put_instance_to_dynamo_table(instance_id, ip_address, on_board_status, on_board_error="None", log_name="None"):
    logger.trace(instance_id, ip_address, on_board_status, on_board_error, log_name, caller_name='put_instance_to_dynamo_table')
    logger.info(f'Adding  {instance_id} to DynamoDB')
    dynamodb_resource = boto3.resource('dynamodb')
    instances_table = dynamodb_resource.Table("Instances")
    try:
        instances_table.put_item(
            Item={
                'InstanceId': instance_id,
                'Address': ip_address,
                'Status': on_board_status,
                'Error': on_board_error,
                'LogId': log_name
            }
        )
    except Exception:
        logger.error('Exception occurred on add item to DynamoDB')
        return False

    logger.info(f'Item {instance_id} added successfully to DynamoDB')
    return True


def release_session_on_dynamo(session_id, session_guid, sessions_table_lock_client=False):
    logger.trace(session_id, session_guid, caller_name='release_session_on_dynamo')
    logger.info('Releasing session lock from DynamoDB')
    try:
        if not sessions_table_lock_client:
            sessions_table_lock_client = LockerClient('Sessions')
        sessions_table_lock_client.locked = True
        sessions_table_lock_client.guid = session_guid
        sessions_table_lock_client.release(session_id)
    except Exception as e:
        logger.error(f'Failed to release session lock from DynamoDB: {str(e)}')
        return False

    return True


def remove_instance_from_dynamo_table(instance_id):
    logger.trace(instance_id, caller_name='remove_instance_from_dynamo_table')
    logger.info(f'Removing {instance_id} from DynamoDB')
    dynamodb_resource = boto3.resource('dynamodb')
    instances_table = dynamodb_resource.Table("Instances")
    try:
        instances_table.delete_item(
            Key={
                'InstanceId': instance_id
            }
        )
    except Exception as e:
        logger.error(f'Exception occurred on deleting {instance_id} on dynamodb:\n{str(e)}')
        return False

    logger.info(f'Item {instance_id} successfully deleted from DB')
    return True


def get_session_from_dynamo(sessions_table_lock_client=False):
    logger.info("Getting available Session from DynamoDB")
    if not sessions_table_lock_client:
        sessions_table_lock_client = LockerClient('Sessions')

    timeout = 20000  # Setting the timeout to 20 seconds on a row lock
    random_session_number = str(random.randint(1, 100))  # A number between 1 and 100

    try:
        for i in range(0, 20):

            lock_response = sessions_table_lock_client.acquire(random_session_number, timeout)
            if lock_response:  # no lock on connection number, return it
                logger.info("Successfully retrieved session from DynamoDB")
                return random_session_number, sessions_table_lock_client.guid
            else:  # connection number is locked, retry in 5 seconds
                time.sleep(5)
                continue
        #  if reached here, 20 retries with 5 seconds between retry - ended
        logger.info("Connection limit has been reached")
        return False, ""
    except Exception as e:
        print(f"Failed to retrieve session from DynamoDB: {str(e)}")
        raise Exception(f"Exception on get_session_from_dynamo:{str(e)}")


def update_instances_table_status(instance_id, status, error="None"):
    logger.trace(instance_id, status, error, caller_name='update_instances_table_status')
    logger.info(f'Updating DynamoDB with {instance_id} onboarding status. \nStatus: {status}')
    try:
        dynamodb_resource = boto3.resource('dynamodb')
        instances_table = dynamodb_resource.Table("Instances")
        instances_table.update_item(
            Key={
                'InstanceId': instance_id
            },
            AttributeUpdates={
                'Status': {
                    "Value": status,
                    "Action": "PUT"
                },
                'Error': {
                    "Value": error,
                    "Action": "PUT"
                }
            }
        )
    except Exception as e:
        logger.error(f'Exception occurred on updating session on DynamoDB {e}')
        return False
    logger.info("Instance data updated successfully")
    return True


# Search if Key pair exist, if not - create it, return the pem key, False for error
def create_new_key_pair(key_pair_name, ec2_client):
    logger.trace(key_pair_name, caller_name='create_new_key_pair_on_aws')

    # throws exception if key not found, if exception is InvalidKeyPair.Duplicate return True
    try:
        logger.info('Creating key pair')
        key_pair_response = ec2_client.create_key_pair(
            KeyName=key_pair_name,
            DryRun=False
        )
    except Exception as e:
        if e.response["Error"]["Code"] == "InvalidKeyPair.Duplicate":
            logger.error(f"Key Pair {key_pair_name} already exists")
            return True
        logger.error(f'Creating new key pair failed. error code:\n {e.response["Error"]["Code"]}')
        return False

    return key_pair_response["KeyMaterial"]


class StoreParameters:
    unix_safe_name = ""
    windows_safe_name = ""
    vault_username = ""
    vault_password = ""
    pvwa_url = "https://{0}/PasswordVault"
    key_pair_safe_name = ""
    key_pair_name = ""
    key_pair_platform = "UnixSSHKeys"
    pvwa_verification_key = ""
    aob_mode = ""
    vault_user_source = ""
    conjur_verification_key = ""
    conjur_hostname = ""
    conjur_account = ""
    conjur_authn_service_id = ""
    conjur_authn_host_namespace = ""
    conjur_vault_username_id = ""
    conjur_vault_password_id = ""


    def __init__(self, unix_safe_name, windows_safe_name, username, password, ip, key_pair_safe, key_pair_name,
                 key_pair_platform, pvwa_verification_key, mode, debug, vault_user_source, conjur_verification_key='',
                 conjur_hostname='', conjur_account='', conjur_authn_service_id='', conjur_authn_host_namespace='',
                 conjur_vault_username_id='', conjur_vault_password_id=''):
        self.unix_safe_name = unix_safe_name
        self.windows_safe_name = windows_safe_name
        self.vault_username = username
        self.vault_password = password
        self.pvwa_url = f"https://{ip}/PasswordVault"
        self.key_pair_safe_name = key_pair_safe
        self.key_pair_name = key_pair_name
        self.key_pair_platform = key_pair_platform
        self.pvwa_verification_key = pvwa_verification_key
        self.aob_mode = mode
        self.debug_level = debug
        self.vault_user_source = vault_user_source
        self.conjur_verification_key = conjur_verification_key
        self.conjur_hostname = conjur_hostname
        self.conjur_account = conjur_account
        self.conjur_authn_service_id = conjur_authn_service_id
        self.conjur_authn_host_namespace = conjur_authn_host_namespace
        self.conjur_vault_username_id = conjur_vault_username_id
        self.conjur_vault_password_id = conjur_vault_password_id
