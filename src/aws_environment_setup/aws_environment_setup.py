import uuid
import time
import requests
import urllib3
import boto3
import botocore
import cfnresponse
import aws_services
from log_mechanism import LogMechanism
from pvwa_integration import PvwaIntegration
from conjur_integration import ConjurIntegration
from dynamo_lock import LockerClient

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEBUG_LEVEL_DEBUG = 'debug' # Outputs all information
DEFAULT_HEADER = {"content-type": "application/json"}
IS_SAFE_HANDLER = True
logger = LogMechanism()


def lambda_handler(event, context):
    logger.trace(event, context, caller_name='lambda_handler')
    try:
        physical_resource_id = str(uuid.uuid4())
        if 'PhysicalResourceId' in event:
            physical_resource_id = event['PhysicalResourceId']

        if event['RequestType'] == 'Delete':
            logger.info('Delete request received')
            # Deleting parameters from parameter store that were created by this Lambda
            params_to_del = ["AOB_Vault_Pass", "AOB_mode", "AOB_PVWA_Verification_Key",
                             "AOB_KeyPair_Name", "AOB_KeyPair_Platform", "AOB_Conjur_Verification_Key"]
            logger.info('Begin delete of extra AOB parameters')
            delete_params = delete_params_from_param_store(params_to_del)
            if not delete_params:
                return cfnresponse.send(event, context, cfnresponse.FAILED,
                                        {'Message': "Failed to delete one or more parameters from parameter store, "
                                            "see detailed error in logs"},
                                        physical_resource_id)
            # Deleting DynamoDB Sessions Table
            logger.info('Begin delete of DynamoDB Sessions Table')
            is_sessions_table_deleted = delete_sessions_table()
            if not is_sessions_table_deleted:
                return cfnresponse.send(event, context, cfnresponse.FAILED,
                                        {'Message': "Failed to delete the Sessions table from DynamoDB"},
                                        physical_resource_id)

            # Attempting cleanup of public key in AWS, retaining private key in the CyberArk Vault
            request_key_pair_name = event['ResourceProperties']['KeyPairName']
            if request_key_pair_name != '':
                logger.info('Beginning EC2 key pair public key cleanup')
                try:
                    ec2_client = boto3.client('ec2')
                    ec2_client.delete_key_pair(KeyName=request_key_pair_name)
                    logger.info(f'Key Pair {request_key_pair_name} successfully deleted')
                except Exception as e:
                    if e.response['Error']['Code'] == 'InvalidKeyPair.NotFound':
                        logger.info(f'Key Pair {request_key_pair_name} not found, nothing to remove')
                    else:
                        cfnresponse.send(event, context, cfnresponse.FAILED, {'Message': str(e)})

            return cfnresponse.send(event, context, cfnresponse.SUCCESS, None, physical_resource_id)

        if event['RequestType'] == 'Create':
            logger.info('Create request received')
            request_unix_cpm_name = event['ResourceProperties']['CPMUnix']
            request_windows_cpm_name = event['ResourceProperties']['CPMWindows']
            request_username = event['ResourceProperties']['Username']
            request_unix_safe_name = event['ResourceProperties']['UnixSafeName']
            request_windows_safe_name = event['ResourceProperties']['WindowsSafeName']
            request_pvwa_ip = event['ResourceProperties']['PVWAIP']
            request_password = event['ResourceProperties']['Password']
            request_key_pair_safe = event['ResourceProperties']['KeyPairSafe']
            request_key_pair_name = event['ResourceProperties']['KeyPairName']
            request_key_pair_platform = event['ResourceProperties']['KeyPairPlatform']
            request_aws_region_name = event['ResourceProperties']['AWSRegionName']
            request_aws_account_id = event['ResourceProperties']['AWSAccountId']
            request_s3_bucket_name = event['ResourceProperties']['S3BucketName']
            request_pvwa_verification_key_name = event['ResourceProperties']['PVWAVerificationKeyFileName']
            aob_mode = event['ResourceProperties']['Environment']
            request_vault_user_source = event['ResourceProperties']['VaultUserSource']
            request_conjur_hostname = event['ResourceProperties']['ConjurHostname']
            request_conjur_verification_key_name = event['ResourceProperties']['ConjurVerificationKeyFileName']
            request_conjur_account = event['ResourceProperties']['ConjurAccount']
            request_conjur_authn_service_id = event['ResourceProperties']['ConjurAuthnServiceID']
            request_conjur_authn_host_namespace = event['ResourceProperties']['ConjurAuthnHostNamespace']
            request_conjur_vault_username_id = event['ResourceProperties']['ConjurVaultUsernameID']
            request_conjur_vault_password_id = event['ResourceProperties']['ConjurVaultPasswordID']

            if request_vault_user_source == "SSM Parameter Store":
                if request_username != '' and request_password != '':
                    # Not using Conjur, we'll add the Vault Password to the parameter store
                    logger.info('Using SSM Parameter Store for Vault User Details')
                    logger.info('Adding AOB_Vault_Pass to parameter store', DEBUG_LEVEL_DEBUG)
                    is_password_saved = add_param_to_parameter_store(request_password, "AOB_Vault_Pass", "Vault Password")
                    if not is_password_saved:  # if password failed to be saved
                        return cfnresponse.send(event, context, cfnresponse.FAILED,
                                                {'Message': "Failed to create Vault user's password in Parameter Store"},
                                                physical_resource_id)
                    vault_username = request_username
                    vault_password = request_password
                else:
                    return cfnresponse.send(event, context, cfnresponse.FAILED,
                                            {'Message': "Vault Username or Vault Password parameters have not been defined"},
                                            physical_resource_id)
            else:
                if (request_conjur_account != '' and request_conjur_hostname != '' and request_conjur_authn_service_id != ''
                        and request_conjur_vault_username_id != '' and request_conjur_vault_password_id != ''):
                    # Using Conjur
                    logger.info('Using Conjur for Vault User Details')
                    if aob_mode == 'Production':
                        if request_s3_bucket_name == '' and request_conjur_verification_key_name != '':
                            raise Exception('S3 Bucket cannot be empty if Conjur Verification key is provided')
                        elif request_s3_bucket_name != '' and request_conjur_verification_key_name == '':
                            raise Exception('Conjur Verification key cannot be empty if S3 Bucket is provided')
                        logger.info('Adding Conjur CA cert to parameter store', DEBUG_LEVEL_DEBUG)
                        is_conjur_cert_saved = save_verification_key_to_param_store(request_s3_bucket_name,
                                                                                    request_conjur_verification_key_name,
                                                                                    "conjur",
                                                                                    "AOB_Conjur_Verification_Key",
                                                                                    "Conjur Verification Key")
                        if not is_conjur_cert_saved:  # if Conjur verification key failed to be saved
                            return cfnresponse.send(event, context, cfnresponse.FAILED,
                                                    {'Message': "Failed to create Conjur Verification Key in Parameter Store"},
                                                    physical_resource_id)

                    account_id = context.invoked_function_arn.split(':')[4]
                    if request_conjur_authn_host_namespace == 'root':
                        conjur_username = f'host/{account_id}/CyberArk-AOB-SafeHandlerLambdaRole'
                    else:
                        conjur_username = f'host/{request_conjur_authn_host_namespace}/{account_id}/CyberArk-AOB-SafeHandlerLambdaRole'
                    conjur_integration_class = ConjurIntegration(IS_SAFE_HANDLER, aob_mode)
                    conjur_token = conjur_integration_class.logon_conjur(request_conjur_hostname, request_conjur_account,
                                                                         request_conjur_authn_service_id, conjur_username)
                    vault_username = conjur_integration_class.get(conjur_token, request_conjur_vault_username_id)
                    vault_password = conjur_integration_class.get(conjur_token, request_conjur_vault_password_id)
                else:
                    return cfnresponse.send(event, context, cfnresponse.FAILED,
                                            {'Message': "One or more Conjur parameters have not been defined"},
                                            physical_resource_id)


            if request_s3_bucket_name == '' and request_pvwa_verification_key_name != '':
                raise Exception('S3 Bucket cannot be empty if Verification Key is provided')
            elif request_s3_bucket_name != '' and request_pvwa_verification_key_name == '':
                raise Exception('Verification Key cannot be empty if S3 Bucket is provided')
            else:
                logger.info('Adding AOB_mode to parameter store', DEBUG_LEVEL_DEBUG)
                is_aob_mode_saved = add_param_to_parameter_store(aob_mode, 'AOB_mode',
                                                                 'Dictates if the solution will work in POC (no SSL) or ' \
                                                                 'Production (with SSL) mode')
                if not is_aob_mode_saved:  # if AOB_mode failed to be saved
                    return cfnresponse.send(event, context, cfnresponse.FAILED,
                                            {'Message': "Failed to create AOB_mode parameter in Parameter Store"},
                                            physical_resource_id)
                if aob_mode == 'Production':
                    logger.info('Adding verification key to Parameter Store', DEBUG_LEVEL_DEBUG)
                    is_verification_key_saved = save_verification_key_to_param_store(request_s3_bucket_name,
                                                                                     request_pvwa_verification_key_name,
                                                                                     "pvwa",
                                                                                     "AOB_PVWA_Verification_Key",
                                                                                     "PVWA Verification Key")
                    if not is_verification_key_saved:  # If PVWA Verification Key failed to be saved
                        return cfnresponse.send(event, context, cfnresponse.FAILED,
                                                {'Message': "Failed to create PVWA Verification Key in Parameter Store"},
                                                physical_resource_id)

            pvwa_integration_class = PvwaIntegration(IS_SAFE_HANDLER, aob_mode)
            pvwa_url = f"https://{request_pvwa_ip}/PasswordVault"
            pvwa_session_id = pvwa_integration_class.logon_pvwa(vault_username, vault_password, pvwa_url, "1")
            if not pvwa_session_id:
                return cfnresponse.send(event, context, cfnresponse.FAILED,
                                        {'Message': "Failed to connect to PVWA, see detailed error in logs"},
                                        physical_resource_id)

            is_safe_created = create_safe(pvwa_integration_class, request_unix_safe_name, request_unix_cpm_name, request_pvwa_ip,
                                          pvwa_session_id, 1)
            if not is_safe_created:
                return cfnresponse.send(event, context, cfnresponse.FAILED,
                                        {'Message': f"Failed to create the Safe {request_unix_safe_name}, "
                                                    "see detailed error in logs"},
                                        physical_resource_id)

            is_safe_created = create_safe(pvwa_integration_class, request_windows_safe_name, request_windows_cpm_name,
                                          request_pvwa_ip, pvwa_session_id, 1)

            if not is_safe_created:
                return cfnresponse.send(event, context, cfnresponse.FAILED,
                                        {'Message': f"Failed to create the Safe {request_windows_safe_name}, "
                                                    "see detailed error in logs"},
                                        physical_resource_id)

            if not create_session_table():
                return cfnresponse.send(event, context, cfnresponse.FAILED,
                                        {'Message': "Failed to create 'Sessions' table in DynamoDB, "
                                                    "see detailed error in logs"},
                                        physical_resource_id)

            #  Creating KeyPair Safe
            is_safe_created = create_safe(pvwa_integration_class, request_key_pair_safe, "", request_pvwa_ip, pvwa_session_id)
            if not is_safe_created:
                return cfnresponse.send(event, context, cfnresponse.FAILED,
                                        {'Message': f"Failed to create the Key Pairs safe: {request_key_pair_safe}, "
                                            "see detailed error in logs"},
                                        physical_resource_id)

            #  key pair is optional parameter
            if not request_key_pair_name:
                logger.info("Key Pair name parameter is empty, the solution will not create a new Key Pair")
                return cfnresponse.send(event, context, cfnresponse.SUCCESS, None, physical_resource_id)
            logger.info('Adding AOB_KeyPair_Name to parameter store', DEBUG_LEVEL_DEBUG)
            is_keypair_parm_saved = add_param_to_parameter_store(request_key_pair_name, 'AOB_KeyPair_Name',
                                                                 'Name of the EC2 KeyPair that will be created by the'
                                                                 'solution in all targeted accounts and regions')
            if not is_keypair_parm_saved:  # if keypair failed to be saved
                return cfnresponse.send(event, context, cfnresponse.FAILED,
                                        {'Message': "Failed to create KeyPair Name in Parameter Store"},
                                        physical_resource_id)

            if not request_key_pair_platform:
                logger.info("Key Pair platform parameter is empty, assuming default of UnixSSHKeys")
            else:
                logger.info('Adding AOB_KeyPair_Platform to parameter store', DEBUG_LEVEL_DEBUG)
                is_keypair_plat_parm_saved = add_param_to_parameter_store(request_key_pair_platform, 'AOB_KeyPair_Platform',
                                                                          'Name of the SSH Key Platform that will be used'
                                                                          'by the solution for on-boarding EC2 key pairs')
                if not is_keypair_plat_parm_saved:  # if keypair platform failed to be saved
                    return cfnresponse.send(event, context, cfnresponse.FAILED,
                                            {'Message': "Failed to create KeyPair Name in Parameter Store"},
                                            physical_resource_id)

            ec2_client = boto3.client('ec2')
            aws_key_pair = aws_services.create_new_key_pair(request_key_pair_name, ec2_client)

            if aws_key_pair is False:
                # Account already exist, no need to create it, can't insert it to the vault
                return cfnresponse.send(event, context, cfnresponse.FAILED,
                                        {'Message': f"Failed to create Key Pair {request_key_pair_name} in AWS"},
                                        physical_resource_id)
            if aws_key_pair is True:
                return cfnresponse.send(event, context, cfnresponse.FAILED,
                                        {'Message': f"Key Pair {request_key_pair_name} already exists in AWS"},
                                        physical_resource_id)
            # Create the key pair account on KeyPairs vault
            is_aws_account_created = create_key_pair_in_vault(pvwa_integration_class, pvwa_session_id,
                                                              request_key_pair_name, aws_key_pair,
                                                              pvwa_url, request_key_pair_safe,
                                                              request_key_pair_platform, request_aws_account_id,
                                                              request_aws_region_name)
            if not is_aws_account_created:
                return cfnresponse.send(event, context, cfnresponse.FAILED,
                                        {'Message': f"Failed to create Key Pair {request_key_pair_name} in safe "
                                            f"{request_key_pair_safe}. see detailed error in logs"},
                                        physical_resource_id)

            return cfnresponse.send(event, context, cfnresponse.SUCCESS, None, physical_resource_id)

    except Exception as e:
        logger.error(f"Exception occurred:{str(e)}:")
        return cfnresponse.send(event, context, cfnresponse.FAILED, {'Message': f"Exception occurred: {str(e)}"})

    finally:
        if 'pvwa_session_id' in locals():  # pvwa_session_id has been declared
            if pvwa_session_id:  # Logging off the session in case of successful logon
                pvwa_integration_class.logoff_pvwa(pvwa_url, pvwa_session_id)


def create_key_pair_in_vault(pvwa_integration_class, session, aws_key_name, private_key_value, pvwa_url, safe_name,
                             platform_name, aws_account_id, aws_region_name):
    logger.trace(session, aws_key_name, pvwa_url, safe_name, aws_account_id,
                 aws_region_name, caller_name='create_key_pair_in_vault')
    header = DEFAULT_HEADER
    header.update({"Authorization": session})

    trimmed_pem_key = str(private_key_value).replace("\n", "\\n")
    trimmed_pem_key = trimmed_pem_key.replace("\r", "\\r")

    # AWS.<AWS Account>.<Region name>.<key pair name>
    unique_user_name = f"AWS.{aws_account_id}.{aws_region_name}.{aws_key_name}"
    logger.info(f"Creating account with username:{unique_user_name}")

    url = f"{pvwa_url}/WebServices/PIMServices.svc/Account"
    data = f"""
            {{
              "account" : {{
                  "safe":"{safe_name}",
                  "platformID":"{platform_name}",
                  "address":"AWS",
                  "password":"{trimmed_pem_key}",
                  "username":"{unique_user_name}",
                  "disableAutoMgmt":"true",
                  "disableAutoMgmtReason":"Unmanaged account"
              }}
            }}
        """
    rest_response = pvwa_integration_class.call_rest_api_post(url, data, header)

    if rest_response.status_code == requests.codes.created:
        logger.info(f"Key Pair created successfully in safe '{safe_name}'")
        return True
    elif rest_response.status_code == requests.codes.conflict:
        logger.info(f"Key Pair created already exists in safe {safe_name}")
        return True
    logger.error(f"Failed to create Key Pair in safe {safe_name}, status code:{rest_response.status_code}")
    return False

# Creating a safe, if a failure occur, retry 3 time, wait 10 sec. between retries
def create_safe(pvwa_integration_class, safe_name, cpm_name, pvwa_ip, session_id, number_of_days_retention=7):
    logger.trace(pvwa_integration_class, safe_name, cpm_name, pvwa_ip, session_id, number_of_days_retention,
                 caller_name='create_safe')
    header = DEFAULT_HEADER
    header.update({"Authorization": session_id})
    create_safe_url = f"https://{pvwa_ip}/PasswordVault/WebServices/PIMServices.svc/Safes"
    # Create new safe, default number of days retention is 7, unless specified otherwise
    data = f"""
            {{
            "safe":{{
                "SafeName":"{safe_name}",
                "Description":"",
                "OLACEnabled":false,
                "ManagingCPM":"{cpm_name}",
                "NumberOfDaysRetention":"{number_of_days_retention}"
              }}
            }}
            """

    for i in range(0, 3):
        create_safe_rest_response = pvwa_integration_class.call_rest_api_post(create_safe_url, data, header)

        if create_safe_rest_response.status_code == requests.codes.conflict:
            logger.info(f"The Safe {safe_name} already exists")
            return True
        elif create_safe_rest_response.status_code == requests.codes.bad_request:
            logger.error(f"Failed to create Safe {safe_name}, error 400: bad request")
            return False
        elif create_safe_rest_response.status_code == requests.codes.created:  # safe created
            logger.info(f"Safe {safe_name} was successfully created")
            return True
        else:  # Error creating safe, retry for 3 times, with 10 seconds between retries
            logger.error(f"Error creating Safe, status code:{create_safe_rest_response.status_code}, will retry in 10 seconds")
            if i == 3:
                logger.error(f"Failed to create safe after several retries, status code:{create_safe_rest_response.status_code}")
                return False
        time.sleep(10)


def create_session_table():
    logger.trace(caller_name='create_session_table')
    try:
        logger.info('Locking Dynamo Table')
        sessions_table_lock = LockerClient('Sessions')
        sessions_table_lock.create_lock_table()
    except Exception as e:
        logger.error(f"Failed to create 'Sessions' table in DynamoDB. Exception: {str(e)}")
        return None

    logger.info("Table 'Sessions' created successfully")
    return True


def save_verification_key_to_param_store(s3_bucket_name, verification_key_name, verification_key_type, parameter_name, parameter_description):
    logger.trace(s3_bucket_name, verification_key_name, caller_name='save_verification_key_to_param_store')
    try:
        logger.info(f'Downloading {verification_key_name} from S3 bucket - {s3_bucket_name}')
        s3_resource = boto3.resource('s3')
        s3_resource.Bucket(s3_bucket_name).download_file(verification_key_name, f'/tmp/{verification_key_type}_server.crt')
        add_param_to_parameter_store(open(f'/tmp/{verification_key_type}_server.crt').read(), parameter_name, parameter_description)
    except Exception as e:
        logger.error(f"An error occurred while downloading {verification_key_name} from S3 Bucket - {s3_bucket_name}. Exception: {e}")
        return False
    return True


def add_param_to_parameter_store(value, parameter_name, parameter_description):
    logger.trace(parameter_name, parameter_description, caller_name='add_param_to_parameter_store')
    try:
        logger.info(f'Adding parameter {parameter_name} to parameter store')
        ssm_client = boto3.client('ssm')
        ssm_client.put_parameter(
            Name=parameter_name,
            Description=parameter_description,
            Value=value,
            Type="SecureString"
        )
    except Exception as e:
        logger.error(f"Unable to create parameter {parameter_name} in Parameter Store. Exception: {e}")
        return False
    return True


def delete_params_from_param_store(params_to_del):
    logger.trace(params_to_del, caller_name='delete_params_from_param_store')
    logger.info('Deleting parameters from parameter store')
    state = True
    ssm_client = boto3.client('ssm')
    for param in params_to_del:
        try:
            ssm_client.delete_parameter(Name=f'{param}')
            logger.info(f"Parameter '{param}' deleted successfully from Parameter Store")
        except Exception as e:
            if e.response["Error"]["Code"] == "ParameterNotFound":
                logger.info(f"Parameter '{param}' was not found, skipping")
            else:
                logger.error(f'Failed to delete parameter "{param}" from Parameter Store. Error code: {e.response["Error"]["Code"]}')
                state = False
    return state


def delete_sessions_table():
    logger.trace(caller_name='delete_sessions_table')
    try:
        logger.info('Deleting Dynamo session table')
        dynamodb = boto3.resource('dynamodb')
        sessions_table = dynamodb.Table('Sessions')
        sessions_table.delete()
        return True
    except Exception as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            logger.info("Sessions table does not exist")
            return True
        return False
