import json
import boto3
import botocore.exceptions
import urllib3
from pvwa_integration import PvwaIntegration
from conjur_integration import ConjurIntegration
import aws_services
import instance_processing
import pvwa_api_calls
from log_mechanism import LogMechanism


DEBUG_LEVEL_DEBUG = 'debug' # Outputs all information
logger = LogMechanism()
pvwa_integration_class = PvwaIntegration()
conjur_integration_class = ConjurIntegration()

def lambda_handler(event, context):
    logger.trace(context, caller_name='lambda_handler')
    logger.info('Parsing event')

    try:
        event_account_id = event["account"]
    except Exception as e:
        logger.error(f"Error on retrieving Event Account Id from Event Message. Error: {e}")
        return

    try:
        event_region = event["region"]
    except Exception as e:
        logger.error(f"Error on retrieving Event Region from Event Message. Error: {e}")
        return

    try:
        event_source = event["source"]
    except Exception as e:
        logger.error(f"Error on retrieving Event Source from Event Message. Error: {e}")
        return

    solution_account_id = context.invoked_function_arn.split(':')[4]

    if event_source == "aws.ec2":
        try:
            instance_id = event["detail"]["instance-id"]
        except Exception as e:
            logger.error(f"Error on retrieving Instance Id from Event Message. Error: {e}")
            return

        try:
            action_type = event["detail"]["state"]
        except Exception as e:
            logger.error(f"Error on retrieving Action Type from Event Message. Error: {e}")
            return

        log_name = context.log_stream_name if context.log_stream_name else "None"

        elasticity_function(instance_id, action_type, event_account_id, event_region, solution_account_id, log_name)

    if event_source == "cyberark.aob":
        try:
            method = event["detail"]["method"]
        except Exception as e:
            logger.error(f"Error on retrieving method name from Event Message. Error: {e}")
            return

        try:
            action = event["detail"]["action"]
        except Exception as e:
            logger.error(f"Error on retrieving action from Event Message. Error: {e}")
            return

        try:
            source_region = event["detail"]["source_region"]
        except Exception as e:
            logger.error(f"Error on retrieving source region from Event Message. Error: {e}")
            return

        if method == "keypair_lifecycle" and action == "create":
            keypair_create_function(event_account_id, source_region, solution_account_id)


def elasticity_function(instance_id, action_type, event_account_id, event_region, solution_account_id, log_name):
    logger.info(f"Beginning EC2 instance processing sequence for {instance_id}/{event_account_id}/{event_region}")
    try:
        ec2_object = aws_services.get_account_details(solution_account_id, event_account_id, event_region)
        instance_details = aws_services.get_ec2_details(instance_id, ec2_object, event_account_id)
        instance_data = aws_services.get_instance_data_from_dynamo_table(instance_id)
        if action_type == 'terminated':
            if not instance_data:
                logger.info(f"Item {instance_id} does not exist on DB")
                return None
            instance_status = instance_data["Status"]["S"]
            if instance_status == OnBoardStatus.on_boarded_failed:
                logger.error(f"Item {instance_id} is in status OnBoard failed, removing from DynamoDB table")
                aws_services.remove_instance_from_dynamo_table(instance_id)
                return None
        elif action_type == 'running':
            if not instance_details["address"]:  # In case querying AWS return empty address
                logger.error("Retrieving Instance Address from AWS failed.")
                return None
            if instance_data:
                instance_status = instance_data["Status"]["S"]
                if instance_status == OnBoardStatus.on_boarded:
                    logger.info(f"Item {instance_id} already exists on DB, no need to add it to Vault")
                    return None
                elif instance_status == OnBoardStatus.on_boarded_failed:
                    logger.error(f"Item {instance_id} exists with status 'OnBoard failed', adding to Vault")
                else:
                    logger.info(f"Item {instance_id} does not exist on DB, adding to Vault")
        else:
            logger.info('Unknown instance state')
            return

        store_parameters_class = get_parameters_and_pvwa_auth_info(solution_account_id)

        if store_parameters_class is False:
            return

        session_token = pvwa_integration_class.logon_pvwa(store_parameters_class.vault_username,
                                                          store_parameters_class.vault_password,
                                                          store_parameters_class.pvwa_url)
        if not session_token:
            return
        disconnect = False
        if action_type == 'terminated':
            logger.info(f'Detected termination of {instance_id}')
            instance_processing.delete_instance(instance_id, event_account_id, session_token, store_parameters_class, instance_data,
                                                instance_details)
        elif action_type == 'running':
            # get key pair
            logger.info('Retrieving account id where the key-pair is stored')
            # Retrieving the account id of the account where the instance keyPair is stored
            # AWS.<AWS Account>.<Event Region name>.<key pair name>
            key_pair_value_on_safe = f'AWS.{instance_details["aws_account_id"]}.{event_region}.{instance_details["key_name"]}'
            key_pair_account_id = pvwa_api_calls.check_if_kp_exists(session_token, key_pair_value_on_safe,
                                                                    store_parameters_class.key_pair_safe_name,
                                                                    instance_id,
                                                                    store_parameters_class.pvwa_url)
            if not key_pair_account_id:
                logger.error(f"Key Pair {key_pair_value_on_safe} does not exist in Safe " \
                             f"{store_parameters_class.key_pair_safe_name}")
                return
            instance_account_password = pvwa_api_calls.get_account_value(session_token, key_pair_account_id, instance_id,
                                                                         store_parameters_class.pvwa_url)
            if instance_account_password is False:
                return
            pvwa_integration_class.logoff_pvwa(store_parameters_class.pvwa_url, session_token)
            disconnect = True
            instance_processing.create_instance(instance_id, instance_details, store_parameters_class, log_name,
                                                solution_account_id, event_region, event_account_id, instance_account_password)
        else:
            logger.error('Unknown instance state')
            return

        if not disconnect:
            pvwa_integration_class.logoff_pvwa(store_parameters_class.pvwa_url, session_token)

    except Exception as e:
        logger.error(f"Unknown error occurred: {e}")
        if action_type == 'terminated':
            # put_instance_to_dynamo_table(instance_id, instance_details["address"]\
            # , OnBoardStatus.delete_failed, str(e), log_name)
            aws_services.update_instances_table_status(instance_id, OnBoardStatus.delete_failed, str(e))
        elif action_type == 'running':
            aws_services.put_instance_to_dynamo_table(instance_id, instance_details["address"], OnBoardStatus.on_boarded_failed,
                                                      str(e), log_name)
# TODO: Retry mechanism?
        return


def keypair_create_function(event_account_id, event_region, solution_account_id):
    logger.info(f"Beginning EC2 Key Pair lifecycle-create sequence for {event_account_id}/{event_region}")
    store_parameters_class = get_parameters_and_pvwa_auth_info(solution_account_id)

    if store_parameters_class is False:
        return

    if not store_parameters_class.key_pair_name:
        logger.info("AOB_KeyPair_Name parameter is empty, the solution will not create a new Key Pair")
        return

    if solution_account_id == event_account_id:
        try:
            ec2_client = boto3.client('ec2', region_name=event_region)
            lambda_client = boto3.client('lambda', region_name=event_region)
        except Exception as e:
            logger.error(f'Error on creating boto3 client: {str(e)}')
            return
    else:
        try:
            logger.info('Assuming role for key-pair creation')
            sts_connection = boto3.client('sts')
            sts_token = sts_connection.assume_role(RoleArn=f"arn:aws:iam::{event_account_id}"
                                                   ":role/CyberArk-AOB-AssumeRoleForElasticityLambda-"
                                                   f"{event_region}",
                                                   RoleSessionName="cross_acct_lambda")

            # Creating ec2 client using STS token detail
            ec2_client = boto3.client('ec2', region_name=event_region,
                                      aws_access_key_id=sts_token['Credentials']['AccessKeyId'],
                                      aws_secret_access_key=sts_token['Credentials']['SecretAccessKey'],
                                      aws_session_token=sts_token['Credentials']['SessionToken'])

            # Creating lambda client using STS token detail
            lambda_client = boto3.client('lambda', region_name=event_region,
                                         aws_access_key_id=sts_token['Credentials']['AccessKeyId'],
                                         aws_secret_access_key=sts_token['Credentials']['SecretAccessKey'],
                                         aws_session_token=sts_token['Credentials']['SessionToken'])
        except Exception as e:
            logger.error(f'Error retrieving STS token for account {event_account_id} : {str(e)}')
            return

    # Creating EC2 Key Pair
    aws_private_key = aws_services.create_new_key_pair(store_parameters_class.key_pair_name, ec2_client)

    if aws_private_key is False:
        # Unexpected error creating EC2 Key Pair, can't provision in the Vault
        return

    if aws_private_key is True:
        # EC2 Key Pair already exists in AWS, can't provision in the Vault
        return

    # Adding key pair name to target account lifecycle lambda
    try:
        response = lambda_client.update_function_configuration(
                       FunctionName='CyberArk-AOB-KeyPairLifecycleLambda',
                       Environment={
                           'Variables': {
                                'AOB_EC2_KEYPAIR_NAME': store_parameters_class.key_pair_name
                           }
                       }
                    )
        if response:
            logger.info(f'EC2 key pair name successfully added to the lifecycle lambda in account {event_account_id}')
        else:
            logger.error(f'EC2 key pair has not been updated for lifecycle lambda for account {event_account_id}')
    except Exception as e:
        logger.error(f'Error updating EC2 key pair lifecycle lambda for account {event_account_id} : {str(e)}')

    # Authenticating to PVWA
    session_token = pvwa_integration_class.logon_pvwa(store_parameters_class.vault_username,
                                                      store_parameters_class.vault_password,
                                                      store_parameters_class.pvwa_url)
    if not session_token:
        return

    # Adding EC2 Key Pair to the Vault
    key_pair_created = pvwa_api_calls.create_key_pair_in_vault(session_token, store_parameters_class.key_pair_name,
                                                               aws_private_key, store_parameters_class.pvwa_url,
                                                               store_parameters_class.key_pair_safe_name,
                                                               store_parameters_class.key_pair_platform,
                                                               event_account_id, event_region)

    if not key_pair_created:
        logger.error(f"Failed to create Key Pair {store_parameters_class.key_pair_name} in safe "
                     f"{store_parameters_class.key_pair_safe_name}.  See detailed error in logs")

    logger.info(f"Successfully added Key Pair {store_parameters_class.key_pair_name} to safe "
                f"{store_parameters_class.key_pair_safe_name}.")

    pvwa_integration_class.logoff_pvwa(store_parameters_class.pvwa_url, session_token)


def get_parameters_and_pvwa_auth_info(solution_account_id):
    store_parameters_class = aws_services.get_params_from_param_store()
    if not store_parameters_class:
        logger.error('Unable to retrieve parameters from the parameter store')
        return False
    if store_parameters_class.aob_mode == 'Production':
        # Save PVWA Verification Key in /tmp folder
        logger.info('Saving PVWA verification key')
        crt = open("/tmp/pvwa_server.crt", "w+")
        crt.write(store_parameters_class.pvwa_verification_key)
        crt.close()
        if store_parameters_class.vault_user_source == 'CyberArk Conjur':
            # If using Conjur, save Conjur Verification Key in /tmp folder
            logger.info('Saving Conjur verification key')
            crt = open("/tmp/conjur_server.crt", "w+")
            crt.write(store_parameters_class.conjur_verification_key)
            crt.close()

    # Check for vault user source and set variables for logon
    if store_parameters_class.vault_user_source == 'CyberArk Conjur':
        # Using Conjur
        if store_parameters_class.conjur_authn_host_namespace == 'root':
            conjur_username = f'host/{solution_account_id}/CyberArk-AOB-ElasticityLambdaRole'
        else:
            conjur_username = f'host/{store_parameters_class.conjur_authn_host_namespace}/' \
                              f'{solution_account_id}/CyberArk-AOB-ElasticityLambdaRole'
        try:
            conjur_token = conjur_integration_class.logon_conjur(store_parameters_class.conjur_hostname,
                                                                 store_parameters_class.conjur_account,
                                                                 store_parameters_class.conjur_authn_service_id,
                                                                 conjur_username)
            vault_un = conjur_integration_class.get(conjur_token, store_parameters_class.conjur_vault_username_id)
            if not vault_un:
                logger.error("The Conjur variable for vault username is empty")
                return False
            store_parameters_class.vault_username = vault_un

            vault_pw = conjur_integration_class.get(conjur_token, store_parameters_class.conjur_vault_password_id)
            if not vault_pw:
                logger.error("The Conjur Variable for vault user password is empty")
                return False
            store_parameters_class.vault_password = vault_pw
        except Exception as e:
            logger.error(f'Unable to retrieve Vault User details from Conjur:\n{str(e)}')
            return False

    return store_parameters_class

class OnBoardStatus:
    on_boarded = "on boarded"
    on_boarded_failed = "on board failed"
    delete_failed = "delete failed"
