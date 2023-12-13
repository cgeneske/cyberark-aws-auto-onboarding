import requests
from pvwa_integration import PvwaIntegration
from log_mechanism import LogMechanism

DEBUG_LEVEL_DEBUG = 'debug' # Outputs all information
DEFAULT_HEADER = {"content-type": "application/json"}
pvwa_integration_class = PvwaIntegration()
logger = LogMechanism()


def create_account_on_vault(session, account_name, account_password, store_parameters_class, platform_id, address,
                            instance_id, username, safe_name):
    logger.trace(session, account_name, store_parameters_class, platform_id, address,
                 instance_id, username, safe_name, caller_name='create_account_on_vault')
    logger.info(f'Creating account in vault for {instance_id}')
    secret_type = "key"
    if "Windows" in account_name:
        secret_type = "password"
    header = DEFAULT_HEADER
    header.update({"Authorization": session})
    url = f"{store_parameters_class.pvwa_url}/api/Accounts"
    data = f"""
    {{
        "name":"{account_name}",
        "username":"{username}",
        "address":"{address}",
        "safeName":"{safe_name}",
        "platformId":"{platform_id}",
        "secretType": "{secret_type}",
        "secret":"{account_password}",
        "secretManagement": {{
            "automaticManagementEnabled": "true"
        }}
    }}
    """
    rest_response = pvwa_integration_class.call_rest_api_post(url, data, header)
    if rest_response.status_code == requests.codes.created:
        logger.info(f"Account for {instance_id} was successfully created")
        return True, ""
    logger.error(f'Failed to create the account for {instance_id} from the vault. status code:{rest_response.status_code}')
    return False, f"Error Creating Account, Status Code:{rest_response.status_code}"


def create_key_pair_in_vault(session, aws_key_name, private_key_value, pvwa_url, safe_name,
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

    url = f"{pvwa_url}/api/Accounts"
    data = f"""
    {{
        "safeName":"{safe_name}",
        "platformID":"{platform_name}",
        "address":"AWS",
        "secretType": "key",
        "secret":"{trimmed_pem_key}",
        "username":"{unique_user_name}",
        "secretManagement": {{
            "automaticManagementEnabled": "false",
            "manualManagementReason": "Unmanaged account"
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


def rotate_credentials_immediately(session, pvwa_url, account_id, instance_id):
    logger.trace(session, pvwa_url, account_id, instance_id, caller_name='rotate_credentials_immediately')
    logger.info(f'Rotating {instance_id} credentials')
    header = DEFAULT_HEADER
    header.update({"Authorization": session})
    url = f"{pvwa_url}/api/Accounts/{account_id}/Change"
    data = ""
    rest_response = pvwa_integration_class.call_rest_api_post(url, data, header)
    if rest_response.status_code == requests.codes.ok:
        logger.info(f"Call for immediate key change for {instance_id} performed successfully")
        return True
    logger.error(f'Failed to call key change for {instance_id}. an error occurred')
    return False


def get_account_value(session, account, instance_id, rest_url):
    logger.trace(session, account, instance_id, rest_url, caller_name='get_account_value')
    logger.info(f'Getting {instance_id} account from vault')
    header = DEFAULT_HEADER
    header.update({"Authorization": session})
    pvwa_url = f"{rest_url}/api/Accounts/{account}/Password/Retrieve"
    rest_logon_data = """{ "reason":"AWS Auto On-Boarding Solution" }"""
    rest_response = pvwa_integration_class.call_rest_api_post(pvwa_url, rest_logon_data, header)
    if rest_response.status_code == requests.codes.ok:
        return rest_response.text
    elif rest_response.status_code == requests.codes.not_found:
        logger.info(f"Account {account} for instance {instance_id}, not found on vault")
        return False
    logger.error(f"Unexpected result from rest service - get account value, status code: {rest_response.status_code}")
    return False


def delete_account_from_vault(session, account_id, instance_id, pvwa_url):
    logger.trace(session, account_id, instance_id, pvwa_url, caller_name='delete_account_from_vault')
    logger.info(f'Deleting {instance_id} from vault')
    header = DEFAULT_HEADER
    header.update({"Authorization": session})
    # Continuing use of the Gen 1 API here as Gen 2 API does not yet support deletion of SSH Keys
    rest_url = f"{pvwa_url}/WebServices/PIMServices.svc/Accounts/{account_id}"
    rest_response = pvwa_integration_class.call_rest_api_delete(rest_url, header)

    if rest_response.status_code != requests.codes.ok:
        if rest_response.status_code == requests.codes.not_found:
            logger.error(f"Failed to delete the account for {instance_id} from the vault. The account does not exists")
            raise Exception(f"Failed to delete the account for {instance_id} from the vault. The account does not exists")
        logger.error(f"Failed to delete the account for {instance_id} from the vault. an error occurred")
        raise Exception(f"Unknown status code received {rest_response.status_code}")

    logger.info(f"The account for {instance_id} was successfully deleted")
    return True


def check_if_kp_exists(session, account_name, safe_name, instance_id, rest_url):
    logger.trace(session, account_name, safe_name, instance_id, rest_url, caller_name='check_if_kp_exists')
    logger.info('Checking if key pair is onboarded')
    header = DEFAULT_HEADER
    header.update({"Authorization": session})
    # 2 options of search - if safe name not empty, add it to query, if not - search without it

    if safe_name:  # has value
        pvwa_url = f"{rest_url}/api/accounts?search={account_name}&filter=safeName eq {safe_name}"
    else:  # has no value
        pvwa_url = f"{rest_url}/api/accounts?search={account_name}"
    try:
        rest_response = pvwa_integration_class.call_rest_api_get(pvwa_url, header)
        if not rest_response:
            raise Exception(f"Unknown Error when calling rest service - retrieve account - REST response: {rest_response}")
    except Exception as e:
        logger.error(f'An error occurred: {str(e)}')
        raise Exception(e)
    if rest_response.status_code == requests.codes.ok:
        # if response received, check account is not empty {"Count": 0,"accounts": []}
        if 'value' in rest_response.json() and rest_response.json()["value"]:
            parsed_json_response = rest_response.json()['value']
            return parsed_json_response[0]['id']
        return False
    logger.error(f"Status code {rest_response.status_code}, received from REST service")
    raise Exception(f"Status code {rest_response.status_code}, received from REST service")


def retrieve_account_id_from_account_name(session, account_name, safe_name, instance_id, rest_url):
    logger.trace(session, account_name, safe_name, instance_id, rest_url, caller_name='retrieve_account_id_from_account_name')
    logger.info('Retrieving account_id from account_name')
    header = DEFAULT_HEADER
    header.update({"Authorization": session})
    # 2 options of search - if safe name not empty, add it to query, if not - search without it

    if safe_name:  # has value
        pvwa_url = f"{rest_url}/api/accounts?search={account_name}&filter=safeName eq {safe_name}"
    else:  # has no value
        pvwa_url = f"{rest_url}/api/accounts?search={account_name}"
    try:
        rest_response = pvwa_integration_class.call_rest_api_get(pvwa_url, header)
        if not rest_response:
            raise Exception("Unknown Error when calling rest service - retrieve account_id")
    except Exception as e:
        logger.error(f'An error occurred:\n{str(e)}')
        raise Exception(e)
    if rest_response.status_code == requests.codes.ok:
        # if response received, check account is not empty {"Count": 0,"accounts": []}
        if 'value' in rest_response.json() and rest_response.json()["value"]:
            parsed_json_response = rest_response.json()['value']
            return filter_get_accounts_result(parsed_json_response, instance_id)
        logger.info(f'No match for account: {account_name}')
        return False
    logger.error(f"Status code {rest_response.status_code}, received from REST service")
    raise Exception(f"Status code {rest_response.status_code}, received from REST service")


def filter_get_accounts_result(parsed_json_response, instance_id):
    logger.trace(parsed_json_response, instance_id, caller_name='filter_get_accounts_result')
    for element in parsed_json_response:
        if instance_id in element['name']:
            return element['id']
    return False


def check_if_safe_exists(session, safe_name, pvwa_url):
    logger.trace(session, safe_name, pvwa_url, caller_name='check_if_safe_exists')
    logger.info(f"Checking if {safe_name} exists in the vault")
    header = DEFAULT_HEADER
    header.update({"Authorization": session})
    url = f"{pvwa_url}/api/Safes?search={safe_name}"
    try:
        rest_response = pvwa_integration_class.call_rest_api_get(url, header)
        if not rest_response:
            raise Exception("Unknown Error when calling rest service - check_if_safe_exists")
    except Exception as e:
        logger.error(f'An error occurred:\n{str(e)}')
        raise Exception(e)
    if rest_response.status_code == requests.codes.ok:
        if 'value' in rest_response.json() and rest_response.json()["value"]:
            parsed_json_response = rest_response.json()['value']
            for element in parsed_json_response:
                if safe_name in element['safeName']:
                    logger.info(f"Found matching safe - {safe_name}")
                    return True
        logger.info(f"No matching safe was found for - {safe_name}")
        return False
    logger.error(f"Status code {rest_response.status_code}, received from REST service")
    raise Exception(f"Status code {rest_response.status_code}, received from REST service")
