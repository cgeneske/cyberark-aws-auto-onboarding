import hashlib
import json
import urllib.parse
import requests
import aws_services
from log_mechanism import LogMechanism
import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

DEBUG_LEVEL_DEBUG = 'debug'  # Outputs all information


class ConjurIntegration:
    def __init__(self, is_safe_handler=False, safe_handler_environment=None):
        self.logger = LogMechanism()
        self.logger.trace(is_safe_handler, safe_handler_environment, caller_name='__init__')
        self.is_safe_handler = is_safe_handler
        self.safe_handler_environment = safe_handler_environment
        self.conjur_url = ''
        self.conjur_account = ''
        try:
            self.logger.info('Conjur Integration - Getting parameters from parameter store')
            if not is_safe_handler:
                parameters = aws_services.get_params_from_param_store()
                environment = parameters.aob_mode
            else:
                environment = self.safe_handler_environment
            if environment == 'Production':
                self.logger.info(f'{environment} Environment Detected', DEBUG_LEVEL_DEBUG)
                self.certificate = "/tmp/conjur_server.crt"
            else:
                self.logger.info(f'{environment} Environment Detected', DEBUG_LEVEL_DEBUG)
                self.certificate = False
        except Exception as e:
            self.logger.error(f'Failed to retrieve aob_mode parameter: {str(e)}')
            raise Exception("Error occurred while retrieving aob_mode parameter")            


    def logon_conjur(self, conjur_hostname, conjur_account, service_id, host_id):
        self.logger.trace(conjur_hostname, conjur_account, service_id, host_id, caller_name='logon_conjur')
        self.logger.info("Authenticating to Conjur")
        self.conjur_url = f"https://{conjur_hostname}"
        self.conjur_account = conjur_account

        session = boto3.Session()
        credentials = session.get_credentials()
        creds = credentials.get_frozen_credentials()

        self.logger.info("Generating signed request to STS for Conjur AWS IAM Authenticator", DEBUG_LEVEL_DEBUG)
        request = AWSRequest("GET", "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15")
        payload_hash = hashlib.sha256(('').encode('utf-8')).hexdigest()
        request.headers.add_header("Host", "sts.amazonaws.com")
        request.headers.add_header("X-Amz-Content-sha256", payload_hash)
        request.headers.add_header("Accept-Encoding", "identity")
        request.headers.add_header("Content-Type", "application/x-www-form-urlencoded")
        SigV4Auth(creds, "sts", "us-east-1").add_auth(request)
        headers = {key: value for (key, value) in request.headers.items()}

        host_id_safe = urllib.parse.quote(host_id, safe='')
        auth_url = f"{self.conjur_url}/authn-iam/{service_id}/{conjur_account}/{host_id_safe}/authenticate"
        
        self.logger.info(f"Authenticating to Conjur Endpoint - {auth_url}")
        auth_res = requests.post(auth_url, json.dumps(headers), headers={
                'Accept-Encoding': "base64"
            }, verify=self.certificate, timeout=5)
        print(f"Get conjur token: {auth_res.status_code}:{auth_res.reason}")
        if auth_res.status_code != 200:
            raise Exception(f"Conjur authentication failure: {auth_res.status_code}:{auth_res.reason}")
        return auth_res.text


    def get(self, conjur_token, variable_id):
        self.logger.trace(variable_id, caller_name='get')
        self.logger.info("Retrieving Conjur Variable from Endpoint - "
                         f"{self.conjur_url}/secrets/{self.conjur_account}/variable/{variable_id}", DEBUG_LEVEL_DEBUG)
        res = requests.get(f"{self.conjur_url}/secrets/{self.conjur_account}/variable/{variable_id}", headers={
                           'Authorization': f"Token token=\"{conjur_token}\""
                           }, verify=self.certificate, timeout=5)
            
        if res.status_code != 200:
            raise Exception(f"Failed to get secret {variable_id}. {res.status_code}:{res.reason}")

        return res.text
