import boto3
from botocore.config import Config

DEBUG_LEVEL_INFO = 'info' # Outputs erros and info only.
DEBUG_LEVEL_DEBUG = 'debug' # Outputs all information


class LogMechanism:
    def __init__(self):
        self.debug_level = get_debug_level()


    def info(self, message, debug_level=DEBUG_LEVEL_INFO):
        message = str(message)
        if debug_level == self.debug_level.lower() or self.debug_level.lower() == 'trace':
            print(f'[INFO] {message}')


    def error(self, message, debug_level=DEBUG_LEVEL_INFO):
        message = str(message)
        if debug_level == self.debug_level.lower() or self.debug_level.lower() == 'trace':
            print(f'[ERROR] {message}')


    def trace(self, *args, caller_name):
        args = [str(arg) for arg in args]
        if self.debug_level.lower() == 'trace':
            print(f'[TRACE] {caller_name}: ', args, sep=' | ')


def get_debug_level():
    try:
        config = Config(connect_timeout=5, retries={'total_max_attempts': 1, 'mode': 'standard'})
        ssm = boto3.client('ssm', config=config)
        ssm_parameter = ssm.get_parameter(
            Name='AOB_Debug_Level'
        )
        aob_debug_level = ssm_parameter['Parameter']['Value']
        return aob_debug_level
    except Exception as e:
        print(f'[ERROR] Failed to read "AOB_Debug_Level" from the SSM Parameter Store: {str(e)}')
        print("[INFO] Defaulting debug_level to INFO")
        return DEBUG_LEVEL_INFO
