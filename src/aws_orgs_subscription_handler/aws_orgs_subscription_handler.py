import boto3
import cfnresponse

ROLE_ARN = 'CyberArk-AOB-SubscribeServiceRole'


def lambda_handler(event, context):
    print(f'lambda_handler | {event} | {context}')
    try:
        physical_resource_id = str(uuid.uuid4())
        if 'PhysicalResourceId' in event:
            physical_resource_id = event['PhysicalResourceId']

        stack_name = event['ResourceProperties']['StackName']
        template_url = event['ResourceProperties']['TemplateURL']
        target_aws_account_id = event['ResourceProperties']['TargetAWSAccountID']
        target_aws_region = event['ResourceProperties']['TargetAWSRegion']
        solution_region = event['ResourceProperties']['SolutionRegion']

        if event['RequestType'] == 'Create':
            print('[INFO] Create request received')
            cfn_client = boto3.client('cloudformation', region_name=solution_region)
            params = {
                'StackName': stack_name,
                'TemplateURL': template_url,
                'Parameters': [
                    {
                        "TargetAWSAccountID": target_aws_account_id,
                        "TargetAWSRegion": target_aws_region
                    }
                ],
                'RoleARN': ROLE_ARN
            }
            print(f'[INFO] Initiating subscription stack creation in solution region for '
                  f'{target_aws_account_id} in {target_aws_region}')
            cfn_client.create_stack(**params)
            cfn_waiter = cfn_client.get_waiter('stack_create_complete')
            print('[INFO] Waiting for the stack creation to complete...')
            cfn_waiter.wait(StackName=stack_name)
            print('[INFO] Stack creation successful')
            return cfnresponse.send(event, context, cfnresponse.SUCCESS, None, physical_resource_id)

        if event['RequestType'] == 'Delete':
            print('[INFO] Delete request received')
            cfn_client = boto3.client('cloudformation', region_name=solution_region)
            print(f'[INFO] Confirming stack {stack_name} exists')
            stack_exists = False
            stacks = cfn_client.list_stacks()['StackSummaries']
            for stack in stacks:
                if stack['StackStatus'] == 'DELETE_COMPLETE':
                    continue
                if stack_name == stack['StackName']:
                    stack_exists = True
                    stack_id = stack['StackId']
            if not stack_exists:
                print(f'[INFO] Stack does not exist, nothing to delete')
                return cfnresponse.send(event, context, cfnresponse.SUCCESS, None, physical_resource_id)
            print(f'[INFO] Initiating stack deletion in solution region for {stack_id}')
            cfn_client.delete_stack(StackName=stack_id)
            cfn_waiter = cfn_client.get_waiter('stack_delete_complete')
            print(f'[INFO] Waiting for the stack deletion to complete...')
            cfn_waiter.wait(StackName=stack_id)
            print(f'[INFO] Stack deletion successful')
            return cfnresponse.send(event, context, cfnresponse.SUCCESS, None, physical_resource_id)
    except Exception as e:
        print(f"[ERROR] Exception occurred:{str(e)}:")
        return cfnresponse.send(event, context, cfnresponse.FAILED, {'Message': f"Exception occurred: {str(e)}"})
