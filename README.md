
Protecting privileged accounts is never an easy task. They must be identified and managed, but in most cases it takes time and effort
to cover the entire organization's network. This process is even more challenging in Cloud environments, due to their dynamic nature.
Instances (containers and virtual servers) are ephemeral and may be spun up and down all the time, which can cause a situation where
privileged accounts of critical applications and workloads are not managed while they are active.

CyberArk provides a solution that detects unmanaged privileged SSH Keys in newly created Unix/Linux EC2 instances and unmanaged Windows
instances in Amazon Web Services (AWS) environments, and automatically onboards them to the CyberArk Vault. When an SSH Key\Password is
onboarded, it is immediately changed. This solution also detects when EC2 instances are terminated and subsequently deletes the irrelevant 
accounts from the Vault.

Unlike schedule-based scanners, this is an Event Driven discovery that detects changes in the environment in real time. AWS CloudWatch informs
CyberArk about new EC2 instances and triggers the CyberArk Lambda function that initiates the onboarding process.

The solution is packaged as a series of CloudFormation templates, which automates deployment. We recommend that customers deploy these templates
once (except for the StackSet template, explained further below) into a single designated solution account, which will provide coverage for
all AWS accounts and regions within the respective AWS Organization.

This solution supports CyberArk environments that are deployed in the Cloud and in hybrid architectures.

# Features
- Automatic onboarding and management of new AWS instances upon spin up
- Automatic de-provisioning of accounts for terminated AWS instances
- Near real time onboarding of new instances spinning up  
- Flexible CyberArk Safe targeting for account onboarding - Mix and match per-instance, per-account, and global safe scopes
- Complete multi-region and multi-account (within the AWS Organization scope) coverage via single solution deployment
- Optional CyberArk Conjur integration allowing for JIT retrieval of the Vault User secret needed for CyberArk REST API calls

# Prerequisites
This solution requires the following:

1. The CyberArk PAS solution is installed on-prem / Cloud / hybrid with v9.10 or higher.
2. The CyberArk license must include SSH key manager.
3. Network access from the Lambda VPC to CyberArk's PVWA.
4. Network access from the Lambda VPC to various AWS service endpoints as detailed below.  This is most simply accomplished through the 
use of a NAT Gateway (particularly for reaching cross-region EC2 endpoints) however other techniques such as the use of 
AWS PrivateLink may also be employed.  The AWS service endpoints utilized by the solution Lambdas are as follows:
    
    | Elasticity Lambda: |
    | --- |
        ec2.[target_region].amazonaws.com
        sts.[solution_region].amazonaws.com
        lambda.[solution_region].amazonaws.com
        ssm.[solution_region].amazonaws.com
        dynamodb.[solution_region].amazonaws.com

    | Safe Handler Lambda: |
    | --- |
        s3.[solution_region].amazonaws.com
        ec2.[solution_region].amazonaws.com
        ssm.[solution_region].amazonaws.com
        dynamodb.[solution_region].amazonaws.com

    | Trust Mechanism Lambda: |
    | --- |
        ssm.[solution_region].amazonaws.com

    From the lists provided above, `[target_region]` refers to the region relative to the EC2 instance being on-boarded and `[solution_region]` 
refers to the region the CyberArk AWS auto onboarding solution is deployed into. <br/><br/>For further information, see 
https://docs.aws.amazon.com/lambda/latest/dg/vpc.html and for a CyberArk PAM example network template, see: 
https://github.com/cyberark/pas-on-cloud/blob/master/aws/PAS-network-environment-NAT.json </br></br>
5. The CPM that manages the SSH keys must have a network connection to the target devices (for example, vpc peering).
6. To connect to new instances, PSM must have a network connection to the target devices (for example, vpc peering).
7. The expected maximum number of instances must be within the number of accounts license limits.
8. PVWA is configured with a proper CA-Signed SSL Certificate (unless it's a POC environment).
9. In the "UnixSSH" platform, set the "ChangeNotificationPeriod" value to 60 sec (this platform will be used for managing Unix accounts,
and setting this parameter gives the instance time to boot before attempting to change the password).
10. In the "WinServerLocal" platform, set the "ChangeNotificationPeriod" value to 60 sec (this platform will be used for managing Windows accounts,
and setting this parameter gives the instance time to boot before attempting to change the password) .
11. Dedicated Vault user for the solution with the following authorizations (not Admin):

    | General Vault Permissions:|
    | ------ |
         Add Safes

12. **[Situational]** - StackSet Enabled according to AWS documentation (_See step #5 under "Deployment using Cloud Formation" for additional context_):
    https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-prereqs-self-managed.html

13. If the Keypair and/or the Safes already exist (and are not created by the solution), the Vault user 
must be the owner of these Safes with the following permissions:

    |	 Key Pair Safe Permissions:|
    | ------ |
        Add Accounts
        List Accounts
        Retrieve Account
        Update Accounts Properties

    |	 Unix Accounts Safe Permissions:|
    | ------ |
        Add Accounts
        List Accounts
        Delete Account
        Update Accounts Properties
        Initiate CPM account management operations

    | 	 Windows Accounts Safe Permissions: |
    | ------ |
        Add Accounts
        List Accounts
        Delete Account
        Update Accounts Properties
        Initiate CPM account management operations


# Deployment using Cloud Formation 



1. Download cyberark-aws-auto-onboarding solution zip files and CloudFormation template from
[https://github.com/cyberark/cyberark-aws-auto-onboarding/tree/master/dist](https://github.com/cyberark/cyberark-aws-auto-onboarding/tree/master/dist)

2. Upload the solution to your S3 Bucket in the same region you want to deploy the solution. 
3. Deploy CyberArk-AOB-MultiRegion-CF.json.
4. Deploy CyberArk-AOB-MultiRegion-CF-VaultEnvCreation.yaml.
   1. For more information on the _Environment Type and Verification Key_ parameters that are prompted for in this template, 
   see the section below [Environment Type and Verification Keys](#environment-type-and-verification-keys).
   2. For more information on the _Conjur Integration_ parameters that are prompted for in this template, see the section
   below [CyberArk Conjur Integration](#cyberark-conjur-integration)
5. **[Situational]** - Deploy CyberArk-AOB-MultiRegion-StackSet.json in accordance with one of the following scenarios:
   1. _For a single-account, single-region deployment_ - **this template is not required and may be skipped</ins>** as all necessary 
   resources to enable the solution account/region itself are deployed via the previous two CloudFormation templates.
   2. _For a single-account, multi-region deployment_ - You must deploy this template into all targeted regions (i.e. those
   containing EC2 instances you wish to include for auto on-boarding) that are additional to your solution's region.  Deployment 
   may be accomplished via a standard CloudFormation Stack or as a StackSet, whichever your preference.  Given a single additional 
   region for example, simply deploying as a standard stack into that region may be easiest.
   3. _For a multi-account, single/multi-region deployment_ - You must deploy this template to all target accounts and
   regions (i.e. those containing EC2 instances you wish to include for auto on-boarding); a task that is perfectly suited for a CloudFormation StackSet.  A fully automated StackSet deployment mode 
   using service-managed permissions (the AWS Organizations construct) is viable here, though other modes of StackSet deployment 
   (such as self-managed permissions) are also viable.
   >**Note**: Deploying this stack into your solution account/region will not cause any harm, but take note that it will
   not deploy any resources either and thus result in an effectively void stack.
6. Upload the old/existing key pairs used to create instances in your AWS region to the Key Pair Safe in the Vault according to the following naming 
convention: `AWS.[AWSAccount].[Region].[KeyPairName]` Example - AWS.1231231231.us-east-2.Mykey

### Environment Type and Verification Keys
There are two options for Environment Type: `Production` or `POC`.  The selection made governs whether the solution Lambdas 
will verify the PVWA's SSL/TLS certificate has been issued by a trusted source.  This does not impact whether HTTPS is used,
HTTPS is _always_ used.  In `POC` mode, SSL certificate verification is disabled and thus, verification key parameters 
are not utilized or required.  In `Production` mode, SSL certificate verification is enabled and the verification key 
parameters are utilized (and correct contents are crucial to an error-free deployment).  

Selecting `Production` mode is recommended!

#### When proceeding in `Production` mode:
The contents of the `PVWA/Conjur Verification Key File` depend on how the PVWA's (and optionally Conjur's) SSL certificate is signed:
* _If the certificate is self-signed_ - The contents should be the PVWA/Conjur certificate in Base64 (PEM) format <br/><br/>
* _If the certificate is signed by a single-tier PKI (Root CA > PVWA/Conjur Certificate)_ - The contents should be the Root CA's certificate
in Base64 (PEM) format<br/><br/>
* _If the certificate is signed by a multi-tier PKI (Root CA > [Subordinate CA-n] > Issuing CA > PVWA/Conjur Certificate)_ -
The contents should be all CA certificates in the chain, in their signed order, in Base64 (PEM) format, with the Root CA at 
the bottom of the file.<br/><br/>For example, if the PVWA/Conjur certificate is signed by a two-tier PKI (Root CA > Issuing CA > PVWA/Conjur Certificate) 
then the contents should be the Base64 (PEM) text block that represents the certificate of the Issuing CA followed immediately 
by the Base64 text block that represents the certificate of the Root CA.  This example file when viewed in Notepad would 
look something like this (This is a sample redacted for readability, this is not a valid file):
``````
-----BEGIN CERTIFICATE----- 
MIIDdzCCAl+gAwIBAgIQeuHTP//UtY9FXVhc7Ter5DANBgkqhkiG9w0BAQsFADBO
...
24XYXu5UVkBeyOxljNt5rbhTxmppSejaVCGXiDYPYbIvrRilDGXRQpRarD+8JDIA
zFySmOwoIrQdTtdEe51FvhBgQ5oqKOyq8Y0T
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE----- 
MIIDdTCCAl2gAwIBAgILBAAAAAABFUtaw5QwDQYJKoZIhvcNAQEFBQAwVzELMAkG
...
DKqC5JlR3XC321Y9YeRq4VzW9v493kHMB65jUr9TU/Qr6cf9tveCX4XSQRjbgbME
HMUfpIBvFSDJ3gyICh3WZlXi/EjJKSZp4A==
-----END CERTIFICATE-----
``````

>**Note**: If the PVWA/Conjur certificate is updated and the CA chain contains one or more new signers, you must update 
the `AOB_[PVWA/Conjur]_Verification_Key` parameter(s) in the AWS Systems Manager parameter store with the plain text content 
of what would be the new respective verification file, as described above.

### CyberArk Conjur Integration
Integration with CyberArk Conjur is optional but highly recommended.  Below are the high-level steps
required to prepare the Conjur environment and collect the necessary information that will be utilized by this solution.  These
details will be primarily provided during deployment of the `VaultEnvCreation` CloudFormation template as described above:

1. The username and password of the Vault User designated for this solution (see [Prerequisite #11](#prerequisites)) must 
be loaded into Conjur variables.  Use of CyberArk PAS and the [CyberArk Vault Synchronizer](https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Conjur/cv_Synchronizer-lp.htm?tocpath=Integrations%7CCyberArk%20Vault%20Synchronizer%7C_____0)
is highly recommended allowing for fully automated management of this credential.  Take note of the variable paths/names within Conjur policy.
2. Define and enable an [AWS IAM Authenticator](https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Operations/Services/AWS_IAM_Authenticator.htm?tocpath=Integrations%7C_____7)
for Conjur as required, and take note of the service ID (i.e. "prod")
3. Host entries must be provisioned within Conjur that correspond to the IAM roles that our Safe Handler and Elasticity 
Lambdas will assume, and use to authenticate with Conjur.  Two Host entries within Conjur must be created as follows:
   1. `[AWS_Solution_Account_ID]/CyberArk-AOB-SafeHandlerLambdaRole`
   2. `[AWS_Solution_Account_ID]/CyberArk-AOB-ElasticityLambdaRole`

    Following creation, these Conjur host entries must be granted authorization to authenticate via the AWS IAM Authenticator WebService
created in step #2 above and granted [read, execute] privilege to the Vault User variables created in step #1 above.  Take note
of the policy/namespace that you decide to provision these hosts into.
4. Collect the following additional Conjur deployment details as these will be required for entry into the CloudFormation 
template during deployment:
   1. Conjur Leader/Follower [LB] IP or FQDN that the solution will target
   2. The account name for your Conjur instance
      1. If this value is not known it can easily be retrieved via Conjur CLI by first logging into the CLI and then issuing the command `conjur whoami`
   3. The CA certificate chain that signs your Conjur Leader/Follower [LB] SSL certificate, which must be consolidated into a single
   verification key file and uploaded to your solution S3 bucket.  See guidance under
   [Environment Type and Verification Keys](#environment-type-and-verification-keys) for more details.

For more information on CyberArk Conjur and more detailed reference to policy management and the policy statements required to accomplish
the steps outlined above, please refer to the appropriate documentation sections from here - https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Resources/_TopNav/cc_Home.htm

# Solution Upgrade Procedure 
1. Replace the solution files in the bucket 
2. Update the cloudFormation stack with the new template

# Solution Options
### Advanced Safe Targeting
By default, accounts will auto onboard into a pair of global safes that you define during deployment of the `VaultEnvCreation` 
CloudFormation template: one for Windows instances and one for *NIX instances.  This may be perfectly adequate for your needs.

It is also possible however, to define AWS account-level safes that instances will auto onboard into.  This may be useful in certain
organizations where permissions boundaries coincide with an AWS account.  Or simply better organization and Vault metrics
based on AWS account are desired.  To achieve this, all that is required is to create these AWS account-level safes using
the following naming convention:

`[AWS_Account_ID]_[Global_Windows_Safe / Global_*NIX_Safe]`

For example, lets say during deployment you define a global Windows safe of `AOB_Windows` and a global *NIX safe of `AOB_NIX`
within CyberArk.  You would also like to establish account-level safes for an AWS account number `123456789012`.  You would create
safes within CyberArk as follows:

`123456789012_AOB_Windows`<br/>
`123456789012_AOB_NIX`

As soon as these safes exist (and your Vault User has the necessary permissions to onboard into them per [Prerequisite #13](#prerequisites))
accounts will begin to onboard into these safes automatically.

For even greater safe targeting control at the instance level, you may also optionally define a Tag on the EC2 instance of 
the following name/value pair:

Tag Name - `CyberArk-Safe`<br/>
Tag Value - `[Your Desired Target Safe in CyberArk]`

For example, lets say you create a Tag on a new EC2 instance with Name `CyberArk-Safe` and Value `PROD_DB_Oracle`.  During 
the onboarding motion, the solution will search for and find the existence of this Tag on the EC2 instance, reading its value.  It
will then search CyberArk for a Safe named `PROD_DB_Oracle` and if one is found, it will be utilized for onboarding.

These advanced safe targeting techniques are optional and the resultant order of precedence to safe targeting is ultimately as follows:

1. The solution checks the EC2 instance for a `CyberArk-Safe` Tag.  If the Tag does not exist or otherwise defines a safe that 
does not exist, move to step 2.
2. The solution checks for an account-level safe based on the source account of the EC2 instance and its instance type (Windows/*NIX).  If
an account-level safe does not exist, move to step 3
3. The solution utilizes the appropriate global Windows/*NIX safe as defined during solution deployment

# Limitations
1. CyberArk currently supports onboarding SSH keys for the following AWS accounts:
 - AWS Linux, RHL AMIs: ec2-user
 - Ubuntu: ubuntu user
 - Centos: centos user
 - openSuse: root user
 - Debian: admin user
 - Fedora: fedora user
> Amazon AMI/custom AMI with a key that was created by the solution or uploaded in advance to the Safe in the Vault supplied in the solution deployment (not supplied hard coded by Amazon)

2. Existing AWS instances (pre-installed) are not onboarded automatically (only after restart).
3. This solution currently handles a maximum of 100 events in 4 seconds.
4. EC2 instance public IPs must be elastic IPs to allow continuous access and management after changing the instance state.
5. Constrained multi-account and multi-region functionality in AWS GovCloud (US) and China at this time due to limitations in AWS EventBridge and cross-region event bus targeting (which precludes the GovCloud (US) and China regions).
For such scenarios, the solution must be deployed independently into each account and region.
For more information see https://aws.amazon.com/blogs/compute/expanding-cross-region-event-routing-with-amazon-eventbridge/ 
6. For the CPM to manage new Windows instances for some versions (see the list below), the user must run the following command manually on all
new Windows instances:

```sh
netsh firewall set service RemoteAdmin enable
```

>**Note**: CPM will fail to rotate the password if this command has not been executed.

##### List of Windows instances that require this command to be run manually:

- Microsoft Windows Server 2016 Base
- Microsoft Windows Server 2016 Base with Containers
- Microsoft Windows Server 2016 with SQL Server 2017 Express
- Microsoft Windows Server 2016 with SQL Server 2017 Web 
- Microsoft Windows Server 2016 with SQL Server 2017 Standard
- Microsoft Windows Server 2016 with SQL Server 2017 Enterprise
- Microsoft Windows Server 2016 with SQL Server 2016 Express
- Microsoft Windows Server 2016 with SQL Server 2016 Web 
- Microsoft Windows Server 2016 with SQL Server 2016 Standard
- Microsoft Windows Server 2016 with SQL Server 2016 Enterprise

# Debugging and Troubleshooting
* There are three main lambdas:
	1. SafeHandler - Creates the safes for the solution and uploads the solution main key pair.
	2. Elasticity - Onboards new instances to PAS.
	3. TrustMechanism - Responsible for SSM integration.
>**Note**: You can find the lambdas by searching in the cloudformation's resource tab `AWS::Lambda::Function`

* All information about debugging is available through AWS CloudWatch and can be accessed easily
through each lambda function under the monitoring section.
* The debug level can be controlled by editing the SSM parameter - `AOB_Debug_Level`.
* There are 3 debug levels :
	* Info - Displays general information and errors.
	* Debug - Displays detailed information and errors.
	* Trace - Displays every call made by the solution in details.

# Contributing
Feel free to open pull requests with additional features or improvements!

1. Fork it.
2. Create your feature branch.
```sh
git checkout -b my-new-feature)
```
3. Commit your changes.
```sh
git commit -am 'Added some feature'
```
4. Push to the branch.
```sh
git push origin my-new-feature
```
5. Create a new Pull Request.


# Deleting the solution 
### Order of deletion:
1. Delete StackSet.
2. Delete the CloudFormations in the following order:
	- CyberArk-AOB-MultiRegion-CF-VaultEnvCreation
	- CyberArk-AOB-MultiRegion-CF


# Licensing
Copyright 1999-2020 CyberArk Software Ltd.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this software except in compliance with the License. You may obtain a copy of the License at

[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
