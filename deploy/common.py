"""
Menus for interactive prompting
"""
from __future__ import unicode_literals
from collections import namedtuple
from deploy.ngfw import obtain_locations, obtain_fwpolicy, obtain_vpnpolicy

FieldValidator = namedtuple('Validator', 'prompt, field choices')
def fields(prompt, field, choices=None):
    return FieldValidator(prompt, field, choices)

# NGFW specific information. Choice menu's are pulled directly from SMC API
FW = [fields('\nSelect a firewall policy: ', 'firewall_policy', choices=obtain_fwpolicy),
      fields('Select a location for NGFW: ', 'location', choices=obtain_locations),
      fields('Enter DNS server, comma separated', 'dns'),
      fields('Use default NAT', 'default_nat'),
      fields('Enable anti-virus', 'antivirus'),
      fields('Enable GTI', 'gti'),
      fields('Assign a VPN Policy', 'vpn')]

FW_VPN = [fields('Enter VPN policy: ', 'vpn_policy', choices=obtain_vpnpolicy),
          fields('VPN role (central|satellite)', 'vpn_role')]

# Stonesoft Management Server information. Optional, if skipped, other menu's will
# be ignored
SMC_CREDS = [fields('IP address of SMC API (bypassing will use ~/.smcrc)', 'smc_address'),
             fields('Enter the api key', 'smc_apikey'),
             fields('Enter the SMC port', 'smc_port'),
             fields('Use SSL connection', 'smc_ssl')]

# SMC settings that are required after SMC address is specified
VERIFY_SMC = [fields('Enter the api key', 'smc_apikey'),
              fields('Enter the SMC port', 'smc_port'),
              fields('Use SSL connection', 'smc_ssl')]

VERIFY_SSL = [fields('Verify SSL cert', 'verify_ssl')]
SMC_CACERT = [fields('Full path to SSL cert file', 'ssl_cert_file')]

AWS_BANNER = ('\nProviding your AWS credentials will store them in the YML file.\n'
              'If you already use boto3 credential files this section is optional.\n')

AWS_REQ_BANNER = ('\nThese AWS settings are required in order to properly launch a Stonesoft\n'
                  'NGFW instance into AWS:\n')

AWS_OPT_BANNER = ('\nIf you want to automate the deployment of a VPC with NGFW into AWS without\n'
                  'providing interactive input, enter the VPC configuration information below.\n'
                  'These settings are not needed if only adding or removing from an existing VPC.\n')

# AWS Credentials are optional but can be stored in generalized YML
AWS_CREDS = [fields('Enter AWS access key id', 'aws_access_key_id'),
             fields('Enter AWS secret access key', 'aws_secret_access_key'),
             fields('Enter AWS region (prompt if not provided)', 'aws_region')]

# Required settings for launching AMI instances into AWS
AWS_REQ = [fields('Enter name of AWS keypair (required)', 'aws_keypair'),
           fields('Enter NGFW AMI id (required)', 'ngfw_ami'),
           fields('Enter NGFW instance type', 'aws_instance_type')]

AWS_OPT_ASK = [fields('Provide VPC subnet information', 'vpc')]

AWS_OPT = [fields('Enter VPC subnet (required)', 'vpc_subnet'),
           fields('Enter VPC public network (required)', 'vpc_public'),
           fields('Enter VPC private network (required)', 'vpc_private'),
           fields('Start an AMI client instance', 'aws_client')]

def aws_creds():
    for opt in AWS_CREDS:
        yield opt

def smc_creds():
    for opt in SMC_CREDS:
        yield opt

AWS_CLIENT = [fields('Enter AWS client AMI', 'aws_client_ami')]

FILE_PATH = [fields('Location for yaml file', 'path')]
