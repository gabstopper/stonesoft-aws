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
FW = [fields('Enter a name', 'name'),
      fields('Enter DNS server, comma separated', 'dns'),
      fields('Enter firewall policy: ', 'firewall_policy', choices=obtain_fwpolicy),
      fields('Enter a location for NGFW: ', 'location', choices=obtain_locations),
      fields('Use default NAT', 'default_nat'),
      fields('Enable anti-virus', 'antivirus'),
      fields('Enable GTI', 'gti'),
      fields('Assign a VPN Policy', 'vpn')]

FW_VPN = [fields('Enter VPN policy: ', 'vpn_policy', choices=obtain_vpnpolicy),
          fields('VPN role (central|satellite)', 'vpn_role')]

# Stonesoft Management Server information. Optional, if skipped, other menu's will
# be ignored
SMC = [fields('IP address of SMC API', 'smc_address')]

# SMC settings that are required after SMC address is specified
VERIFY_SMC = [fields('Enter the api key', 'smc_apikey'),
              fields('Enter the SMC port', 'smc_port'),
              fields('Use SSL connection', 'smc_ssl')]

VERIFY_SSL = [fields('Verify SSL cert', 'verify_ssl')]
SMC_CACERT = [fields('Full path to SSL cert file', 'ssl_cert_file')]

# Amazon AWS information
AWS = [fields('Enter AWS access key id', 'aws_access_key_id'),
       fields('Enter AWS secret access key', 'aws_secret_access_key'),
       fields('Enter AWS region', 'aws_region'),
       fields('Enter VPC subnet (required)', 'vpc_subnet'),
       fields('Enter VPC public network (required)', 'vpc_public'),
       fields('Enter VPC private network (required)', 'vpc_private'),
       fields('Enter name of AWS keypair (required)', 'aws_keypair'),
       fields('Enter NGFW AMI id (required)', 'ngfw_ami'),
       fields('Enter NGFW instance type', 'aws_instance_type'),
       fields('Start an AMI client instance', 'aws_client')]

AWS_CLIENT = [fields('Enter AWS client AMI', 'aws_client_ami')]

FILE_PATH = [fields('Location for yaml file', 'path')]
