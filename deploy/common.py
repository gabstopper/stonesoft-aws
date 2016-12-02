"""
Menus for interactive prompting
"""
from __future__ import unicode_literals
from os.path import expanduser
from collections import namedtuple
from ngfw import obtain_locations, obtain_fwpolicy, obtain_vpnpolicy

# Template
Field = namedtuple('Field', 'prompt default required')

def field(prompt, default=None, required=False):
    return Field(prompt, default, required)

# Main NGFW Prompts. Attribute name maps to YML heading
NGFW = [{'name': field('Enter a name', 'awsfirewall', True)},
        {'dns': field('Enter DNS servers, comma seperated (required for AV/GTI):')},
        {'location':field('Enter the location element for NGFW:', default=obtain_locations)},
        {'firewall_policy': field('Enter firewall policy:', default=obtain_fwpolicy)},
        {'vpn': field('Assign VPN policy (optional)', default='False')},
        {'default_nat': field('Use default NAT', default='True')},
        {'antivirus': field('Enable antivirus', default='False')},
        {'gti': field('Enable GTI', default='False')}]

# Optional VPN prompts if VPN is specified
OPT_VPN = [{'vpn_policy': field('Enter VPN policy:', default=obtain_vpnpolicy)},
           {'vpn_role': field('VPN role (central|satellite)', default='central')}]

# SMC credential info
SMC = [{'smc_address': field('IP address of SMC API')},
       {'smc_apikey': field('Enter the api key')},
       {'smc_port': field('Enter the SMC port', default='8082')},
       {'smc_ssl': field('Use SSL connection', default='False')}]

# SMC SSL settings, if use SSL connection is specified
OPT_SMC_SSL = [{'verify_ssl': field('Verify SSL cert', default='False')}]
OPT_SMC_CERT = [{'ssl_cert_file': field('Full path to SSL cert file', required=True)}]

# AWS base information
AWS = [{'aws_access_key_id': field('Enter AWS access key id')},
       {'aws_secret_access_key': field('Enter AWS secret access key')},
       {'aws_region': field('Enter AWS region')},
       {'vpc_subnet': field('Enter VPC subnet (required)', required=True)},
       {'vpc_public': field('Enter VPC public network (required)', required=True)},
       {'vpc_private': field('Enter VPC private network (required)', required=True)},
       {'aws_keypair': field('Enter name of AWS keypair (required)', required=True)},
       {'ngfw_ami': field('Enter NGFW AMI id (required)', required=True)},
       {'aws_instance_type': field('Enter NGFW instance type', default='t2.micro')},
       {'aws_client': field('Start an AMI client instance', default='False')}]

# Optional if client AMI specified
OPT_AWS = [{'aws_client_ami': field('Enter AWS client AMI', required=True)}]

# Path to save the configuration
PATH = [{'path': field('Location for yaml file', 
                       default='{}/ngfw-deploy.yml'.format(expanduser("~")))}]

