'''
Created on Nov 18, 2016

@author: davidlepage
'''
from os.path import expanduser
from collections import namedtuple
from ngfw import obtain_locations, obtain_fwpolicy, obtain_vpnpolicy

# Template field
class Field(namedtuple('Field', 'prompt default required')):
    """
    Used to store YAML file field header, prompt to the user, default value 
    (if any) and whether it a required field. This is used when user wants to
    use interactive setup and provide input to configuration data. 
    """
    def __new__(cls, prompt, default, required=False): # @ReservedAssignment
        return super(Field, cls).__new__(cls, prompt, default, required)

# Main NGFW Prompts. Attribute name maps to YML heading
NGFW = [{'name' : Field(prompt='Enter a name', default='awsfirewall', required=True)},
        {'dns': Field(prompt='Enter DNS servers, comma seperated', default=None)},
        {'location': Field(prompt='Enter location for NGFW', default=obtain_locations)},
        {'firewall_policy': Field(prompt='Enter firewall policy', default=obtain_fwpolicy)},
        {'vpn': Field(prompt='Assign VPN policy', default='False')},
        {'default_nat': Field(prompt='Use default NAT', default='True')},
        {'antivirus': Field(prompt='Enable antivirus', default='False')},
        {'gti': Field(prompt='Enable GTI', default='False')}]

# Optional VPN prompts if VPN is specified
OPT_VPN = [{'vpn_policy': Field(prompt='Enter VPN policy (optional)', default=obtain_vpnpolicy)},
           {'vpn_role': Field(prompt='VPN role (central|satellite)', default='central')}]

# SMC credential info
SMC = [{'smc_address': Field(prompt='IP address of SMC API', default=None)},
       {'smc_apikey': Field(prompt='Enter the api key', default=None)},
       {'smc_port': Field(prompt='Enter the SMC port', default='8082')}]

# AWS base information
AWS = [{'aws_access_key_id': Field(prompt='Enter AWS access key id', default=None)},
       {'aws_secret_access_key': Field(prompt='Enter AWS secret access key', default=None)},
       {'aws_region': Field(prompt='Enter AWS region', default=None)},
       {'vpc_subnet': Field(prompt='Enter VPC subnet', default=None, required=True)},
       {'vpc_public': Field(prompt='Enter VPC public network', default=None, required=True)},
       {'vpc_private': Field(prompt='Enter VPC private network', default=None, required=True)},
       {'aws_keypair': Field(prompt='Enter name of AWS keypair', default=None, required=True)},
       {'ngfw_ami': Field(prompt='Enter NGFW AMI id', default=None, required=True)},
       {'aws_instance_type': Field(prompt='Enter NGFW instance type', default='t2.micro')},
       {'aws_client': Field(prompt='Start an AMI client instance', default='False')}]

# Optional if client AMI specified
OPT_AWS = [{'aws_client_ami': Field(prompt='Enter AWS client AMI', default=None, required=True)}]

PATH = [{'path': Field(prompt='Location for yaml file', default='{}/ngfw-deploy.yml'.format(expanduser("~")))}]