import ipaddress
import yaml
from deploy.ngfw import get_smc_session
from smc.api.exceptions import SMCConnectionError

class ValidationError(Exception):
    def __init__(self, message):
        self.message = message

class Validator(object):
    def __init__(self, field_name):
        self.field_name = field_name

    def validate(self, data):
        raise Exception('Implement in subclass')

class ValidatorSuite(Validator):
    def __init__(self):
        self.validators = []

    def add_validator(self, validator):
        self.validators.append(validator)

class RequiredValidator(Validator):
    def __init__(self, field_name):
        self.field_name = field_name
    
    def validate(self, data):
        if not isinstance(data, str) or len(data) == 0:
            raise ValidationError('Required field')
        return {self.field_name: data}

class IPSubnetValidator(Validator):
    def __init__(self, field_name):
        self.field_name = field_name
        
    def validate(self, data):
        try:
            ipaddress.IPv4Network(data)
        except (ValueError, ipaddress.AddressValueError) as e:
            raise ValidationError(e)
        return {self.field_name: data}

class DefaultValidator(Validator):
    def __init__(self, field_name, default_val):
        self.field_name = field_name
        self.default_val = default_val
  
    def validate(self, data):
        if not isinstance(data, str) or len(data) == 0:
            data = self.default_val
        elif isinstance(self.default_val, bool):
            if data.lower() == 'true':
                data = True
            elif data.lower() == 'false':
                data = False
            else:
                data = self.default_val
        return {self.field_name: data}

class ChoiceValidator(Validator):
    def __init__(self, field_name):
        self.field_name = field_name
    
    def validate(self, choice, lst):
        try:
            data = lst[int(choice)-1]
        except (IndexError, ValueError) as e:
            raise ValidationError(e)
        return {self.field_name: data}

try:
    input = raw_input  # @UndefinedVariable @ReservedAssignment
except NameError:
    pass
 
def prompt(opt):
    """
    Prompts for user input
    """
    while True:
        try:
            if opt.choices:
                print(opt.prompt)
                choice = opt.choices()
                for option in choice:
                    numbering = 1 + choice.index(option)
                    print(str(numbering) + ") " + option)
                value = input()
                for validate in suite.validators:
                    if validate.field_name == opt.field:
                        return validate.validate(value, choice)
            else:
                for validate in suite.validators:
                    if validate.field_name == opt.field:
                        if isinstance(validate, DefaultValidator):
                            value = input('{} [{}]: '.format(opt.prompt, 
                                                             validate.default_val))
                        else:
                            value = input('{}: '.format(opt.prompt))
                        return validate.validate(value)
                    
        except (ValidationError) as e:
            print("Invalid choice: %s" % e)

def write_cfg_to_yml(data, path=None):
    """ Writing collected data to yml """
    with open(path, 'w') as yaml_file:
        yaml.safe_dump(data, yaml_file, default_flow_style=False)
    print('Wrote ngfw-deploy.yml to dir %s' % path)

def custom_choice_menu(prompt, lst_for_menu):
    suite.add_validator(ChoiceValidator(prompt))
    while True:
        try:
            print(prompt)
            for option in lst_for_menu:
                numbering = 1 + lst_for_menu.index(option)
                print(str(numbering) + ") " + option)
            value = input()
            for validate in suite.validators:
                if validate.field_name == prompt:
                    return validate.validate(value, lst_for_menu).get(prompt)
        except ValidationError as e:
            print('Invalid choice: %s' % e) 

def banner_message():
    msg = ('Provide your configuration information to obtain a properly formatted\n'
           'YAML configuration file. The YAML configuration file can then be used\n'
           'to launch the application without intervention\n')
    return msg

suite = ValidatorSuite()
   
def prompt_user(path=None):

    from os.path import expanduser
    from deploy.common import (
            FW, FW_VPN, SMC_CACERT, VERIFY_SSL, AWS_REQ_BANNER,
            AWS_REQ, AWS_OPT_BANNER, AWS_CLIENT, FILE_PATH, 
            AWS_BANNER, AWS_OPT, AWS_OPT_ASK,
            aws_creds, smc_creds)
    
    suite.add_validator(DefaultValidator('smc_address', ''))
    suite.add_validator(RequiredValidator('smc_apikey'))
    suite.add_validator(DefaultValidator('smc_port', '8082'))
    suite.add_validator(DefaultValidator('smc_ssl', False))
    suite.add_validator(DefaultValidator('verify_ssl', False))
    suite.add_validator(RequiredValidator('ssl_cert_file'))
    suite.add_validator(DefaultValidator('dns', '8.8.8.8'))
    suite.add_validator(DefaultValidator('default_nat', True))
    suite.add_validator(DefaultValidator('antivirus', False))
    suite.add_validator(DefaultValidator('gti', False))
    suite.add_validator(DefaultValidator('vpn', False))
    suite.add_validator(DefaultValidator('vpn_role', 'central'))
    suite.add_validator(ChoiceValidator('firewall_policy'))
    suite.add_validator(ChoiceValidator('vpn_policy'))
    suite.add_validator(ChoiceValidator('location'))
    suite.add_validator(DefaultValidator('vpc', False))
    suite.add_validator(IPSubnetValidator('vpc_subnet'))
    suite.add_validator(IPSubnetValidator('vpc_private'))
    suite.add_validator(IPSubnetValidator('vpc_public'))
    suite.add_validator(DefaultValidator('aws_access_key_id', ''))
    suite.add_validator(RequiredValidator('aws_secret_access_key'))
    suite.add_validator(DefaultValidator('aws_region', ''))
    suite.add_validator(RequiredValidator('aws_keypair'))
    suite.add_validator(RequiredValidator('ngfw_ami'))
    suite.add_validator(DefaultValidator('aws_instance_type', 't2.micro'))
    suite.add_validator(DefaultValidator('aws_client', False))
    suite.add_validator(RequiredValidator('aws_client_ami'))
    suite.add_validator(DefaultValidator('path', '{}/ngfw-deploy.yml'.format(expanduser("~"))))
    
    print(banner_message())
    data = {}
    
    while True:
        creds = smc_creds()
        smc = {}
        for opt in creds:
            smc.update(prompt(opt))
            if smc.get('smc_address'):
                continue
            break
        if smc.get('smc_ssl'):
            for opt in VERIFY_SSL:
                smc.update(prompt(opt))
            if smc.get('verify_ssl'):
                for opt in SMC_CACERT:
                    smc.update(prompt(opt)) 
        try:
            get_smc_session(smc)
            # If provided during configure
            if smc.get('smc_address'):
                data.update({'SMC': smc}) 
            break
        except SMCConnectionError as e:
            print('Failed connecting to SMC: {}'.format(e))
        
    fw={}
    for opt in FW:
        fw.update(prompt(opt))
    if fw.get('vpn'):
        for opt in FW_VPN:
            fw.update(prompt(opt))
    fw.update(dns=fw.get('dns').split(','))
    data.update({'NGFW': fw})
    
    aws = {}
    creds = aws_creds()
    
    print(AWS_BANNER)
    for opt in creds:
        aws.update(prompt(opt))
        if aws.get('aws_access_key_id'):
            continue
        break
    
    print(AWS_REQ_BANNER)
    for opt in AWS_REQ:
        aws.update(prompt(opt))
        
    print(AWS_OPT_BANNER)
    for opt in AWS_OPT_ASK:
        if prompt(opt).get('vpc'):
            for opt in AWS_OPT:
                aws.update(prompt(opt))
            if aws.get('aws_client'):
                for opt in AWS_CLIENT:
                    aws.update(prompt(opt))
       
    data.update({'AWS': aws})

    path = prompt(FILE_PATH[0]).get('path')
    write_cfg_to_yml(data, path)
    return path

    