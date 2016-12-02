"""
Module handling user keyboard input
"""
from __future__ import unicode_literals
import sys
import yaml
from smc.api.exceptions import SMCConnectionError
from smc.api.configloader import transform_login
from deploy.common import field, NGFW, OPT_VPN, SMC, AWS, OPT_AWS, \
PATH, OPT_SMC_SSL, OPT_SMC_CERT

try:
    input = raw_input  # @UndefinedVariable @ReservedAssignment
except NameError:
    pass

def menu(prompt, fields=None, choices=None):
    """
    Generic menu prompt for interactive sessions
    
    If choices are provided, fields param is not required
    
    :param str prompt: prompt for the menu
    :param Field fields: Field namedtuple describing what to display
    :param list choices: list of options if need to present choices
    """
    while True:
        if not choices: #expecting Field namedtuple
            assert fields is not None, 'Missing field definitions'
            default = '' if not fields.default else fields.default
            if callable(default):   #list returned from SMC API call
                options = default()
                print(prompt)
                for entry in options:
                    numbering = 1 + options.index(entry)
                    print(str(numbering) + ") " + entry)
                try:
                    user_input = input()
                    if not user_input:
                        print('Field required, try again')
                        pass
                    else:
                        return options[int(user_input)-1]
                except IndexError:
                    print('Invalid choice, try again')
                except ValueError:
                    print('Invalid entry, try again')
            else:
                if sys.version_info > (3,):
                    value = input('{} [{}]: '.format(prompt, default))
                else:
                    value = input('{} [{}]: '.format(prompt, default))\
                        .decode(sys.stdin.encoding)
                if not value:
                    # No value given (user pressed enter)
                    if fields.default:
                        return fields.default
                    elif fields.required:
                        print('Field required, try again')
                        pass
                    else:   # Not required; empty is ok
                        return None
                else:
                    return value
        # Choices provided        
        else:
            print(prompt)
            for entry in choices:
                numbering = 1 + choices.index(entry)
                print(str(numbering) + ") " + entry)
            try:
                choice = input()
                try:
                    return choices[int(choice)-1]
                except ValueError:
                    print('Invalid input. Try again.')
            except IndexError:
                print('Invalid choice. Try again.')

def get_input(fields):
    """
    Parse fields requesting input. Expecting that fields param is an
    instance of namedtuple Field. 
    
    :param Field fields: Field namedtuple to parse through for input
    :return: dict of updated fields
    """
    data = {}
    for field in fields:
        for name, fieldtuple in field.items():
            #print name, fieldtuple
            result = menu(fieldtuple.prompt, fields=fieldtuple)
            field[name] = result
            data.update(field)
    return data

def write_cfg_to_yml(data, path=None):
    """
    Write the dict to yml
    
    :param dict data: data to write
    """
    # Convert string True|False to boolean
    for _, fields in data.items():
        for key, value in fields.items():
            if value and not isinstance(value, list):
                if value.lower() == 'false':
                    fields[key] = False
                elif value.lower() == 'true':
                    fields[key] = True
    # Write to file
    with open(path, 'w') as yaml_file:
        yaml.safe_dump(data, yaml_file, default_flow_style=False)
    print('Wrote ngfw-deploy.yml to dir %s' % path)

def prompt_user(path=None):
    """
    Start the prompt to the user. This is useful for the first run 
    through to get the correct yml template format. Returns a dict
    of the data.
    
    :param str path: path to save yml
    :return: dict of prompt items
    """
    from smc import session
    yml = {}    # For writing to yaml file
    try:
        # SMC settings
        smc = get_input(SMC)
        if smc.get('smc_address') and smc.get('smc_apikey'):
            # User specifying SMC information, need SSL?
            if smc.get('smc_ssl').lower().startswith('true'):
                smc.update(smc_ssl=True)
                
                # Should we verify SSL
                verify_ssl = get_input(OPT_SMC_SSL)
                if verify_ssl.get('verify_ssl').lower().startswith('true'):
                    smc.update(verify_ssl=True)
                    # If verify SSL selected, need cert path to verify
                    cert_file = get_input(OPT_SMC_CERT)
                    smc.update(ssl_cert_file=cert_file.get('ssl_cert_file'))
                else:
                    smc.update(verify_ssl=False)
            else:
                smc.update(smc_ssl=False)
           
            login = transform_login(smc)
            session.login(**login)
            yml.update({'SMC': smc})
        else:
            print('Checking for ~.smcrc file as SMC credential info was not given')
            session.login()
        print('Successfully logged in to SMC API')

        print("##### NGFW Configuration #####")
        # Get NGFW settings
        ngfw = get_input(NGFW)
        if ngfw.get('vpn'):
            value = ngfw.pop('vpn')
            if value.lower().startswith('true'):
                vpninfo = get_input(OPT_VPN)
                ngfw.update(vpninfo)
        dns=None
        if ngfw.get('dns'):
            dns = ngfw.get('dns').split(',')
            ngfw.update(dns=dns)
       
        # If AV or GTI are enabled, but DNS is not provided, prompt
        if (ngfw.get('gti').lower().startswith('true') or \
            ngfw.get('antivirus').lower().startswith('true')) and not dns:
            print('DNS is required when AV or GTI is enabled')
            dns = get_input([{'dns': field('Enter DNS servers, comma separated',
                                           required=True)}])
            ngfw.update(dns=dns.get('dns').split(','))
        
        yml.update({'NGFW': ngfw})
        
        print("##### AWS Configuration #####")
        data = get_input(AWS)
        if data.get('aws_client').lower().startswith('true'):
            client_ami = get_input(OPT_AWS)
            data.update(client_ami)
        if not data.get('aws_access_key_id') and \
                not data.get('aws_secret_access_key'):
            data.pop('aws_secret_access_key', None)
            data.pop('aws_access_key_id', None)
        yml.update({'AWS': data})
        
        # Prompt for location to write file, default to home dir
        path = get_input(PATH).get('path')
        # Write to yml
        write_cfg_to_yml(yml, path=path)
        return path
        
    except SMCConnectionError:
        print('Failed logging in to SMC. Verify the credentials used are '\
            'correct.')
        raise
    except KeyboardInterrupt:
        sys.exit(1)