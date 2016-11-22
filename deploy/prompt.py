"""
Module handling user keyboard input
"""
import yaml
from smc.api.exceptions import SMCConnectionError

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
            assert fields is not None, "Missing field definitions"
            default = '' if not fields.default else fields.default
            if callable(default):   #list returned from SMC API call
                options = default()
                for entry in options:
                    print(1 + options.index(entry)),
                    print(") " + entry)
                try:
                    user_input = raw_input()
                    if not user_input:
                        print "Field required, try again"
                        pass
                    else:
                        return options[int(user_input)-1]
                except IndexError:
                    print "Invalid choice, try again"
                except ValueError:
                    print "Invalid entry, try again"
            else:
                value = raw_input('{} [{}]: '.format(prompt, default))
                if not str(value):
                    # No value given (user pressed enter)
                    if fields.default:
                        return fields.default
                    elif fields.required:
                        print "Field required, try again"
                        pass    #Need this field
                    else:   #Not required ane empty is ok
                        return ''
                else:
                    return value
        # Choices provided        
        else:
            print prompt
            for entry in choices:
                print(1 + choices.index(entry)),
                print(") " + entry)
            
            try:
                return choices[input()-1]
            except IndexError:
                print "Invalid choice. Try again."

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
            if isinstance(value, str):
                if value.lower() == 'false':
                    fields[key] = False
                elif value.lower() == 'true':
                    fields[key] = True
    # Write to file
    with open(path, 'w') as yaml_file:
        yaml.safe_dump(data, yaml_file, default_flow_style=False)
    print "Wrote ngfw-deploy.yml to dir %s" % path

def prompt_user(path=None):
    """
    Start the prompt to the user. This is useful for the first run 
    through to get the correct yml template format. Returns a dict
    of the data.
    
    :param str path: path to save yml
    :return: dict of prompt items
    """
    from common import NGFW, OPT_VPN, SMC, AWS, OPT_AWS, PATH
    from smc import session
    yml = {}    #For writing to yaml file
    try:
        # SMC settings
        data = get_input(SMC)
        if data.get('smc_address') and data.get('smc_apikey'):
            href = 'http://{}:{}'.format(data.get('smc_address'), data.get('smc_port'))
            session.login(url=href, api_key=data.get('smc_apikey'))
            yml.update({'SMC': data})
        else:
            print "Checking for ~.smcrc file as SMC credential info was not given"
            session.login()
        print "Successfully logged in to SMC API"

        #Get NGFW settings
        data = get_input(NGFW)
        if data.get('vpn'):
            value = data.pop('vpn')
            if value.lower().startswith('true'):
                vpninfo = get_input(OPT_VPN)
                data.update(vpninfo)
        if data.get('dns'):
            dns = data.get('dns').split(',')
            data.update(dns=dns)
        yml.update({'NGFW': data})
        
        data = get_input(AWS)
        if data.get('aws_client').lower().startswith('true'):
            client_ami = get_input(OPT_AWS)
            data.update(client_ami)
        if not data.get('aws_access_key_id') and \
                not data.get('aws_secret_access_key'):
            data.pop('aws_secret_access_key')
            data.pop('aws_access_key_id')
        yml.update({'AWS': data})
        
        # Prompt for location to write file, default to home dir
        path = get_input(PATH).get('path')
        # Write to yml
        write_cfg_to_yml(yml, path=path)
        return path
        
    except SMCConnectionError:
        print "Failed logging in to SMC. Verify credentials and service is running"
        raise
