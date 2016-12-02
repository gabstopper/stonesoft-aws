'''
Created on Nov 19, 2016

@author: davidlepage
'''

from deploy.ngfw import NGFWConfiguration

if __name__ == '__main__':

    ngfw = NGFWConfiguration(name='awsfirewall', dns=['8.8.8.8'], default_nat=True,
                             antivirus=True, gti=False, location='Internet',
                             firewall_policy=None, vpn_policy=None)
    

    '''
    interfaces = [{'address': '1.1.1.1',
                  'network_value': '1.1.1.0/24',
                  'interface_id': 0},
                  {'address': '2.2.2.2',
                   'network_value': '2.2.2.0/24',
                   'interface_id': 1}]
    gateway = '1.1.1.254'
    
    ngfw(interfaces, gateway)
    '''
    #session.logout()