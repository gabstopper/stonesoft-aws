'''
NGFW Settings and required methods
'''
import logging
from smc.elements.helpers import location_helper
from smc.vpn.policy import VPNPolicy
from smc.core.engines import Layer3Firewall
from smc.api.exceptions import TaskRunFailed, NodeCommandFailed, LicenseError,\
    LoadEngineFailed, ElementNotFound, LoadPolicyFailed, MissingRequiredInput
from smc.core.engine import Engine
from smc.elements.collection import describe_vpn, describe_fw_policy,\
    describe_location
from smc.elements.other import prepare_contact_address

logger = logging.getLogger(__name__)

class NGFWConfiguration(object):
    
    def __init__(self, name='aws-stonesoft', dns=None, default_nat=True, 
                 antivirus=False, gti=False, location=None,
                 firewall_policy=None, vpn_policy=None,
                 vpn_role='central', reverse_connection=False, 
                 **kwargs):
        self.task = None
        self.engine = None
        self.name = name
        self.dns = dns if dns else []
        self.default_nat = default_nat
        self.antivirus = antivirus
        self.gti = gti
        self.location_ref = location
        self.vpn_role = vpn_role
        self.vpn_policy = vpn_policy
        self.firewall_policy = firewall_policy
        self.reverse_connection = reverse_connection
        self.has_errors = []

    def __call__(self, interfaces, default_gateway):
        """
        Create NGFW
        
        :param list interfaces: dict of interface information
        :return: self
        """
        for interface in interfaces:
            address = interface.get('address')
            interface_id = interface.get('interface_id')
            network_value = interface.get('network_value')
            if interface_id == 0:
                mgmt_ip = address
                mgmt_network = network_value
                engine = Layer3Firewall.create(self.name, 
                                               mgmt_ip, 
                                               mgmt_network,
                                               domain_server_address=self.dns,
                                               reverse_connection=self.reverse_connection, 
                                               default_nat=self.default_nat,
                                               enable_antivirus=self.antivirus,
                                               enable_gti=self.gti,
                                               location_ref=location_helper(self.location_ref))
                engine.add_route(default_gateway, '0.0.0.0/0')
            else:
                engine.physical_interface.add_single_node_interface(interface_id, 
                                                                    address, 
                                                                    network_value)
        logger.info('Created NGFW')

        self.engine = engine.reload()
        #Enable VPN on external interface if policy provided
        if self.vpn_policy:
            for intf in engine.internal_gateway.internal_endpoint.all():
                if intf.name == mgmt_ip:
                    intf.modify_attribute(enabled=True)
            success = VPNPolicy.add_internal_gateway_to_vpn(
                                                    engine.internal_gateway.href, 
                                                    self.vpn_policy, 
                                                    self.vpn_role)
            if not success:
                logger.error('VPN policy: {} specified was not successfully bound. '
                             'This may require manual intervention to push policy from '
                             'the SMC to enable VPN.'.format(self.vpn_policy))

    def queue_policy(self):
        """
        Queue Firewall Policy for firewall. Monitor the upload process from 
        the SMC Administration->Tasks menu
        
        :return: None
        """
        try:
            self.task = next(self.engine.upload(
                                    '{}'.format(self.firewall_policy)))
        except TaskRunFailed as e:
            msg = 'Firewall policy: {} was not successfully bound. '\
                  'This will require manual intervention to push '\
                  'policy from the SMC.Message: {}'\
                  .format(self.firewall_policy, e)
            logger.error(msg)
            self.has_errors.append(msg)
        
    def add_contact_address(self, elastic_ip):
        """
        Add the elastic IP public address as a contact address to the 
        management interface (Interface 0)
        
        :return: None
        """
        for interface in self.engine.interface.all():
            if interface.name == 'Interface 0':
                contact_address = prepare_contact_address(elastic_ip, 
                                                          location='Default')
                interface.add_contact_address(contact_address,
                                              self.engine.etag)

    def initial_contact(self):
        """
        Bind license and return initial contact information
        
        :return: text content for userdata
        """
        for node in self.engine.nodes:
            try:
                userdata = node.initial_contact(enable_ssh=True)
                node.bind_license()
            except (LicenseError, NodeCommandFailed) as e:
                msg = 'Error during initial contact process: {}. '\
                      'You will have to resolve and manually push '\
                      'policy to complete installation.'.format(e)
                logger.error(msg)
                self.has_errors.append(msg)
            return userdata

    def rollback(self):
        """
        Rollback the engine, remove from VPN Policy if it's assigned
        """
        try:
            engine = Engine(self.name).load()
            if self.vpn_policy: #If a policy was specified
                vpn = VPNPolicy(self.vpn_policy)
                vpn.open()
                for gw in vpn.central_gateway_node.all():
                    if gw.name.startswith(self.name):
                        gw.delete()
                vpn.save()
                vpn.close()
            result = engine.delete()
            if result.msg is None:
                logger.info('NGFW deleted successfully')
            else:
                logger.error('Failed deleting NGFW: %s', result.msg)
        except LoadEngineFailed as e:
            logger.error('Failed loading engine, rollback failed: %s', e)
        except ElementNotFound as e:
            logger.error('Failed finding VPN Policy: %s', e)

def monitor_status(engine=None, status='No Policy Installed', 
                   step=10):
        """
        Monitor NGFW initialization. See :py:class:`smc.core.node.NodeStatus` for
        more information on statuses or attributes to monitor/
        
        :param step: sleep interval
        """
        desired_status = status
        import time
        try:
            while True:
                node = engine.nodes[0]
                current = node.status()
                if current.status != desired_status:
                    yield 'NGFW status: {}, waiting..'.format(current.status)
                else:
                    yield 'Initialization complete. Version: {}, State: {}'\
                            .format(current.version, current.state)
                    break
                time.sleep(step)
        except KeyboardInterrupt:
            pass
    
def obtain_vpnpolicy():
    """
    Return available VPN policies
    
    :return: list available VPN Policies
    """
    return [vpn.name for vpn in describe_vpn()]

def obtain_fwpolicy():
    """
    Return layer 3 firewall policies
    
    :return: list available layer 3 firewall policies
    """
    return [policy.name for policy in describe_fw_policy()]

def obtain_locations():
    """
    Return available locations in SMC
    
    :return: list list of defined locations
    """
    return [location.name for location in describe_location()]

def validate(ngfw):
    """
    Validate that settings provided are valid objects in SMC before anything
    is kicked off to AWS
    """
    if not ngfw.firewall_policy in obtain_fwpolicy():
        raise LoadPolicyFailed('Firewall policy not found, name provided: {}'
                               .format(ngfw.firewall_policy))
    if ngfw.vpn_policy:
        if not ngfw.vpn_policy in obtain_vpnpolicy():
            raise LoadPolicyFailed('VPN policy not found, name provided: {}'
                                   .format(ngfw.vpn_policy))
    # Make sure DNS is provided or SMC will reject AV/GTI
    if (ngfw.antivirus or ngfw.gti) and not ngfw.dns:
        raise MissingRequiredInput('Anti-Virus and GTI required DNS servers '
                                   'be specified')
