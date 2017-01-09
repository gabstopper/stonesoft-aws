'''
NGFW Settings and required methods
'''
import uuid
import time
import logging      
from smc import session
from smc.api.configloader import transform_login
from smc.elements.helpers import location_helper
from smc.vpn.policy import VPNPolicy
from smc.core.engines import Layer3Firewall
from smc.api.exceptions import TaskRunFailed, LicenseError, MissingRequiredInput
from smc.administration.tasks import Task
from smc.actions.search import element_by_href_as_json
from smc.elements.collection import describe_vpn, describe_fw_policy,\
    describe_single_fw, describe_mgt_server, describe_log_server
from smc.elements.other import prepare_contact_address

logger = logging.getLogger(__name__)

class NGFWConfiguration(object):
    
    def __init__(self, dns=None, default_nat=True, 
                 antivirus=False, gti=False, location=None,
                 firewall_policy=None, vpn=None,
                 reverse_connection=False, nat_address=None,
                 **kwargs):
        self.engine = None
        self.dns = dns if dns else []
        self.default_nat = default_nat
        self.antivirus = antivirus
        self.gti = gti
        self.location = location #Required if the SMC is behind NAT
        self.nat_address = nat_address
        self.vpn = vpn
        self.firewall_policy = firewall_policy
        self.reverse_connection = reverse_connection
        # Unique temporary name
        uid = uuid.uuid4()
        self.name = uid.hex
        
    def __call__(self, interfaces, default_gateway, location_name):
        """
        Create NGFW
        
        :param list interfaces: dict of interface information
        :return: self
        """
        # Location can be None if SMC is not behind NAT
        location = self.add_location(location_name)
        
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
                                               location_ref=location)
                engine.add_route(default_gateway, '0.0.0.0/0')
            else:
                engine.physical_interface.add_single_node_interface(interface_id, 
                                                                    address, 
                                                                    network_value)
   
        logger.info('Created NGFW successfully')
        self.engine = engine
        # Enable VPN on external interface if policy provided
        if self.vpn:
            try:
                vpn_policy = self.vpn['vpn_policy']
                for intf in engine.internal_gateway.internal_endpoint.all():
                        if intf.name == mgmt_ip:
                            intf.modify_attribute(enabled=True)
                            intf.modify_attribute(nat_t=True)
                    
                role = self.vpn.get('vpn_role') if self.vpn.get('vpn_role') else 'central'
                VPNPolicy.add_internal_gateway_to_vpn(engine.internal_gateway.href, 
                                                      vpn_policy, 
                                                      role)
            except KeyError:
                pass
            
    def __copy__(self):
        clone = type(self)()
        clone.__dict__.update(self.__dict__)
        clone.network_interface = []
        return clone
    
    def rename(self, name):
        """
        Rename NGFW to instance_id (availability zone)
        """
        self.name = name
        self.engine.rename(name)
        
    def upload_policy(self):
        """
        Upload policy to engine. This is executed after initial contact
        has succeeded so it's not queued. Monitor the upload process from 
        the SMC Administration->Tasks menu
        
        :return: `smc.actions.tasks.Task` follower link
        """
        try:
            return next(self.engine.upload('{}'.format(self.firewall_policy)))
        except TaskRunFailed as e:
            logger.error(e)
    
    def add_location(self, location_name):
        """
        Create a unique Location for the AWS Firewall if the NAT address is set.
        If nat_address is not set, then location will be None for the engine. 
        This assumes that the SMC is not located behind NAT.
        
        :return: str of location or None
        """
        #TODO: If vpn policy isnt required, use a common NAT element?
        if self.nat_address: #SMC behind NAT
            # Add to management server
            mgt = describe_mgt_server()
            for server in mgt:
                server.add_contact_address(self.nat_address, location_name)
            log = describe_log_server()
            for server in log:
                server.add_contact_address(self.nat_address, location_name)
            return location_helper(location_name)
    
    def add_contact_address(self, elastic_ip):
        """
        Add the elastic IP public address as a contact address to the 
        management interface (Interface 0). This allows SMC to contact
        the NGFW using the elastic address.
        
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
        Bind license and return initial contact information. Will be generated
        with the location set so NGFW knows how to contact the SMC from a public
        NAT address.
        
        :return: text content for userdata
        :raises: `smc.api.exceptions.NodeCommandFailed`
        """
        node = self.engine.nodes[0]
        userdata = node.initial_contact(enable_ssh=True)
        return userdata

    def bind_license(self):
        """
        Bind license. If this fails, still deploy, and policy push will complain
        that the node is not licensed and require a manual license be attached
        and policy pushed.
        
        :return: None
        """
        node = self.engine.nodes[0]
        try:
            node.bind_license()
        except(LicenseError) as e:
            logger.error(e)
    
    def get_waiter(self, status='Configured'):
        """
        Wait for initial contact
        """
        logger.info('Waiting for initial contact from: {}'.format(self.engine.name))
        start_time = time.time()
        node = self.engine.nodes[0]
        while True:
            state = node.status()
            logger.debug('Node: {} status {}'.format(node.name, state.configuration_status))
            if status == state.configuration_status:
                logger.info("Initial contact: '%s' took: %s seconds" % \
                            (node.name, time.time() - start_time))
                yield self
            yield None

    def policy_waiter(self, follower):
        """
        Wait for policy upload
        """
        logger.info('Uploading policy for {}..'.format(self.engine.name))
        start_time = time.time()
        while True:
            reply = Task(**element_by_href_as_json(follower))
            if reply.progress:
                logger.info('[{}]: policy progress -> {}%'.format(self.engine.name, 
                                                                  reply.progress))
            if not reply.in_progress:
                logger.info('Upload policy task completed for {} in {} seconds'
                            .format(self.engine.name, time.time() - start_time))
                if not reply.success:
                    yield [reply.last_message]
                else:
                    yield []
            yield None
                       
def del_fw_from_smc(instance_ids):
    """
    FW name is 'instance_id (availability zone). To do proper cleanup,
    remove the FW instance after terminating the EC2 instance.
    
    :param list instance_ids: string of instance ids
    :return: None
    """
    firewalls = describe_single_fw() # FW List
    for instance in instance_ids:
        for fw in firewalls:
            if fw.name.startswith(instance):
                # Remove Locations from mgmt / log server
                fw.load()
                location_ref = fw.get_attr_by_name('location_ref')
                mgt = describe_mgt_server()
                for server in mgt:
                    server.remove_contact_address(location_ref)
                log = describe_log_server()
                for server in log:
                    server.remove_contact_address(location_ref)
                del_from_smc_vpn_policy(fw.name)
                response = fw.delete()
                if response.msg:
                    logger.error('Could not delete fw: {}, {}'
                                 .format(fw.name, response.msg))
                else:
                    logger.info("Successfully removed NGFW.")

def del_from_smc_vpn_policy(name):
    # Temporary solution - SMC API (6.1.1) does not expose the associated
    # VPN policies on the engine so we need to iterate each VPN policy and
    # look for our engine
    for policyvpn in describe_vpn():
        policyvpn.open()
        for gw in policyvpn.central_gateway_node.all():
            if gw.name.startswith(name):
                gw.delete()
                policyvpn.save()
                policyvpn.close()
                return
        for gw in policyvpn.satellite_gateway_node.all():
            if gw.name.startswith(name):
                gw.delete()
                policyvpn.save()
                policyvpn.close()
                return
        policyvpn.close()

def obtain_vpnpolicy(vpn_policy=None):
    """
    Return available VPN policies
    
    :return: list available VPN Policies
    """
    policy = [vpn.name for vpn in describe_vpn()]
    if vpn_policy is None:
        return policy
    else:
        if not vpn_policy in policy:
            raise MissingRequiredInput('VPN policy not found, name provided: '
                                        '{}. Available policies: {}'
                                        .format(vpn_policy, policy))

def obtain_fwpolicy(firewall_policy=None):
    """
    Return layer 3 firewall policies
    
    :return: list available layer 3 firewall policies
    """
    policy = [policy.name for policy in describe_fw_policy()]
    if firewall_policy is None:
        return policy
    else:
        if not firewall_policy in policy:
            raise MissingRequiredInput('Firewall policy not found, name provided: '
                                       '{}. Available policies: {}'
                                       .format(firewall_policy, policy))
            
    return [policy.name for policy in describe_fw_policy()]

def validate(firewall_policy, vpn=None, antivirus=None, 
             gti=None, dns=None, **kwargs):
    """
    Validate that settings provided are valid objects in SMC before anything
    is kicked off to AWS
    """
    obtain_fwpolicy(firewall_policy)
    if vpn is not None:
        try:
            vpn_policy = vpn['vpn_policy']
            obtain_vpnpolicy(vpn_policy)
        except KeyError:
            raise MissingRequiredInput('VPN setting present but missing vpn_policy.')
    # Make sure DNS is provided or SMC will reject AV/GTI
    if (antivirus or gti) and not dns:
        raise MissingRequiredInput('Anti-Virus and GTI require that DNS servers '
                                   'be specified')

def get_smc_session(smc):
    """
    Get SMC session and validate settings exist
    
    :raises: smc.api.exceptions.SMCConnectionError on failure
    """
    if smc:
        if smc.get('smc_address') and smc.get('smc_apikey'):
            session.login(**transform_login(smc))
        else:
            session.login()
    else:
        session.login()
    logger.debug("Successful connection to SMC")