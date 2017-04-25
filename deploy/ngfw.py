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
from smc.api.exceptions import TaskRunFailed, LicenseError, MissingRequiredInput,\
    DeleteElementFailed, CreatePolicyFailed
from smc.administration.tasks import Task
from smc.actions.search import element_by_href_as_json, element_name_by_href
from smc.policy.layer3 import FirewallPolicy
from smc.core.contact_address import ContactAddress
from smc.elements.servers import ManagementServer, LogServer
from smc.base.collection import Search
from smc.elements.service import TCPService
from smc.elements.network import Alias
from smc.policy.rule_elements import LogOptions, Action

logger = logging.getLogger(__name__)

class NGFWConfiguration(object):
    
    def __init__(self, dns=None, default_nat=True, 
                 antivirus=False, gti=False, location=None,
                 firewall_policy=None, vpn=None,
                 reverse_connection=False, nat_address=None,
                 **kwargs):
        self.engine = None #smc.core.engine.Engine
        self.dns = dns if dns else []
        self.default_nat = default_nat
        self.antivirus = antivirus
        self.gti = gti
        self.location = location #Required if the SMC is behind NAT
        self.nat_address = nat_address
        self.vpn = vpn
        self.firewall_policy = firewall_policy
        self.reverse_connection = reverse_connection
        self.aws_ami_ip = None #IP used for client AMI rules
        self.nat_ports = kwargs.pop('inbound_nat', None)
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
                engine = Layer3Firewall.create(
                    self.name, 
                    mgmt_ip=address, 
                    mgmt_network=network_value,
                    domain_server_address=self.dns,
                    reverse_connection=self.reverse_connection, 
                    default_nat=self.default_nat,
                    enable_antivirus=self.antivirus,
                    enable_gti=self.gti,
                    location_ref=location)
                engine.add_route(default_gateway, '0.0.0.0/0')
            else:
                engine.physical_interface.add_single_node_interface(
                    interface_id=interface_id, 
                    address=address, 
                    network_value=network_value)
   
        logger.info('Created NGFW successfully')
        self.engine = engine
        # Enable VPN on external interface if policy provided
        
        if self.vpn:
            try:
                vpn_policy = self.vpn['vpn_policy']
                for intf in self.engine.internal_gateway.internal_endpoint.all():
                    if intf.name == mgmt_ip:
                        intf.modify_attribute(enabled=True,
                                              nat_t=True)
                    
                role = self.vpn.get('vpn_role') if self.vpn.get('vpn_role') else 'central'
                VPNPolicy.add_internal_gateway_to_vpn(
                    self.engine.internal_gateway.href, 
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
    
    def add_policy(self):
        """
        If a client AMI was specified when building a new VPC, this will add
        rules to allow inbound access to the AMI. This could be extended to 
        more generically support VPN rules.
        """
        if not self.firewall_policy:
            self.firewall_policy = 'AWS_Default'
            # Policy not specified, use the default, or check if hidden setting was specified
            try:
                FirewallPolicy.create(name='AWS_Default', 
                                      template='Firewall Inspection Template')  
            except CreatePolicyFailed:
                pass # Already exists
        
        policy = FirewallPolicy(self.firewall_policy)
        # Create the access rule for the network
        
        options = LogOptions()
        options.log_accounting_info_mode = True 
        options.log_level = 'stored' 
        options.application_logging = 'enforced' 
        options.user_logging = 'enforced'
        
        action = Action()
        action.deep_inspection = True
        action.file_filtering = False
    
        outbound_rule = policy.search_rule('AWS outbound access rule')
        if not outbound_rule:
            # Generic outbound access rule        
            policy.fw_ipv4_access_rules.create(
                name='AWS outbound access rule',
                sources=[Alias('$$ Interface ID 1.net')],
                destinations='any',
                services='any',
                action=action,
                log_options=options)
            
        if self.aws_ami_ip and self.nat_ports:
            dest_port = self.nat_ports.get('dest_port')
            redirect_port = self.nat_ports.get('redirect_port')
            
            services = list(TCPService.objects.filter(dest_port))  # @UndefinedVariable
            # Ignore services with protocol agents so we skip SSM
            service = next(([service] 
                            for service in services 
                            if not service.protocol_agent), [])
            
            if not service:
                service = [TCPService.create(name='aws_tcp{}'.format(dest_port), 
                                             min_dst_port=dest_port)]
            
            # Create the access rule for the client
            policy.fw_ipv4_access_rules.create(
                name=self.name, 
                sources='any', 
                destinations=[Alias('$$ Interface ID 0.ip')], 
                services=service, 
                action='allow',
                log_options=options)
            policy.fw_ipv4_nat_rules.create(
                name=self.name, 
                sources='any', 
                destinations=[Alias('$$ Interface ID 0.ip')], 
                services=service, 
                static_dst_nat=self.aws_ami_ip, 
                static_dst_nat_ports=(dest_port, redirect_port),
                used_on=self.engine.href)
    
    def add_location(self, location_name):
        """
        Create a unique Location for the AWS Firewall if the NAT address is set.
        If nat_address is not set, then location will be None for the engine. 
        This assumes that the SMC is not located behind NAT.
        
        :return: str of location or None
        """
        if self.nat_address: #SMC behind NAT
            # Add to management server
            mgt = list(ManagementServer.objects.filter('Management*'))  # @UndefinedVariable
            for server in mgt:
                server.add_contact_address(self.nat_address, location_name)
            log = list(LogServer.objects.filter('Log*'))  # @UndefinedVariable
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
        contact_addresses = self.engine.contact_addresses(0)
        for interface in contact_addresses: #ContactInterface
            contact_addr = ContactAddress.create(elastic_ip) #Default
            interface.add_contact_address(contact_addr)

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
    firewalls = list(Search('single_fw').objects.all())
    for instance in instance_ids:
        for fw in firewalls:
            if fw.name.startswith(instance):
                # Remove Locations from mgmt / log server
                location_ref = fw.attr_by_name('location_ref')
                location_name = element_name_by_href(location_ref)
                mgt = list(ManagementServer.objects.filter('Management*'))  # @UndefinedVariable
                for server in mgt:
                    server.remove_contact_address(location_name)
                log = list(LogServer.objects.filter('Log*'))  # @UndefinedVariable
                for server in log:
                    server.remove_contact_address(location_name)
                del_from_smc_vpn_policy(fw.name)
                # Quick search to delete rules
                policy = fw.nodes[0].status().installed_policy
                try:
                    if policy: # It's been installed
                        f = FirewallPolicy(policy)
                        search = f.search_rule(fw.name)
                        for rules in search:
                            rules.delete()
                    fw.delete()
                except DeleteElementFailed as e:
                    logger.error('Deleting element failed: %s' % e)
                else:
                    logger.info("Successfully removed NGFW.")

def del_from_smc_vpn_policy(name):
    # Temporary solution - SMC API (6.1.1) does not expose the associated
    # VPN policies on the engine so we need to iterate each VPN policy and
    # look for our engine
    for policyvpn in list(Search('vpn').objects.all()):
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
    policy = [vpn.name for vpn in list(Search('vpn').objects.all())]
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
    
    :param firewall_policy: when called from command line menu, we
        only need the list of options so firewall_policy will be none
    :return: list available layer 3 firewall policies
    """
    policy = [policy.name for policy in list(FirewallPolicy.objects.all())]  # @UndefinedVariable
    if firewall_policy is None:
        return policy
    else:
        if not firewall_policy in policy:
            raise MissingRequiredInput('Firewall policy not found, name provided: '
                                       '{}. Available policies: {}'
                                       .format(firewall_policy, policy))
            
def validate(firewall_policy=None, vpn=None, antivirus=None, 
             gti=None, dns=None, **kwargs):
    """
    Validate that settings provided are valid objects in SMC before anything
    is kicked off to AWS. If Firewall Policy is not provided, bypass the 
    checks that it exists. When instance spins up, a new policy will be 
    created called "Default_AWS". if the policy exists, it will be re-used.
    """
    if firewall_policy is not None:
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