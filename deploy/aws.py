"""
AWS Related Configuration
"""
import time
from collections import namedtuple
import ipaddress
import boto3
import botocore.exceptions
from deploy.validators import custom_choice_menu
from deploy.ngfw import del_fw_from_smc
import logging
from smc.api.exceptions import MissingRequiredInput

ec2 = None

logger = logging.getLogger(__name__)

class VpcConfiguration(object):
    """ 
    VpcConfiguration models the data to correlate certain aspects of an 
    AWS VPC such as VPC ID, associated subnets, and network interfaces and uses the boto3
    services model api.
    
    If the class is instantiated without a VPC id, the default VPC will be used. If a
    VPC is specified, it is loaded along with any relevant settings needed to configure
    and spin up a NGFW instance.
    
    Note that operations performed against AWS are not idempotent, so if there is a 
    failure, changes made would need to be undone.
    
    Instance attributes:
    
    :ivar vpcid: ID of the VPC
    :ivar vpc: Reference to the VPC object
    :ivar alt_route_table: reference to the alternate route table for private networks
    :ivar elastic_ip: Elastic IP address, will be used for contact address
    :ivar private_subnet: Private subnet used to spin up client instance
    :ivar internet_gateway: AWS internet gateway object reference
    :ivar network_interface: list of dict holding interface index, network
    :ivar availability_zone: AWS AZ for placement
     
    :param vpcid: VPC id
    """
    def __init__(self, vpcid=None):
        self.vpcid = vpcid
        self.vpc = None
        self.elastic_ip = None
        self.public_subnet = None
        self.private_subnet = None
        self.alt_route_table = None
        self.network_interface = [] #[{interface_id: ec2.NetworkInterface}]
        self.availability_zone = None
    
    def load(self):
        if not self.vpcid:
            default_vpc = ec2.vpcs.filter(Filters=[{
                                            'Name': 'isDefault',
                                            'Values': ['true']}])
            for v in default_vpc:
                self.vpc = v
        else:
            for _ in range(5):
                try:
                    self.vpc = ec2.Vpc(self.vpcid)
                    logger.info('State of VPC: {}'.format(self.vpc.state))
                    break
                except botocore.exceptions.ClientError:
                    time.sleep(2)
            
        logger.info('Loaded VPC with id: {} and cidr_block: {}'
                    .format(self.vpc.vpc_id, self.vpc.cidr_block))
        return self
   
    @classmethod
    def create(cls, vpc_subnet, instance_tenancy='default'):
        """ Create new VPC with internet gateway and default route
        * Create the VPC
        * Create internet gateway
        * Attach internet gateway to VPC
        * Create route in main route table for all outbound to igw
        
        :param vpc_subnet: VPC cidr for encapsulated subnets
        :param instance_tenancy: 'default|dedicated|host'
        :returns: self
        """
        vpc_new = ec2.create_vpc(CidrBlock=vpc_subnet,
                                 InstanceTenancy=instance_tenancy)
        logger.info('Created VPC: {}'.format(vpc_new.vpc_id))
        
        aws = VpcConfiguration(vpc_new.vpc_id).load()
        
        internet_gateway = ec2.create_internet_gateway()
        
        logger.info('Created internet gateway: {}'
                    .format(internet_gateway.id))
        
        # Attach internet gateway to VPC
        internet_gateway.attach_to_vpc(VpcId=aws.vpc.vpc_id)
        
        # Main route table is automatically created
        main_rt = list(aws.vpc.route_tables.filter(Filters=[{
                                                    'Name': 'association.main',
                                                    'Values': ['true']}]))
        if main_rt:
            main_rt[0].create_route(DestinationCidrBlock='0.0.0.0/0',
                                    GatewayId=internet_gateway.id)
        else:
            raise botocore.exceptions.ClientError('Cannot find default route table')

        return aws

    def create_network_interface(self, interface_id, cidr_block=None,
                                 ec2_subnet=None, availability_zone=None, 
                                 description=''):
        """
        Create a network interface to be used for the NGFW AMI
        This involves several steps: 
        * Create the public /28 subnet (or use ec2_subnet existing subnet)
        * Create the network interface for subnet
        * Disable SourceDestCheck on the network interface
        * Create elastic IP and bind (only to interface eth0)
        
        NGFW will act as a gateway to the private networks and will have 
        default NAT enabled.
        Interface 0 will be attached to the AWS interface eth0 which will
        be bound to the AWS Internet GW for inbound / outbound routing. The
        static IP address for eth0 will be calculated based on the network address
        broadcast -1.
        See AWS doc's for reserved addresses in a VPC:
        http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Subnets.html
        
        :param int interface_id: id to assign interface
        :param cidr_block: cidr of subnet to create
        :param ec2.Subnet ec2_subnet: existing ec2 subnet to use
        :param availability_zone: Use for existing subnets to ensure public /28 network
               is in the same availability zone
        :param description: description on interface
        :raises: botocore.exception.ClientError
        
        .. note:: When cidr_block is specified, a subnet will be created using this
                  value. If ec2_subnet is specified, this existing subnet will be used
        """
        if not cidr_block and not ec2_subnet:
            raise ValueError('You must specify a cidr to create or existing ec2 subnet')
        
        if cidr_block:
            subnet = self.create_subnet(cidr_block, availability_zone)
            wait_for_resource(subnet, self.vpc.subnets.all())
        else:
            subnet = ec2_subnet
    
        #Assign static address and elastic to eth0 (public)
        if interface_id == 0:
            external = ipaddress.ip_network(u'{}'.format(cidr_block))
            external = str(list(external)[-2]) #broadcast address -1
            interface = subnet.create_network_interface(PrivateIpAddress=external,
                                                        Description=description)
            # Wait to make sure it's available
            wait_for_resource(interface, self.vpc.network_interfaces.all())
            self.network_interface.append({interface_id: interface})
            
            # Set elastic and associate
            allocation_id = self.allocate_elastic_ip()
            address = ec2.VpcAddress(allocation_id)
            address.associate(NetworkInterfaceId=interface.network_interface_id)
            self.public_subnet = subnet
        else: 
            # This attaches to private side networks
            interface = subnet.create_network_interface(Description=description)
            wait_for_resource(interface, self.vpc.network_interfaces.all())
            
            self.network_interface.append({interface_id: interface})
            self.private_subnet = subnet
            
            alt_route_table = self.vpc.create_route_table()
            alt_route_table.create_tags(Tags=create_tag())
            self.alt_route_table = alt_route_table
            
            logger.info('Associating subnet ID: {} to alternate route table'
                        .format(subnet.subnet_id))
            try:
                alt_route_table.associate_with_subnet(SubnetId=subnet.subnet_id)
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'Resource.AlreadyAssociated':
                    # Subnet is already associated with a non-Main route table.
                    # To preserve the configuration, create rules that were manually
                    # created and add a stonesoft tag value = pre-existing route table.
                    # This allows the route table to be mapped back if NGFW is removed.
                    filter_rt = list(ec2.route_tables.filter(Filters=[{
                                                                'Name': 'association.subnet-id',
                                                                'Values': [subnet.subnet_id]}]))
                    assigned_rt = filter_rt.pop()
                    logger.warning('{} is already associated with route table: {}'
                                   .format(subnet.subnet_id, assigned_rt.id))
                    for route in assigned_rt.routes:
                        # Copy manually created routes
                        if route.origin == 'CreateRoute' and \
                            route.destination_cidr_block != '0.0.0.0/0':
                            self.alt_route_table.create_route(
                                    DestinationCidrBlock=route.destination_cidr_block,
                                    GatewayId=route.gateway_id)
                                    #InstanceId='',
                                    #NetworkInterfaceId='')
                        # Disassociate the existing route table
                        for assoc in assigned_rt.associations.all():
                            if assoc.subnet_id == subnet.subnet_id:
                                logger.info('Removing route tbl assoc: {} for subnet: {}'
                                            .format(assoc.route_table_id, assoc.subnet_id))
                                assoc.delete()
                        # Associate it to our table with tag: {'stonesoft': original_route_table_id}
                        alt_route_table.associate_with_subnet(SubnetId=subnet.subnet_id)
                        # Add original route table ID to stonesoft tag
                        alt_route_table.create_tags(Tags=create_tag(value=assigned_rt.id))
            
            logger.info('Setting default route using alternate route table for '
                        'interface {}'.format(interface.network_interface_id))
            alt_route_table.create_route(DestinationCidrBlock='0.0.0.0/0',
                                         NetworkInterfaceId=interface.network_interface_id)
          
        interface.modify_attribute(SourceDestCheck={'Value': False})
        self.availability_zone = interface.availability_zone
        
        logger.info('Finished creating and configuring network interface: {}, '
                    'subnet_id: {}, address: {}'
                    .format(interface.network_interface_id, interface.subnet_id,
                            interface.private_ip_address))

    def create_subnet(self, cidr_block, az=None):
        """
        Create a subnet, add stonesoft tag
        
        :return: ec2.Subnet
        """
        az = '' if not az else az
        subnet = ec2.create_subnet(VpcId=self.vpc.vpc_id,
                                   CidrBlock=cidr_block,
                                   AvailabilityZone=az)
        logger.info('Created subnet: {}, in availablity zone: {}'
                    .format(subnet.subnet_id, subnet.availability_zone))
        subnet.create_tags(Tags=create_tag())
        return subnet

    def allocate_elastic_ip(self):
        """ 
        Create elastic IP address for network interface. An elastic IP is
        used for the public facing interface for the NGFW AMI
        
        :return: AllocationId (elastic IP reference)
        """
        eip = None
        try:
            eip = ec2.meta.client.allocate_address(Domain='vpc')
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'AddressLimitExceeded':
                #Try to find unassigned or re-raise
                addresses = ec2.meta.client.describe_addresses().get('Addresses')
                for unassigned in addresses:
                    if not unassigned.get('NetworkInterfaceId'):
                        logger.info('Unassigned Elastic IP found: {}'
                                    .format(unassigned.get('AllocationId')))
                        eip = unassigned
                        break
                if not eip: raise
                self.elastic_ip = eip.get('PublicIp')
                return eip.get('AllocationId')
            else: raise
         
    def __call__(self):
        """
        Retrieve interface map information for NGFW
        """
        interfaces = []
        for intf in self.network_interface:
            for idx, obj in intf.items():
                interfaces.append({'interface_id': idx,
                                   'address': obj.private_ip_address,
                                   'network_value': obj.subnet.cidr_block})
                if idx == 0:
                    #default gateway is first IP on network subnet
                    gateway = ipaddress.ip_network(u'{}'.format(obj.subnet.cidr_block))
                    gateway = str(list(gateway)[1])
        return (interfaces, gateway)
        
    def __copy__(self):
        clone = type(self)()
        clone.__dict__.update(self.__dict__)
        clone.network_interface = []
        return clone
                                   
    def launch(self, key_pair, userdata=None, 
               imageid=None, 
               instance_type='t2.micro'):
        """
        Launch the instance
        
        :param key_name: keypair required to enable SSH to AMI
        :param userdata: optional, but recommended
        :param imageid: NGFW AMI id
        :param availability_zone: where to launch instance
        :return: instance
        """
        logger.info('Launching ngfw as {} instance into availability zone: {}'
                    .format(instance_type, self.availability_zone))
          
        interfaces = []
        for interface in self.network_interface:
            for idx, network in interface.items():
                interfaces.append({'NetworkInterfaceId': network.network_interface_id,
                                   'DeviceIndex': idx})
       
        #create run instance
        instance = ec2.create_instances(ImageId=imageid,
                                        MinCount=1,
                                        MaxCount=1,
                                        InstanceType=instance_type,
                                        KeyName=key_pair,
                                        Placement={'AvailabilityZone': 
                                                   self.availability_zone},
                                        NetworkInterfaces=interfaces,
                                        UserData=userdata)
        return instance[0]
        
    def rollback(self):
        """ 
        In case of failure, convenience to wrap in try/except and remove
        the VPC. If there is a running EC2 instance, this will terminate
        that instnace, remove all other dependencies and delete the VPC.
        Typically this is best run when attempting to create the entire
        VPC.
        """
        for instance in self.vpc.instances.filter(Filters=[{
                                    'Name': 'instance-state-name',
                                    'Values': ['running', 'pending', 'stopped']}]):
            logger.info("Terminating instance: {}".format(instance.instance_id))
            instance.terminate()
            waiter = ec2.meta.client.get_waiter('instance_terminated')
            waiter.wait(InstanceIds=[instance.id])
        # Network interfaces
        for intf in self.vpc.network_interfaces.all():
            intf.delete()
        # Subnets
        for subnet in self.vpc.subnets.all():
            subnet.delete()
        # Dump route tables
        for rt in self.vpc.route_tables.all():
            if not rt.associations_attribute:
                rt.delete()
            else:
                for current in rt.associations_attribute:
                    if not current or current.get('Main') is False:
                        rt.delete()
        # Internet gateway
        for igw in self.vpc.internet_gateways.all():
            igw.detach_from_vpc(VpcId=self.vpc.vpc_id)
            igw.delete()
        # Delete security group
        try:
            grp = list(self.vpc.security_groups.filter(Filters=[{
                                                    'Name': 'group-name',
                                                    'Values': ['stonesoft-sg']}]))
            if grp:
                grp[0].delete()
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'InvalidGroup.NotFound':
                pass
            else: raise
        self.vpc.delete()
        logger.info("Deleted vpc: {}".format(self.vpc.vpc_id))

def rollback_existing_vpc(vpc, subnet):
    """
    If a failure occurs during injection into AWS VPC, 
    reverse the changes back to original
    """
    if vpc.alt_route_table:
        if vpc.alt_route_table.associations:
            for assoc in vpc.alt_route_table.associations.all():
                if assoc.subnet_id in subnet.id:
                    logger.info('Removing route tbl assoc: {} for subnet: {}'
                                .format(assoc.route_table_id, assoc.subnet_id))
                    assoc.delete()
            vpc.alt_route_table.delete()
        else:
            vpc.alt_route_table.delete()
    
    for intf in vpc.network_interface:
        for _, interface in intf.items():
            interface.delete()
                
    if vpc.public_subnet:
        vpc.public_subnet.delete()

def authorize_security_group_ingress(security_group, from_cidr_block, 
                                     ip_protocol='-1'):
        """ 
        Creates an inbound rule to allow access from public that will
        be redirected to the virtual FW
        For protocols, AWS references:
        http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
        
        :param ec2.SecurityGroup security_group: group reference
        :param cidr_block: network (src 0.0.0.0/0 from internet)
        :param protocol: protocol to allow (-1 for all)
        """
        security_group = ec2.SecurityGroup(security_group.id)
        try:
            security_group.authorize_ingress(CidrIp=from_cidr_block,
                                             IpProtocol=ip_protocol)
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'InvalidPermission.Duplicate':
                pass
            else: raise

def create_security_group(vpc, name='stonesoft-sg', description='stonesoft ngfw'):
        """
        Create security group specific for inbound traffic. Each VPC will have it's own
        security group that will be applied only to the public network interface. 
        If existing VPC with multiple ngfw's are deployed, the same security group is 
        used.
        
        :param ec2.Vpc vpc: VPC reference
        :return: ec2.SecurityGroup
        """
        try:
            groupid = ec2.create_security_group(GroupName=name,
                                                Description=description,
                                                VpcId=vpc.id)
            return groupid
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'InvalidGroup.Duplicate':
                logger.info("Security group already exists, skipping")
                grp = list(vpc.security_groups.filter(Filters=[{
                                                        'Name': 'group-name',
                                                        'Values': [name]}]))
                return grp[0]
            else: raise

def create_tag(key='stonesoft', value=''):
    """
    Tags are applied to instances, route tables and subnets
    """
    return [{'Key': key,
             'Value': value}]

def wait_for_resource(resource, iterable):
    """
    Wait for the resource to become available. If the AWS newly created
    component isn't available right away and a reference call is
    made the AWS client may throw an exception that it doesn't exist. 
    It appears to be a timing issue on their backend on laggy AZ's.
    This checks the iterable for the component id before continuing. 
    Insert this where you might need to introduce a short delay.
    
    :param resource: ec2.Subnet, ec2.NetworkInterface (has an 'id' attr)
    :param iterable: iterable function
    :return: None
    """
    for _ in range(5):
        for _id in iterable:
            if resource.id == _id.id:
                return
            time.sleep(2)
   
def spin_up_host(key_pair, vpc, instance_type='t2.micro',
                 aws_client_ami='ami-2d39803a'):
    """
    Create an internal amazon host on private subnet for testing
    Use ubuntu AMI by default
    """
    logger.info('Spinning up client instance on private subnet: {}'
                .format(vpc.private_subnet.id))
    instance = ec2.create_instances(ImageId=aws_client_ami,
                                    MinCount=1,
                                    MaxCount=1,
                                    SubnetId=vpc.private_subnet.id,
                                    InstanceType=instance_type,
                                    KeyName=key_pair,
                                    Placement={'AvailabilityZone': 
                                                vpc.availability_zone})
    instance = instance[0]
    for data in instance.network_interfaces_attribute:
        ntwk = data.get('PrivateIpAddress')
    logger.info('Client instance created: {} with keypair: {} at ipaddress: {}'
                .format(instance.id, instance.key_name, ntwk))
    
def list_tagged_instances(vpc):
    """
    Instances tagged with 'stonesoft'
    
    :return: list ec2.Instance
    """
    instances = []
    for instance in vpc.instances.filter(Filters=[{
                                            'Name': 'tag-key',
                                            'Values': ['stonesoft']},{
                                            'Name': 'instance-state-name',
                                            'Values': ['running', 'pending', 'stopped']}]):
        instances.append(instance)
    return instances

def list_tagged_subnets(vpc):
    """
    Subnets tagged with 'stonesoft'
    
    :return: list ec2.Subnet
    """
    subnets = []
    for subnet in vpc.subnets.filter(Filters=[{
                                        'Name': 'tag-key',
                                        'Values': ['stonesoft']}]):
        subnets.append(subnet)
    return subnets

def list_tagged_rtables(vpc):
    """
    Route tables tagged with 'stonesoft'
    
    :return: list ec2.RouteTable
    """
    rtables = []
    for rtable in vpc.route_tables.filter(Filters=[{
                                            'Name': 'tag-key',
                                            'Values': ['stonesoft']}]):
        rtables.append(rtable)
    return rtables

def list_unused_subnets(vpc):
    """
    An unused subnet is one that does use a tagged route table or
    is tagged itself.
    
    :return: list ec2.Subnet
    """
    all_subnets = [subnet.id for subnet in list_all_subnets(vpc)]
    used = []
    for rt in list_tagged_rtables(vpc):
        if rt.associations:
            for assoc in rt.associations.all():
                used.append(assoc.subnet_id)
    # Add tagged subnets
    used.extend([tagged.id for tagged in list_tagged_subnets(vpc)])
    return [ec2.Subnet(avail) for avail in all_subnets if avail not in used]

def list_all_subnets(vpc):
    """
    All subnets regardless of tagging
    
    :return: list ec2.Subnet
    """
    return list(vpc.subnets.all())

def installed_as_list_view(vpc):
    """
    Data visible from --list option
    
    :return: tuple (instance.id, avail_zone, state, launch_time)
    """
    instances = []
    for instance in list_tagged_instances(vpc):
        instance_id = instance.id
        azone = instance.subnet.availability_zone
            
        dt = '{:{dfmt} {tfmt}}'.format(instance.launch_time, dfmt='%Y-%m-%d', tfmt='%H:%M %Z')
        instances.append((instance_id, azone, instance.instance_type,
                          instance.state.get('Name'), dt))
    return instances        

def select_vpc(prompt='View available VPC configurations:',
               as_instance=False):
    """
    Prompt for VPC selection
    
    :param boolean as_instance: type to return
    :return: ec2.Vpc or choice string
    """
    vpcs = ['{} ({})'.format(x.id,x.cidr_block) for x in ec2.vpcs.filter()]
    choice = custom_choice_menu(prompt, vpcs)
    if not as_instance:
        return choice.split(' ')[0]
    else:
        return ec2.Vpc(choice.split(' ')[0])

def select_instance(instances, prompt='Remove NGFW instances;',
                    as_instance=False):
    """
    Instance prompt selection for removals
    
    :param list ec2.Instance: call to list_tagged_instances 
    :param boolean as_instance: type to return
    :return: list ec2.Instance or choice string
    """
    inst = ['{} ({})'.format(inst.id, inst.subnet.availability_zone) for inst in instances]
    inst.append('all')
    choice = custom_choice_menu(prompt, inst).split(' ')[0]
    if choice == 'all':
        if as_instance:
            return instances
        else:
            return [inst.id for inst in instances]
    else:
        if as_instance:
            return [inst for inst in instances if inst.id == choice]
        else:
            return [inst.id for inst in instances if inst.id == choice]

def select_unused_subnet(vpc, prompt='Available subnets;',
                         as_instance=False):
    """
    Prompt with subnets not using ngfw bindings
    
    :param ec2.Vpc
    :param boolean as_instance: type to return
    :return: list ec2.Instance or string choice
    """
    unused_subnets = list_unused_subnets(vpc)
    lst = ['{} ({})'.format(x.cidr_block, x.availability_zone) for x in unused_subnets]
    if lst:
        lst.append('all')
    else: return [] # No remaining
    choice = custom_choice_menu(prompt, lst).split(' ')[0]
    if choice == 'all':
        if as_instance:
            return unused_subnets
        else:
            return [subnet.id for subnet in unused_subnets]
    else:
        if as_instance:
            return [subnet for subnet in unused_subnets if subnet.cidr_block == choice]
        else:
            return [subnet.id for subnet in unused_subnets if subnet.cidr_block == choice]

def select_delete_vpc(prompt='Enter a VPC to remove: '):
    """
    Prompt for VPC to delete
    
    :return: choice string
    """
    vpcs = [x.id +' '+ x.cidr_block for x in ec2.vpcs.filter()]
    return custom_choice_menu(prompt, vpcs).split(' ')[0]    
            
def next_available_subnet(az_subnets=None, vpc_cidr=None):
    """
    Pull the available /28 addresses for public address space on
    external side of NGFW. This is called before creating a ngfw
    in an existing VPC.
    
    Expand out VPC subnet into /28 networks and start iterating
    from the high end side of the subnet (i.e. 172.16.0.0/16 would
    start at 172.16.255.240/28, etc). Compare the /28 with the 
    existing subnets to ensure there is no overlap and if not, 
    return that subnet for use.
    
    :param ec2.Subnet az_subnets: existing ec2.Subnet objects
    :param vpc_cidr: full cidr for VPC
    """
    # All /28 addresses in the VPC network as ipaddress.IPv4Network
    public = list(ipaddress.ip_network(u'{}'.format(vpc_cidr)).subnets(new_prefix=28))
   
    # Turn ec2.Subnet into ipaddress.IPv4Network for comparison
    subnet_cidrs = [ipaddress.ip_network(u'{}'.format(cidr.cidr_block)) for cidr in az_subnets]
    for network in reversed(public):
        used = False
        for existing in subnet_cidrs:
            # Check all subnets to see if this is used
            if ipaddress.ip_network(network).overlaps(existing):
                used = True
                break
            else:
                used = False
        if not used:
            yield str(network)
    
def remove_ngfw_from_vpc(instances):
    """
    Instances should all be in the same VPC. 
    Tags are used on subnets, route tables and instances to find stonesoft
    related components and stop in the right order. When route tables are 
    removed, existing subnets will revert to using the Main route table.
    
    :param list ec2.Instance: call from select_instance(list_tagged_instances)
    """
    if not instances: return
   
    vpc = instances[0].vpc
    
    logger.info('Remove instances: {}'.format(instances))

    # Subnet's are last to be removed
    removeables, untagged_subnets = ([] for i in range(2))
    
    tagged_subnets = [tagged.id for tagged in list_tagged_subnets(vpc)]

    for instance in instances:
    
        for dependency in instance.network_interfaces:           
            dependency.modify_attribute(Attachment={
                                    'AttachmentId': dependency.attachment['AttachmentId'],
                                    'DeleteOnTermination': True})

            subnet = dependency.subnet_id
            if subnet in tagged_subnets:
                removeables.append(subnet)
            else:
                untagged_subnets.append(subnet)
        
        logger.info('Terminating instance: {}'.format(instance.instance_id))
        instance.terminate()
    
    # Remove association of route tables created before deleting them. If an existing
    # subnet had a previous route table assigned, it will be reassigned.
    for rt in list_tagged_rtables(vpc):
        if rt.associations:
            for assoc in rt.associations.all():
                if assoc.subnet_id in untagged_subnets:
                    logger.info('Removing route tbl assoc: {} for subnet: {}'
                                .format(assoc.route_table_id, assoc.subnet_id))
                    assoc.delete()
                    # If stonesoft tag value exists with a previous route table 
                    # association, re-map it
                    if rt.tags[0]['Value']:
                        logger.info('Reassociating subnet: {} with original route '
                                    'table: {}'.format(assoc.subnet_id, rt.tags[0]['Value']))
                        try:
                            original_rt = ec2.RouteTable(rt.tags[0]['Value'])
                            original_rt.associate_with_subnet(SubnetId=assoc.subnet_id)
                        except botocore.exceptions.ClientError as e:
                            logger.error('Error reassigning route table. Will default back '
                                         'to main route table: {}'.format(e))
                    rt.delete()
        else:
            rt.delete()

    instance_ids = [ec2_instance.id for ec2_instance in instances]
    
    waiter = ec2.meta.client.get_waiter('instance_terminated')
    logger.info('Waiting for instances to fully terminate...This can take a few minutes.')
    waiter.wait(InstanceIds=instance_ids)
    # Remove after instance termination 
    for subnet in removeables:
        ec2.Subnet(subnet).delete()
    
    del_fw_from_smc(instance_ids)
    
    logger.info('Completed successfully.')  

def validate_aws(awscfg):
    """
    VPC settings required for creating a VPC
    """
    missing = []
    if not awscfg.vpc_subnet:
        missing.append('vpc_subnet')
    if not awscfg.vpc_private:
        missing.append('vpc_private')
    if not awscfg.vpc_public:
        missing.append('vpc_public')
    if missing:
        raise MissingRequiredInput('Missing required settings in configuration: {}'
                                   .format(missing))
    
aws = namedtuple('aws', 'aws_keypair ngfw_ami aws_access_key_id aws_secret_access_key\
                         aws_client vpc_public vpc_private vpc_subnet aws_instance_type\
                         aws_region')

def AWSConfig(aws_keypair, ngfw_ami, 
              aws_access_key_id=None, 
              aws_secret_access_key=None,
              aws_client=False, 
              vpc_public=None, 
              vpc_private=None, 
              vpc_subnet=None,
              aws_instance_type='t2.micro', 
              aws_region=None, **kwargs):
    return aws(aws_keypair, ngfw_ami, aws_access_key_id, aws_secret_access_key,
               aws_client, vpc_public, vpc_private, vpc_subnet, aws_instance_type, aws_region)

def get_ec2_client(awscfg, prompt_for_region=False):
    """
    Strategy to obtain credentials for EC2 operations (in order):
    * Check for AWS credentials in YAML configuration
    * If credentials found in YAML but no region specified, prompt for region
    * Check for credentials via normal boto3 AWS options, i.e ~/.aws/credentials, etc
    For more on boto3 credential locations, see:   
    http://boto3.readthedocs.io/en/latest/guide/quickstart.html#configuration
    
    :param AWSConfiguration awscfg: instance of aws configuration
    :param boolean prompt_for_region: command line call, allow prompt if None
    :raises: botocore.exceptions.ClientError: various client error during validation
    :return: ec2 client
    """
    global ec2
    # Raises NoRegionError
    if awscfg.aws_access_key_id and awscfg.aws_secret_access_key:
        if prompt_for_region:
            if not awscfg.aws_region:
                aws_session = boto3.session.Session()
                region = custom_choice_menu('Enter a region:', 
                                            aws_session.get_available_regions('ec2'))
        ec2 = boto3.resource('ec2',
                             aws_access_key_id=awscfg.aws_access_key_id,
                             aws_secret_access_key=awscfg.aws_secret_access_key,
                             region_name=region)
    else:
        # Resolve AWS credentials using normal boto3 methods
        s = boto3.session.Session()
        logger.debug("Using boto3 for credentials, found: %s" % s.available_profiles)
        access_key = s.get_credentials().access_key
        secret_key = s.get_credentials().secret_key
        region = s.region_name
        if not region:
            region = custom_choice_menu('Enter a region:', 
                                        s.get_available_regions('ec2'))
        logger.debug('Connecting to region: {}'.format(region))
        ec2 = boto3.resource('ec2',
                             aws_access_key_id=access_key,
                             aws_secret_access_key=secret_key,
                             region_name=region)
        
    logger.debug('Obtained ec2 client: %s' % ec2)
    # Verify the AWS key pair exists, raises InvalidKeyPair.NotFound
    ec2.meta.client.describe_key_pairs(KeyNames=[awscfg.aws_keypair])
    # Verify AMI is valid; raises InvalidAMIID.NotFound
    ec2.meta.client.describe_images(ImageIds=[awscfg.ngfw_ami])
    
    return ec2
