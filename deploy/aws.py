"""
AWS Related Configuration
"""
import time
import ipaddress
import boto3
import botocore.exceptions
from deploy.validators import custom_choice_menu
from smc.elements.collection import describe_single_fw
import logging

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
        self.security_group = None
        self.public_subnet = None
        self.private_subnet = None
        self.internet_gateway = None
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
            
        logger.info("Loaded VPC with id: {} and cidr_block: {}"
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
        logger.info("Created VPC: {}".format(vpc_new.vpc_id))
        
        aws = VpcConfiguration(vpc_new.vpc_id).load()
        
        aws.internet_gateway = ec2.create_internet_gateway()
        logger.info("Created internet gateway: {}"
                    .format(aws.internet_gateway.id))
        
        # Attach internet gateway to VPC
        aws.internet_gateway.attach_to_vpc(VpcId=aws.vpc.vpc_id)
        
        # Main route table is automatically created
        main_rt = list(aws.vpc.route_tables.filter(Filters=[{
                                                    'Name': 'association.main',
                                                    'Values': ['true']}]))
        if main_rt:
            main_rt[0].create_route(DestinationCidrBlock='0.0.0.0/0',
                                    GatewayId=aws.internet_gateway.id)
        else:
            raise botocore.exceptions.ClientError("Cannot find default route table")

        return aws

    def create_network_interface(self, interface_id, cidr_block=None,
                                 ec2_subnet=None, availability_zone=None, 
                                 description=''):
        """
        Create a network interface to be used for the NGFW AMI
        This involves several steps: 
        * Create the subnet (or use ec2_subnet existing subnet)
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
            raise ValueError("You must specify a cidr to create or existing ec2 subnet")
        
        if cidr_block:
            subnet = self.create_subnet(cidr_block, availability_zone)
            wait_for_resource(subnet, self.vpc.subnets.all())
        else:
            subnet = ec2_subnet
    
        #Assign static address and elastic to eth0
        if interface_id == 0:
            external = ipaddress.ip_network(u'{}'.format(cidr_block))
            external = str(list(external)[-2]) #broadcast address -1
            interface = subnet.create_network_interface(PrivateIpAddress=external,
                                                        Description=description)
            
            wait_for_resource(interface, self.vpc.network_interfaces.all()) 
            allocation_id = self.allocate_elastic_ip()
            address = ec2.VpcAddress(allocation_id)
            address.associate(NetworkInterfaceId=interface.network_interface_id)
            self.public_subnet = subnet
        else:
            interface = subnet.create_network_interface(Description=description)
            wait_for_resource(interface, self.vpc.network_interfaces.all())
            self.private_subnet = subnet #need this ref for client instance
            
            alt_route_table = self.vpc.create_route_table()
            alt_route_table.create_tags(Tags=create_tag())
            
            logger.info("Associating subnet ID: {} to alternate route table"
                        .format(subnet.subnet_id))
            alt_route_table.associate_with_subnet(SubnetId=subnet.subnet_id)
            
            logger.info("Setting default route using alternate route table for "
                        "interface {}".format(interface.network_interface_id))
            alt_route_table.create_route(
                            DestinationCidrBlock='0.0.0.0/0',
                            NetworkInterfaceId=interface.network_interface_id)
            
        interface.modify_attribute(SourceDestCheck={'Value': False})
        logger.info("Finished creating and configuring network interface: {}, "
                    "subnet_id: {}, address: {}"
                    .format(interface.network_interface_id, interface.subnet_id,
                            interface.private_ip_address))
    
        self.availability_zone = interface.availability_zone
        self.network_interface.append({interface_id: interface})

    def create_subnet(self, cidr_block, az=None):
        """
        Create a subnet, add stonesoft tag
        
        :return: ec2.Subnet
        """
        az = '' if not az else az
        subnet = ec2.create_subnet(VpcId=self.vpc.vpc_id,
                                   CidrBlock=cidr_block,
                                   AvailabilityZone=az)
        logger.info("Created subnet: {}, in availablity zone: {}"
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
                        logger.info("Unassigned Elastic IP found: {}"
                                    .format(unassigned.get('AllocationId')))
                        eip = unassigned
                        break
                if not eip: raise
                self.elastic_ip = eip.get('PublicIp')
                return eip.get('AllocationId')
            else: raise
    
    def create_security_group(self, name='stonesoft-sg', description='stonesoft ngfw'):
        """
        Create security group specific for inbound traffic. Each VPC will have it's own
        security group that will be applied only to the public network interface. 
        If existing VPC with multiple ngfw's are deployed, the same security group is 
        used.
        """
        try:
            groupid = ec2.create_security_group(GroupName=name,
                                                Description=description,
                                                VpcId=self.vpcid)
            self.security_group = groupid
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'InvalidGroup.Duplicate':
                logger.info("Security group already exists, skipping")
                grp = list(self.vpc.security_groups.filter(Filters=[{
                                                        'Name': 'group-name',
                                                        'Values': [name]}]))
                self.security_group = grp[0]
            else: raise
    
    def authorize_security_group_ingress(self, from_cidr_block, 
                                         ip_protocol='-1'):
        """ 
        Creates an inbound rule to allow access from public that will
        be redirected to the virtual FW
        For protocols, AWS references:
        http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
        
        :param cidr_block: network (src 0.0.0.0/0 from internet)
        :param protocol: protocol to allow (-1 for all)
        """
        security_group = ec2.SecurityGroup(self.security_group.id)
        try:
            security_group.authorize_ingress(CidrIp=from_cidr_block,
                                             IpProtocol=ip_protocol)
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'InvalidPermission.Duplicate':
                pass
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
        logger.info("Launching ngfw as {} instance into availability zone: {}"
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
            for state in waiter(instance, 'terminated'):
                logger.info(state)
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
            grp[0].delete()
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'InvalidGroup.NotFound':
                pass
            else: raise
        self.vpc.delete()
        logger.info("Deleted vpc: {}".format(self.vpc.vpc_id))
    
def waiter(instance, status):
    """ 
    Generator to monitor the startup of the launched AMI 
    Call this in loop to get status
    
    :param instance: instance to monitor 
    :param status: status to check for:
           'pending|running|shutting-down|terminated|stopping|stopped'
    :return: generator message updates 
    """
    while True:
        if instance.state.get('Name') != status:
            yield "Instance in state: {}, waiting..".format(instance.state.get('Name'))
            time.sleep(5)
            instance.reload()
        else:
            yield "Image in desired state: {}!".format(status)
            break

def wait_for_resource(resource, iterable):
    """
    Wait for the resource to become available. If the AWS newly created
    component isn't available right away and a reference call is
    made the AWS client throws an exception. This checks the iterable 
    for the component id before continuing. Insert this where you 
    might need to introduce a short delay.
    
    :param resource: subnet, interface, etc
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
    logger.info("Spinning up client instance on private subnet: {}"
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
    logger.info("Client instance created: {} with keypair: {} at ipaddress: {}"
                .format(instance.id, instance.key_name, ntwk))

def create_tag():
    return [{'Key': 'stonesoft',
             'Value': ''}]

def get_available_vpcs(prompt):
    vpcs = [x.id +' '+ x.cidr_block for x in ec2.vpcs.filter()]
    choice = custom_choice_menu(prompt, vpcs)
    return choice

def next_available_subnet(az_subnets=None, vpc_cidr=None):
    """
    Pull the available /28 addresses for public address space on
    external side of NGFW.
    az_subnets are the existing subnets retrieved from the VPC.
    vpc_cidr is the encapsulating network
    
    Expand out VPC subnet into /28 networks and start iterating
    from the high end side of the subnet (i.e. 172.16.0.0/16 would
    start at 172.16.255.240/28, etc). Compare the /28 with the 
    existing subnets to ensure there is no overlap.
    
    :param ec2.Subnet az_subnets: existing ec2.Subnet objects
    :param vpc_cidr: full cidr for VPC
    """
    # All /28 addresses in the VPC network as ipaddress.IPv4Network
    public = list(ipaddress.ip_network(u'{}'.format(vpc_cidr)).subnets(new_prefix=28))
   
    # Turn ec2.Subnet into ipaddress.IPv4Network for comparison
    subnet_cidrs = [ipaddress.ip_network(u'{}'.format(cidr.cidr_block)) for cidr in az_subnets]
    subnet_cidrs.append(ipaddress.ip_network(u'172.31.255.0/24'))
    for network in reversed(public):
        used = False # Assume it's used initially
        for existing in subnet_cidrs:
            # Check all subnets to see if this is used
            if ipaddress.ip_network(network).overlaps(existing):
                used = True
                break
            else:
                used = False # already used
        if not used:
            yield str(network)
       
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
            if not awscfg.region:
                aws_session = boto3.session.Session()
                awscfg.region = custom_choice_menu('Enter a region:', aws_session.get_available_regions('ec2'))
        ec2 = boto3.resource('ec2',
                             aws_access_key_id = awscfg.aws_access_key_id,
                             aws_secret_access_key=awscfg.aws_secret_access_key,
                             region_name=awscfg.region)
    else:
        logger.info('Attempting to resolve AWS credentials natively')
        ec2 = boto3.resource('ec2')
    logger.info("Obtained ec2 client: %s" % ec2)
    # Verify the AWS key pair exists, raises InvalidKeyPair.NotFound
    ec2.meta.client.describe_key_pairs(KeyNames=[awscfg.aws_keypair])
    # Verify AMI is valid; raises InvalidAMIID.NotFound
    ec2.meta.client.describe_images(ImageIds=[awscfg.ngfw_ami])
    
    return ec2

def remove_ngfw_from_vpc():
    """
    Use tags on subnets, route tables and instances to find stonesoft
    related components and stop in the right order. When the alternate
    route tables are removed, existing subnets will revert to using 
    the Main route table.
    """ 
    vpcs = [x.id +' '+ x.cidr_block for x in ec2.vpcs.filter()]
    choice = custom_choice_menu('Remove NGFW from VPC: ', vpcs)
    vpc = VpcConfiguration(choice.split(' ')[0]).load()
    
    # Reset route table back to Main by deleting 'stonesoft' tagged route tables
    for rt in vpc.vpc.route_tables.all():
        if rt.tags:
            if any(tag.get('Key') == 'stonesoft' for tag in rt.tags):
                # Is associated to a subnet?
                if rt.associations:
                    # Delete all associations
                    for assoc in rt.associations.all():
                        assoc.delete()
                    rt.delete()
                else:
                    rt.delete()

    # Find running instances of NGFW
    nics, subnets, instances = ([] for i in range(3))
    for instance in vpc.vpc.instances.filter(Filters=[{
                                            'Name': 'instance-state-name',
                                            'Values': ['running', 'pending', 'stopped']}]):

        if any(tag.get('Key') == 'stonesoft' for tag in instance.tags):            
            instances.append(instance.id)
            # Subnets created were tagged, NICs are not.
            for dependency in instance.network_interfaces_attribute:
                nics.append(dependency.get('NetworkInterfaceId'))
                subnet = dependency.get('SubnetId')
                # If subnet has tags, look for ours
                if ec2.Subnet(subnet).tags:
                    if any(tag.get('Key') == 'stonesoft' for tag in ec2.Subnet(subnet).tags):
                        subnets.append(subnet)

            logger.info("Terminating instance: {}".format(instance.instance_id))
            instance.terminate()

    waiter = ec2.meta.client.get_waiter('instance_terminated')
    logger.info('Waiting for instances to fully terminate...This can take a few minutes.')
    waiter.wait(InstanceIds=instances)
    # NICs can be removed, they would have been added only for NGFW
    for nic in nics:
        ec2.NetworkInterface(nic).delete()
    for subnet in subnets:
        ec2.Subnet(subnet).delete()

    firewalls = describe_single_fw() # FW List
    for instance in instances:
        for fw in firewalls:
            if fw.name.startswith(instance):
                fw.delete()
    logger.info("Completed successfully.")

class AWSConfig(object):
    def __init__(self, aws_keypair, ngfw_ami, aws_client=False, 
                 aws_instance_type='t2.micro', aws_region=None,
                 **kwargs):
        self.aws_keypair = aws_keypair
        self.aws_client = aws_client
        self.ngfw_ami = ngfw_ami
        self.region = aws_region
        self.aws_instance_type = aws_instance_type
        
        for k, v in kwargs.items():
            setattr(self, '_'+k, v)
        
    @property
    def vpc_private(self):
        return self._vpc_private
    
    @property
    def vpc_public(self):
        return self._vpc_public
    
    @property
    def vpc_subnet(self):
        return self._vpc_subnet

    @property
    def aws_access_key_id(self):
        return self._aws_access_key_id
    
    @property
    def aws_secret_access_key(self):
        return self._aws_secret_access_key
    
    @property
    def aws_client_ami(self):
        if self.aws_client and hasattr(self, '_aws_client_ami'):
            return self._aws_client_ami
        else:
            return None
     
    def __getattr__(self, value):
        return None

