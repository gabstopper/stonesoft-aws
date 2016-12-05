"""
AWS Related Configuration
"""
import time
import ipaddress
import boto3
import botocore.exceptions
from deploy.validators import custom_choice_menu
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
        self.alt_route_table = None
        self.elastic_ip = None
        self.private_subnet = None
        self.internet_gateway = None
        self.network_interface = []
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
        
        vpc = VpcConfiguration(vpc_new.vpc_id).load() 
        
        vpc.internet_gateway = ec2.create_internet_gateway()
        logger.info("Created internet gateway: {}"
                    .format(vpc.internet_gateway.id))
        
        #attach igw to vpc
        vpc.internet_gateway.attach_to_vpc(VpcId=vpc.vpc.vpc_id)
        
        vpc.create_default_gw()
        vpc.create_alt_route_table()
        return vpc

    def create_network_interface(self, interface_id, cidr_block,
                                 description=''):
        """
        Create a network interface to be used for the NGFW AMI
        This involves several steps: 
        * Create the subnet
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
        :param cidr_block: cidr of subnet
        :param availability_zone: optional
        :param description: description on interface
        :raises: botocore.exception.ClientError
        """
        subnet = self.create_subnet(cidr_block)
        wait_for_resource(subnet, self.vpc.subnets.all())
       
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
        else:
            interface = subnet.create_network_interface(Description=description)
            wait_for_resource(interface, self.vpc.network_interfaces.all())
            self.private_subnet = subnet #need this ref for client instance
            logger.info("Associating subnet ID: {} to alternate route table"
                        .format(subnet.subnet_id))
            self.alt_route_table.associate_with_subnet(
                                        SubnetId=subnet.subnet_id)
            logger.info("Setting default route using alternate route table for "
                        "interface {}".format(interface.network_interface_id))
            self.alt_route_table.create_route(
                            DestinationCidrBlock='0.0.0.0/0',
                            NetworkInterfaceId=interface.network_interface_id)
            
        interface.modify_attribute(SourceDestCheck={'Value': False})
        logger.info("Finished creating and configuring network interface: {}, "
                "subnet_id: {}, address: {}"
                .format(interface.network_interface_id, interface.subnet_id,
                       interface.private_ip_address))
    
        self.availability_zone = interface.availability_zone 
        self.associate_network_interface(interface_id, interface.network_interface_id)

    def create_subnet(self, cidr_block):
        """
        Create a subnet
        
        :return: Subnet
        """
        subnet = ec2.create_subnet(VpcId=self.vpc.vpc_id,
                                   CidrBlock=cidr_block)
        logger.info("Created subnet: {}, in availablity zone: {}"
                    .format(subnet.subnet_id, subnet.availability_zone))
        return subnet
    
    def create_default_gw(self):
        """ 
        Create the default route with next hop pointing to IGW 
        """
        rt = self.vpc.route_tables.filter(Filters=[{
                                        'Name': 'association.main',
                                        'Values': ['true']}])
        for default_rt in rt:
            default_rt.create_route(
                    DestinationCidrBlock='0.0.0.0/0',
                    GatewayId=self.internet_gateway.id)
 
    def create_alt_route_table(self):
        """ 
        Create alternate route table for non-public subnets
        """
        self.alt_route_table = self.vpc.create_route_table()
        logger.info("Created alt route table: {}"
                    .format(self.alt_route_table.id))
        
    def allocate_elastic_ip(self):
        """ 
        Create elastic IP address for network interface. An elastic IP is
        used for the public facing interface for the NGFW AMI
        
        :return: AllocationId (elastic IP reference)
        """
        eip = None
        try:
            eip = ec2.meta.client.allocate_address(Domain='vpc')
        except botocore.exceptions.ClientError:
            #Caught AddressLimitExceeded. Find unassigned or re-raise
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
    
    def associate_network_interface(self, interface_id, network_interface_id):
        """
        Associate the network interface to a device index. This is used by the
        launch function to fill the constructor details which require a reference
        to the network interface and it's numeric index (eth0=0, eth1=1, etc)
        
        :raises: InvalidNetworkInterfaceID.NotFound
        """
        interface_itr = ec2.network_interfaces.filter(
                                    NetworkInterfaceIds=[network_interface_id])
        for intf in interface_itr:
            self.network_interface.append({interface_id: intf})
    
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
        for grp in self.vpc.security_groups.all():
            grp.authorize_ingress(CidrIp=from_cidr_block,
                                  IpProtocol=ip_protocol)
        logger.info("Modified ingress security group: {}".format(grp.id))
    
    def __call__(self):
        """
        Retrieve interface information for NGFW
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
        VPC. It is not advisable if loading an existing VPC as it will remove
        the entire configuration.
        """
        for instance in self.vpc.instances.filter(Filters=[{
                                    'Name': 'instance-state-name',
                                    'Values': ['running', 'pending', 'stopped']}]):
            logger.info("Terminating instance: {}".format(instance.instance_id))
            instance.terminate()
            for state in waiter(instance, 'terminated'):
                logger.info(state)
     
        for intf in self.vpc.network_interfaces.all():
            logger.info("Deleting interface: {}".format(intf))
            intf.delete()
        for subnet in self.vpc.subnets.all():
            logger.info("Deleting subnet: {}".format(subnet))
            subnet.delete()
        for rt in self.vpc.route_tables.all():
            if not rt.associations_attribute:
                logger.info("Deleting unassociated route table: {}".format(rt))
                rt.delete()
            else:
                for current in rt.associations_attribute:
                    if not current or current.get('Main') is False:
                        logger.info("Deleting non-default route table: {}".format(rt))
                        rt.delete()
        for igw in self.vpc.internet_gateways.all():
            logger.info("Detach and deleting IGW: {}".format(igw))
            igw.detach_from_vpc(VpcId=self.vpc.vpc_id)
            igw.delete()
        
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
    Wait for the resource to become available. If the AWS
    component isn't available right away and a reference call is
    made the AWS client throw an exception. This checks the iterable 
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
    
    print("ec2: %s" % ec2)
    return ec2
