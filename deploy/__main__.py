'''
Stonesoft NGFW configurator for AWS instance deployment with auto-engine creation.
There are two example use cases that can be leveraged to generate NGFW automation into AWS:

Use Case 1: 
    * Fully create a VPC and subnets and auto provision NGFW as gateway
    
Use Case 2: 
    * Fully provision NGFW into existing VPC

In both cases the NGFW in AWS will connect to Stonesoft Management Center over an encrypted 
connection across the internet.
It is also possible to host SMC in AWS where contact could be made through AWS routing

.. note:: This also assumes the NGFW AMI is available in "My AMI's" within the AWS Console 

The Stonesoft NGFW will be created with 2 interfaces by default and use static interfaces
for both private and public. IP Addresses are obtained from AWS.
 
The network interface objects will be created first from the boto3 API, specifying interface 
eth0 (management) and eth1 as private. The public side (eth0) interface will be placed into a 
/28 subnet and assigned the broadcast address -1.

See AWS doc's for reserved addresses in a VPC:
http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Subnets.html

For the 'private' (inside/eth1) interface, AWS will auto-assign an IP address which will be 
statically assigned to the NGFW. A new security group will be created ('stonesoft-sg') which
will bind to the 'public' network interface for inbound traffic.

Default NAT is enabled on stonesoft to allow outbound traffic without a specific NAT rule. 

Once the NGFW is created, a license is automatically bound and the initial_contact for the engine
is created for AMI instance UserData. 

Although it is possible to automate these tasks with smc-python, for simplicity, the SMC should 
be prepared with the following:
------------------------------------
* Available security engine licenses
* Pre-configured Layer 3 Policy with configured policy

The tested scenario was based on public AWS documentation found at:
http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Scenario2.html

Requirements:
* smc-python>=0.4.1
* boto3
* ipaddress
* pyyaml
'''

import yaml
import logging
import botocore
from smc import session
from deploy.aws import AWSConfig, VpcConfiguration, waiter, spin_up_host, get_ec2_client,\
    get_available_vpcs, next_available_subnet, create_tag, remove_ngfw_from_vpc
from deploy.ngfw import NGFWConfiguration, validate, monitor_status, get_smc_session
from smc.actions.tasks import TaskMonitor
from deploy.validators import prompt_user, custom_choice_menu
from smc.api.exceptions import CreateEngineFailed

logger = logging.getLogger(__name__)

def create_vpc_and_ngfw(awscfg, ngfw):
    '''
    Use Case 1: Create entire VPC and deploy NGFW
    ---------------------------------------------
    This will fully create a VPC and associated requirements. 
    The following will occur:
    * A new VPC will be created in the AZ based on boto3 client region
    * Two network subnets are created in the VPC, one public and one private
    * Two network interfaces are created and assigned to the subnets
      eth0 = public, eth1 = private
    * An elastic IP is created and attached to the public network interface
    * An internet gateway is created and attached to the public network interface
    * A route is created in the default route table for the public interface to
      route 0.0.0.0/0 to the IGW
    * The default security group is modified to allow inbound access from 0.0.0.0/0
      to to the NGFW network interface
      :py:func:`VpcConfiguration.authorize_security_group_ingress`
    * A secondary route table is created with a default route to 0.0.0.0/0 with a next
      hop assigned to interface eth1 (NGFW). This is attached to the private subnet.
    * The NGFW is automatically created and UserData is obtained for AMI instance launch
    * AMI is launched using UserData to allow auto-connection to NGFW SMC Management
    * NGFW receives queued policy and becomes active
    '''
    vpc = VpcConfiguration.create(vpc_subnet=awscfg.vpc_subnet)
    try:
        vpc.create_network_interface(0, awscfg.vpc_public, description='public-ngfw') 
        vpc.create_network_interface(1, awscfg.vpc_private, description='private-ngfw')
        vpc.create_security_group('stonesoft-sg')
        vpc.authorize_security_group_ingress('0.0.0.0/0', ip_protocol='-1')
        
        deploy(vpc, ngfw, awscfg)
        # If user wants a client AMI, launch in the background
        if awscfg.aws_client and awscfg.aws_client_ami:
            spin_up_host(awscfg.aws_keypair, vpc, awscfg.aws_instance_type, 
                         awscfg.aws_client_ami)
        
    except (botocore.exceptions.ClientError, CreateEngineFailed) as e:
        logger.error('Caught exception, rolling back: {}'.format(e))
        ngfw.rollback()
        vpc.rollback() 

def create_ngfw_in_existing_vpc(awscfg, ngfw):
    '''
    Use Case 2: Deploy NGFW into existing VPC
    -----------------------------------------
    This assumes the following:
    * You have an existing VPC with one or more subnets
    * Available elastic IP per NGFW
    * Available /28 subnets in VPC network, one per NGFW
    
    When NGFW is injected into an existing VPC, the deployment strategy will
    obtain the defined network address space for the VPC. It will create a 
    'private' supernet using a /28 subnet on the uppermost side of the VPC
    network. For example, a VPC network of 172.16.0.0/16 will result in a 
    new subnet created 172.31.255.240/28. This will act as the 'public' side of
    the NGFW (creating a small subnet allows wasted address space). This public
    side network will use the "Main" route table that should already use the
    AWS Internet Gateway as it's next hop, allowing internet connectivity.
    Next, each a network interface will be created in each subnet that exists in
    the VPC. AWS will assign an address during interface creation which will be 
    assigned to the NGFW on that subnet segment. In addition, a new route table 
    will be created for each subnet and direct 0.0.0.0/0 to the NGFW network 
    interface previously created. This results in each subnet having the NGFW as
    it's gateway for outbound traffic.
    
    .. note:: Each subnet must be in the same AZ, which is why it is necessary to
              create a unique /28 for each subnet if spread across AZ's.
              
    http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-eni.html
    '''
    # Connect to region and view all available VPCs
    choice = get_available_vpcs('View available VPC configurations:')
    vpc = VpcConfiguration(choice.split(' ')[0]).load()
    
    # Choose subnet to install NGFW, or all
    vpcs = [x.cidr_block +' ('+x.availability_zone+')' for x in vpc.vpc.subnets.all()]
    vpcs.append('all')
    choice = custom_choice_menu('Available subnets;', vpcs)

    target = choice.split(' ')[0]
    vpc_subnets = list(vpc.vpc.subnets.all()) # ec2.Subnet
    itr = next_available_subnet(vpc_subnets, vpc.vpc.cidr_block) #Available subnet
    
    if not target == 'all':
        # Find matching subnet
        for subnet in vpc_subnets:
            if subnet.cidr_block == target:
                
                public = next(itr)
                try:
                    # Create public side network for interface 0 using the /28 network space
                    vpc.create_network_interface(0, cidr_block=public, 
                                                 availability_zone=subnet.availability_zone,
                                                 description='public ngfw')
                    vpc.create_network_interface(1, ec2_subnet=subnet, description='private ngfw')
                    vpc.create_security_group('stonesoft-sg')
                    vpc.authorize_security_group_ingress('0.0.0.0/0', ip_protocol='-1')
                    deploy(vpc, ngfw, awscfg)    
                
                except (botocore.exceptions.ClientError, CreateEngineFailed) as e:
                    logger.error('Caught exception, rolling back: {}'.format(e))
                    ngfw.rollback()
                
    else:
        # One NGFW will be created for each availability zone in VPC
        import copy
        for subnet in vpc_subnets:
            
            clone = copy.copy(vpc)
            public = next(itr)
            try:
                # Create public side network for interface 0 using the /28 network space
                clone.create_network_interface(0, cidr_block=public, 
                                             availability_zone=subnet.availability_zone,
                                             description='public ngfw')
                clone.create_network_interface(1, ec2_subnet=subnet, description='private ngfw')
                clone.create_security_group('stonesoft-sg')
                clone.authorize_security_group_ingress('0.0.0.0/0', ip_protocol='-1')
                deploy(clone, ngfw, awscfg)    
                
            except (botocore.exceptions.ClientError, CreateEngineFailed) as e:
                logger.error('Caught exception, rolling back: {}'.format(e))
                ngfw.rollback()

def deploy(vpc, ngfw, awscfg):
    """
    Execute the deploy. This can raise botocore.exceptions.ClientError or
    smc.api.exceptions.CreateEngineFailed exceptions and should be wrapped
    if needed by calling function/method.
    """
    interfaces, gateway = vpc()
            
    ngfw(interfaces, gateway)
    userdata = ngfw.initial_contact()
    ngfw.add_contact_address(vpc.elastic_ip)
                        
    instance = vpc.launch(key_pair=awscfg.aws_keypair, 
                          userdata=userdata, 
                          imageid=awscfg.ngfw_ami,
                          instance_type=awscfg.aws_instance_type)
    instance.create_tags(Tags=create_tag())
    
    # Add security group to network interface 
    # (not supported on launch when network interfaces are specified)
    for interfaces in vpc.network_interface:
        for index, network in interfaces.items():
            if index == 0:
                network.modify_attribute(Groups=[vpc.security_group.id])
                           
    # Rename NGFW to AMI instance id (availability zone)
    ngfw.engine.rename('{} ({})'.format(instance.id, vpc.availability_zone))
                        
    # Wait for AWS instance to show running state
    for message in waiter(instance, 'running'):
        logger.info(message)
        
                
    logger.info('Elastic (public) IP address is set to: {}, ngfw instance id: {}'
                .format(vpc.elastic_ip, instance.id))
                
    logger.info('To connect to your NGFW AWS instance, execute the command: '
                'ssh -i {}.pem aws@{}'.format(instance.key_name, vpc.elastic_ip))
                        
    import time
    start_time = time.time()
    logger.info('Waiting for NGFW to do initial contact...')
    for msg in monitor_status(ngfw.engine, status='No Policy Installed'):
        logger.info(msg)
                        
    # After initial contact has been made, fire off policy upload 
    ngfw.upload_policy()
                        
    if ngfw.task: # Upload policy task
        for message in TaskMonitor(ngfw.task).watch():
            logger.info(message)
                        
    if ngfw.has_errors:
        logger.error('Errors were returned, manual intervention will be required: '
                     '{}'.format(ngfw.has_errors))
    logger.info("--- %s seconds ---" % (time.time() - start_time))
    
def main():
     
    logger = logging.getLogger()
    handler = logging.StreamHandler()
    logger.addHandler(handler)
    
    import argparse
    parser = argparse.ArgumentParser(description='Stonesoft NGFW AWS Launcher')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', '--interactive', action='store_true', help='Use interactive prompt mode')
    group.add_argument('-y', '--yaml', help='Specify yaml configuration file name')
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument('-d', '--delete', action='store_true', help='Delete a VPC using prompt mode')
    actions.add_argument('-r', '--remove', action='store_true', help='Remove ngfw from vpc (menu)')
    actions.add_argument('-a', '--add', action='store_true', help='Add ngfw to vpc (menu)')
    parser.add_argument('-n', '--nolog', action='store_true', help='Disable logging to console')
    
    args = parser.parse_args()
    
    if not any(vars(args).values()):
        parser.print_help()
        parser.exit()
    elif args.delete and not (args.interactive or args.yaml):
        parser.error('-d|--delete requires -i or -y specified')

    if args.nolog:
        logger.setLevel(logging.ERROR)
        logging.getLogger('boto3').setLevel(logging.CRITICAL)
        logging.getLogger('botocore').setLevel(logging.CRITICAL)
    else:
        logger.setLevel(logging.INFO)  

    if args.interactive:
        path = prompt_user()   # Run through user prompts, save, then safe_load
    if args.yaml:
        path = args.yaml
    with open(path, 'r') as stream:
        try:
            data = yaml.safe_load(stream)
            awscfg = AWSConfig(**data.get('AWS'))
            ngfw = NGFWConfiguration(**data.get('NGFW'))
            smc = data.get('SMC')
        except yaml.YAMLError as exc:
            print(exc)
            
    ec2 = get_ec2_client(awscfg, prompt_for_region=True)
    
    get_smc_session(smc)
    
    if args.remove:
        remove_ngfw_from_vpc()
        return
    
    validate(ngfw) #Raises if validation fails
    
    if args.add:
        create_ngfw_in_existing_vpc(awscfg, ngfw)
        return
    
    if args.delete:
        vpcs = [x.id +' '+ x.cidr_block for x in ec2.vpcs.filter()]
        choice = custom_choice_menu('Enter a VPC to remove: ', vpcs)
        vpc = VpcConfiguration(choice.split(' ')[0]).load()
        vpc.rollback()

    create_vpc_and_ngfw(awscfg, ngfw)

    session.logout()

if __name__ == '__main__':
    main()