'''
Created on Nov 21, 2016

@author: davidlepage
'''
from deploy.ngfw import monitor_status
'''
Stonesoft NGFW configurator for AWS instance deployment with auto-engine creation.
There are two example use cases that can be leveraged to generate NGFW automation into AWS:

Use Case 1: 
    * Fully create a VPC and subnets and auto provision NGFW as gateway
    
Use Case 2: 
    * Fully provision NGFW into existing VPC

In both cases the NGFW will connect to Stonesoft Management Center over an encrypted connection 
across the internet.
It is also possible to host SMC in AWS where contact could be made through AWS routing

.. note:: This also assumes the NGFW AMI is available in "My AMI's" within the AWS Console 

The Stonesoft NGFW will be created with 2 interfaces (limit for t2.micro) and use static interfaces
for both private and public. No IP addresses are required when creating the NGFW. 
The strategy is that the network interface objects will be created first from the boto3 API, if
the interface is for eth0 (management), then the subnet range will be determined and the NGFW will
take an IP address on that subnet, -1 from the broadcast address.
For the 'private' (inside) interface, AWS will auto-assign an IP address which will be statically
assigned to the NGFW during FW creation.

See AWS doc's for reserved addresses in a VPC:
http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Subnets.html

Default NAT is enabled on the engine to allow outbound traffic without a specific NAT rule. 

Once the NGFW is created, a license is automatically bound and the initial_contact for the engine
is created for AMI instance UserData. 

The AWS create_instances() method is called specifying the required information and user data allowing the
NGFW to auto-connect to the SMC without intervention.

The SMC should be prepared with the following:
* Available security engine licenses
* Pre-configured Layer 3 Policy with needed policy

The tested scenario was based on public AWS documentation found at:
http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Scenario2.html

Requirements:
* smc-python
* boto3
* ipaddress
* pyyaml

Install smc-python::

    python install git+https://github.com/gabstopper/smc-python.git

Install boto3 and pyyaml via pip::

    pip install boto3
    pip install pyyaml
    pip install ipaddress
'''
import sys
import yaml
import logging
import boto3
import botocore
from smc import session
from aws import AWSConfig, VpcConfiguration, waiter, spin_up_host
from ngfw import NGFWConfiguration
from smc.actions.tasks import TaskMonitor
from prompt import prompt_user, menu
from ngfw import validate
from smc.api.exceptions import CreateEngineFailed

if __name__ == '__main__':
    
    logger = logging.getLogger()
    handler = logging.StreamHandler()
    logger.addHandler(handler)
    
    import argparse
    parser = argparse.ArgumentParser(description='Stonesoft NGFW AWS Launcher')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-i', '--interactive', action='store_true', help='Use interactive prompt mode')
    group.add_argument('-y', '--yaml', help='Specify yaml configuration file name')
    parser.add_argument('-d', '--delete', action='store_true', help='Delete a VPC using prompt mode')
    parser.add_argument('-l', '--nolog', action='store_true', help='disable logging to console')
    args = parser.parse_args()
    
    if len(sys.argv[1:]) == 0:
        parser.print_help()
        parser.exit()
        
    if args.nolog:
        logger.setLevel(logging.ERROR)
    else:
        logger.setLevel(logging.INFO)
    
    smc_url = smc_key = None    
    
    if args.interactive:
        path = prompt_user()   # Run through user prompts, save, then safe_read
    if args.yaml:
        path = args.yaml
    with open(path, 'r') as stream:
        try:
            data = yaml.safe_load(stream)
            awscfg = AWSConfig(**data.get('AWS'))
            ngfw = NGFWConfiguration(**data.get('NGFW'))
            smc = data.get('SMC')
            if smc:
                smc_url = smc.get('url')
                smc_api_key = smc.get('key')
        except yaml.YAMLError as exc:
            print(exc)  
    
    # Verify SMC
    if smc_url and smc_api_key:
        session.login(url=smc_url, api_key=smc_api_key)
    else: #from ~.smcrc
        session.login()
    
    # If NGFW settings were provided in the YAML, verify the critical 
    # settings like VPN policy name and firewall policy name exist.
    if args.yaml:
        validate(ngfw)

    """
    Strategy to obtain credentials for EC2 operations (in order):
    * Check for AWS credentials in YAML configuration
    * If credentials found in YAML but no region specified, prompt for region
    * Check for credentials via normal boto3 AWS options, i.e ~/.aws/credentials, etc
    For more on boto3 credential locations, see:   
    http://boto3.readthedocs.io/en/latest/guide/quickstart.html#configuration
    """
    if awscfg.aws_access_key_id and awscfg.aws_secret_access_key:
        if not awscfg.region:
            aws_session = boto3.session.Session()
            awscfg.region = menu('Enter a region:', choices=aws_session.get_available_regions('ec2'))
        ec2 = boto3.resource('ec2',
                             aws_access_key_id = awscfg.aws_access_key_id,
                             aws_secret_access_key=awscfg.aws_secret_access_key,
                             region_name=awscfg.region)
    else:
        logger.info('Attempting to resolve AWS credentials natively')
        ec2 = boto3.resource('ec2')
    
    import deploy
    deploy.setup_default_session(aws_access_key_id = awscfg.aws_access_key_id,
                                 aws_secret_access_key=awscfg.aws_secret_access_key,
                                 region_name=awscfg.region)
    import aws
    aws.ec2 = ec2 #Have client and credentials
    
    if args.delete:
        vpcs = [x.id +' '+ x.cidr_block for x in ec2.vpcs.filter()]
        choice = menu('Enter a VPC to remove: ', choices=vpcs)
        vpc = VpcConfiguration(choice.split(' ')[0]).load()
        vpc.rollback()
    
    # Before doing anything, verify the AWS key pair exists
    ec2.meta.client.describe_key_pairs(KeyNames=[awscfg.aws_keypair])
    # Verify AMI is valid
    ec2.meta.client.describe_images(ImageIds=[awscfg.ngfw_ami])

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
    
    .. note: The AZ used during instance spin up is based on the AZ that is auto-generated
             by AWS when the interface is created. If you require a different AZ, set the 
             attribute :py:class:`VpcConfiguration.availability_zone` before called launch. 
    '''
    vpc = VpcConfiguration.create(vpc_subnet=awscfg.vpc_subnet)
    try:
        vpc.create_network_interface(0, awscfg.vpc_public, description='public-ngfw') 
        vpc.create_network_interface(1, awscfg.vpc_private, description='private-ngfw')
        vpc.authorize_security_group_ingress('0.0.0.0/0', ip_protocol='-1')
        
        # Retrieve interfaces and gateway info from AWS VPC
        interfaces, gateway = vpc()

        # Create the NGFW
        ngfw(interfaces, gateway)
        userdata = ngfw.initial_contact()
        ngfw.add_contact_address(vpc.elastic_ip)
        
        instance = vpc.launch(key_pair=awscfg.aws_keypair, 
                              userdata=userdata, 
                              imageid=awscfg.ngfw_ami,
                              instance_type=awscfg.aws_instance_type)

        # Rename to AMI instance id (availability zone)
        ngfw.engine.rename('{} ({})'.format(instance.id, vpc.availability_zone))
        
        # Wait for AWS instance to show running state
        for message in waiter(instance, 'running'):
            logger.info(message)
        
        # If user wants a client AMI, launch in the background
        if awscfg.aws_client and awscfg.aws_client_ami:
            spin_up_host(awscfg.aws_keypair, vpc, awscfg.aws_instance_type, 
                         awscfg.aws_client_ami)

        logger.info('Elastic (public) IP address is set to: {}, ngfw instance id: {}'
                    .format(vpc.elastic_ip, instance.id))

        logger.info('To connect to your AWS instance, execute the command: '
                    'ssh -i {}.pem aws@{}'.format(instance.key_name, vpc.elastic_ip))
        
        logger.info('Waiting for NGFW to do initial contact...')
        for msg in monitor_status(ngfw.engine, status='No Policy Installed'):
            logger.info(msg)
        
        # After initial contact has been made, fire off policy upload 
        ngfw.queue_policy()
        
        import time
        start_time = time.time()
        
        if ngfw.task:
            for message in TaskMonitor(ngfw.task).watch():
                logger.info(message)
        
        if ngfw.has_errors:
            print 'Errors were returned, manual intervention will be required: {}'\
            .format(ngfw.has_errors)

        print("--- %s seconds ---" % (time.time() - start_time))
                  
    except (botocore.exceptions.ClientError, CreateEngineFailed) as e:
        logger.error('Caught exception, rolling back: {}'.format(e))
        ngfw.rollback()
        vpc.rollback() 

    '''
    Use Case 2: Deploy NGFW into existing VPC
    -----------------------------------------
    This assumes the following:
    * You have an existing VPC, with a public subnet and private subnet/s
    * You have created 2 network interfaces, one assigned to the public subnet
    * Disable SourceDestCheck on the network interfaces
    * The public network interface is assigned an elastic IP
    * An internet gateway is attached to the VPC
    * A route table exists for the VPC (default is ok) and allows outbound traffic 
      to the internet gateway.
    
    When associating the network interface, interface eth0 should be the network
    interface associated with the elastic (public) facing interface id.
    After creating the instance, manually add a new route table, and 
    route table entry that directs destination 0.0.0.0/0 to the NGFW 
    interface id for eth1 (not the instance). Then attach the new route table 
    to the private subnet.
    '''
    '''    
    vpc = VpcConfiguration('vpc-f1735e95').load()
    vpc.associate_network_interface(0, 'eni-49ab2635')
    vpc.associate_network_interface(1, 'eni-0b931e77')
    vpc.authorize_security_group_ingress('0.0.0.0/0', ip_protocol='-1')
    
    userdata = create_ngfw_in_smc(name='aws-02', 
                                  interfaces=vpc.build_ngfw_interfaces(),
                                  domain_server_address=['8.8.8.8', '8.8.4.4'])
    
    instance = vpc.launch(key_pair='aws-ngfw', userdata=userdata)
    for message in wait_for_ready(instance):
        print message
    '''
    session.logout()
