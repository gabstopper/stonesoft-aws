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
* smc-python>=0.4.12
* boto3
* ipaddress
* pyyaml
'''
from __future__ import print_function
import threading
import time
import yaml
import logging
import botocore
from smc import session
from deploy.aws import (
    AWSConfig, VpcConfiguration,
    spin_up_host, next_available_subnet, 
    create_tag, remove_ngfw_from_vpc, 
    select_vpc, installed_as_list_view,
    list_all_subnets, list_tagged_instances, 
    select_unused_subnet, select_instance, 
    select_delete_vpc, get_ec2_client, 
    rollback_existing_vpc, validate_aws, select_deploy_style, map_az_to_subnet,
    VpcConfigurationError, rollback, get_ec2_resource, get_boto3_session)
from deploy.ngfw import NGFWConfiguration, validate, get_smc_session,\
    del_fw_from_smc
from deploy.validators import prompt_user
from smc.api.exceptions import CreateEngineFailed, NodeCommandFailed
from smc.core.waiters import ConfigurationStatusWaiter
try:
    from queue import Queue
except ImportError:
    from Queue import Queue
    
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
    ngfw = NGFWConfiguration(**ngfw)

    try:
        vpc.create_network_interface(0, awscfg.vpc_public, description='stonesoft-public') 
        vpc.create_network_interface(1, awscfg.vpc_private, description='stonesoft-private')
        
        # If user wants a client AMI, launch in the background
        if awscfg.aws_client_ami:
            logger.info('Launching client AMI with id: {}'.format(awscfg.aws_client_ami))
            ngfw.aws_ami_ip = spin_up_host(awscfg.aws_keypair, vpc, awscfg.aws_client_ami)
    
        ngfw_init = deploy(vpc, ngfw, awscfg)
        return task_runner(ngfw_init)
        
    except (botocore.exceptions.ClientError, CreateEngineFailed,
            NodeCommandFailed) as e:
        logger.error('Caught exception, rolling back: {}'.format(e))
        rollback(vpc.vpc)
        if ngfw.engine:
            del_fw_from_smc([ngfw.name])
        return [('Failed deploying VPC', [str(e)])]

def create_inline_ngfw(subnets, public, awscfg, ngfw, queue):
    '''
    Use Case 2: Deploy NGFW into existing VPC
    -----------------------------------------
    This assumes the following:
    * You have an existing VPC with one or more subnets
    * Available elastic IP per NGFW
    * Available /28 subnets in VPC network, one for each AZ NGFW
    
    When NGFW is injected into an existing VPC, the deployment strategy will
    obtain the defined network address space for the VPC. It will create a 
    'private' supernet using a /28 subnet on the uppermost side of the VPC
    network. For example, a VPC network of 172.16.0.0/16 will result in a 
    new subnet created 172.31.255.240/28. This will act as the 'public' side of
    the NGFW (creating a small subnet prevents wasted address space). This public
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
    
    :param list ec2.Subnet subnets: subnets to inject ngfw
    :param str public: public network for ngfw instance
    :param AWSConfig awscfg: aws config
    :param dict ngfw: ngfw configuration
    :param Queue queue: reference to result queue
    '''
    vpc = VpcConfiguration(subnets[0].vpc.id).load()
    ngfw = NGFWConfiguration(**ngfw)     
    
    logger.info('Creating NGFW as Inline Gateway in availability zone: {} with '
                'subnets: {}'.format(subnets[0].availability_zone, subnets))
    
    try:
        # Create public side network for interface 0 using the /28 network space
        vpc.create_network_interface(0, cidr_block=public, 
                                     availability_zone=subnets[0].availability_zone,
                                     description='stonesoft-public')
        
        # Each ec2 Subnet gets it's own network interface and route table
        intf = 1
        for subnet in subnets:
            vpc.create_network_interface(intf, ec2_subnet=subnet, description='stonesoft-private')
            intf += 1
    
        ngfw_init = deploy(vpc, ngfw, awscfg)
        task_runner(ngfw_init, queue)
    
    except (botocore.exceptions.ClientError, CreateEngineFailed,
            NodeCommandFailed) as e:
        logger.error('Caught exception, rolling back: {}'.format(e))
        queue.put(('{}, {}:'.format(subnets[0].availability_zone, subnets), [str(e)]))
        rollback_existing_vpc(vpc, subnets)
        if ngfw.engine:
            del_fw_from_smc([ngfw.name])

def create_as_nat_gateway(subnets, public, awscfg, ngfw, queue):
    
    vpc = VpcConfiguration(subnets[0].vpc.id).load()
    ngfw = NGFWConfiguration(**ngfw)

    logger.info('Creating NGFW as a NAT Gateway in availability zone: {} with '
                'subnets: {}'.format(subnets[0].availability_zone, subnets))
    
    try:
        # Create public side network for interface 0 using the /28 network space
        vpc.create_network_interface(0, cidr_block=public, 
                                     availability_zone=subnets[0].availability_zone,
                                     description='stonesoft-public')
        
        # Change route tables of any subnets specified to use NAT Gateway
        interface = [intf.get(0) for intf in vpc.network_interface][0]
        for subnet in subnets:
            vpc.assign_route_table(subnet, interface)
        ngfw_init = deploy(vpc, ngfw, awscfg)
        task_runner(ngfw_init, queue)
        
    except (botocore.exceptions.ClientError, CreateEngineFailed,
            NodeCommandFailed) as e:
        logger.error('Caught exception, rolling back: {}'.format(e))
        queue.put(('{}, {}:'.format(subnets[0].availability_zone, subnets), [str(e)]))
        rollback_existing_vpc(vpc, subnets)
        if ngfw.engine:
            del_fw_from_smc([ngfw.name])
                
def task_runner(ngfw, queue=None, sleep=5, duration=48):
    """ 
    Start the tasks running, first wait for the NGFW to 
    make initial contact. Sleep and duration controls how
    often polling occurs and for how long. Then execute
    upload policy and return overall results to queue
    """
    # Wait max of 4 minutes for initial contact
    waiter = ConfigurationStatusWaiter(ngfw.engine.nodes[0], 'Configured')
    logger.info('Waiting for NGFW: %s initial contact. ', ngfw.engine.name)
    while not waiter.done():
        waiter.wait(sleep)

    result = []
    if waiter.result() == 'Configured':
        ngfw.bind_license()
        # Start policy upload
        policy_task = ngfw.upload_policy(
            timeout=sleep,
            duration=duration)
        
        if policy_task:
            while not policy_task.done():
                status = policy_task.result(sleep)
                logger.info('[{}]: policy progress -> {}%'.format(
                    ngfw.name, status.progress))
    
            if not policy_task.task.success:
                result = [policy_task.last_message]
            else:
                logger.info('Upload policy task completed for {} in {} seconds'.format(
                    ngfw.name, (policy_task.task.end_time - policy_task.task.start_time).total_seconds()))
    else:
        result = ['Timed out waiting for initial contact, manual intervention required']
    
    if queue:
        queue.put((ngfw.engine.name, result))
    return [(ngfw.engine.name, result)]
  
           
def generate_report(results):
    """
    Generate report if errors
    """
    for result in results:
        name, errors = result
        if not errors:
            logger.info('Finished running stonesoft deploy for: {}'.format(name))
        else:
            logger.error('Exception occurred deploying: {}, reason: {}'.format(
                name, errors[0]))
        
def deploy(vpc, ngfw, awscfg):
    """
    Execute the deploy. This can raise botocore.exceptions.ClientError or
    smc.api.exceptions.CreateEngineFailed exceptions and should be wrapped
    if needed by calling function/method.
    
    :return NGFWConfiguration updated instance
    """
    interfaces, gateway = vpc()
    
    # Specific location for this Firewall
    location_name = '{}-{}'.format(vpc.availability_zone,vpc.elastic_ip)
           
    ngfw(interfaces, gateway, location_name)
    
    #NodeCommandFailed means initial contact failed and we don't have userdata
    userdata = ngfw.initial_contact()
    ngfw.add_contact_address(vpc.elastic_ip)

    instance = vpc.launch(key_pair=awscfg.aws_keypair, 
                          userdata=userdata, 
                          imageid=awscfg.ngfw_ami,
                          instance_type=awscfg.aws_instance_type)

    instance.create_tags(Tags=create_tag())

    logger.info('Elastic (public) IP address is set to: {}, ngfw instance id: {}'
                .format(vpc.elastic_ip, instance.id))
                
    logger.info('To connect to your NGFW AWS instance, execute the command: '
                'ssh -i {}.pem aws@{}'.format(instance.key_name, vpc.elastic_ip))
                           
    # Rename NGFW to AMI instance id (availability zone)
    ngfw.rename('{} ({})'.format(instance.id, vpc.availability_zone))
    ngfw.add_policy()
    return ngfw

def main():

    logger = logging.getLogger()
    formatter = logging.Formatter('%(asctime)s (%(threadName)-8s) [%(levelname)s] - %(name)s %(message)s')
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    
    from deploy import __version__
    import argparse
    parser = argparse.ArgumentParser(description='Stonesoft NGFW AWS Launcher')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-y', '--yaml', help='Specify yaml configuration file name')
    group.add_argument('configure', nargs='?', help='Initial configuration wizard')
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument('--delete_vpc', action='store_true', help='Delete a VPC (menu)')
    actions.add_argument('--create_vpc', action='store_true', help='Create a VPC with NGFW')
    actions.add_argument('-r', '--remove', action='store_true', help='Remove NGFW from VPC (menu)')
    actions.add_argument('-a', '--add', action='store_true', help='Add NGFW to existing VPC (menu)')
    actions.add_argument('-l', '--list', action='store_true', help='List NGFW installed in VPC (menu)')
    actions.add_argument('-la', '--listall', action='store_true', help='List all NGFW instances in AZs')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('--version', action='version',
                        version='%(prog)s {version}'.format(version=__version__))
    
    args = parser.parse_args()
    
    if not any(vars(args).values()):
        parser.print_help()
        parser.exit()
 
    logger.setLevel(logging.INFO)
    logging.getLogger('smc').setLevel(logging.ERROR)
    logging.getLogger('boto3').setLevel(logging.CRITICAL)
    logging.getLogger('botocore').setLevel(logging.CRITICAL)
    
    if args.verbose:
        logging.getLogger('smc').setLevel(logging.INFO)
        logging.getLogger('requests').setLevel(logging.INFO)
        logging.getLogger('boto3').setLevel(logging.INFO)
        logging.getLogger('botocore').setLevel(logging.INFO)
    
    print()
    print('Stonesoft AWS Launcher')
    print("======================")
    print()
    
    if args.configure:
        path = prompt_user()
        print('Configuration complete. You can launch the script using '
              'the -y {} for subsequent operations.'.format(path))
        return
    
    if args.yaml:
        path = args.yaml
    with open(path, 'r') as stream:
        try:
            data = yaml.safe_load(stream)
            awscfg = AWSConfig(**data.get('AWS'))
            ngfw = data.get('NGFW')
            smc = data.get('SMC')
        except yaml.YAMLError as exc:
            print(exc)
    
    if args.listall:
        aws_session = get_boto3_session()
        template = '{0:22}|{1:20}|{2:12}|{3:12}|{4:12}'
        vpc_template = '{0:15}|' 
        print(vpc_template.format('VPC ID'), 
              template.format('Instance ID', 'Availability Zone', 'Type', 'State', 'Launch Time'))
        for region in aws_session.get_available_regions('ec2'):
            ec2 = get_ec2_resource(
                awscfg.aws_access_key_id,
                awscfg.aws_secret_access_key,
                region)
            for vpc in ec2.vpcs.filter():
                instances = installed_as_list_view(vpc)
                if instances:
                    for instance in instances:
                        print(vpc_template.format(vpc.id), template.format(*instance))
        return
    
    get_ec2_client(awscfg, prompt_for_region=True)
    get_smc_session(smc)
    
    if args.remove:
        tagged = list_tagged_instances(select_vpc(as_instance=True))
        if tagged:
            instances = select_instance(tagged, as_instance=True)
            remove_ngfw_from_vpc(instances)
        else:
            print('Nothing to remove.')
        return
    
    if args.list:
        instances = installed_as_list_view(select_vpc(as_instance=True))
        if instances:
            template = '{0:22}|{1:20}|{2:12}|{3:12}|{4:12}' 
            print(template.format('Instance ID', 'Availability Zone', 'Type', 'State', 'Launch Time'))
            for instance in instances:
                print(template.format(*instance))
        return
    
    # Need the NGFW config validated for remaining options
    validate(**ngfw) #Raises if validation fails
    
    if args.add:
        validate_aws(awscfg)
        vpc = select_vpc(as_instance=True)
        subnets = select_unused_subnet(vpc, as_instance=True)
        if subnets:
          
            style = select_deploy_style()
            if style == 'Inline Gateway':
                style = create_inline_ngfw
            else: #NAT Gateway
                style = create_as_nat_gateway
              
            subnet_map = map_az_to_subnet(subnets)
           
            itr = next_available_subnet(list_all_subnets(vpc), vpc.cidr_block)
            q = Queue()
            pool, subnet_keys, results = ([] for i in range(3))
            try:
                for zone, subnets in subnet_map.items():
                    t = threading.Thread(target=style,
                                         args=[subnets, next(itr), awscfg, ngfw, q])
                    pool.append(t)
                    subnet_keys.append(zone)
            except StopIteration:
                for zone in subnet_keys:
                    del subnet_map[zone]
                results.append((subnet_map, ['No available network addresses in VPC to create '
                                             'NGFW in the following subnets. Skipping.']))
            finally:
                for thread in pool:
                    thread.start()      
                start_time = time.time()
        
                for thread in pool:
                    thread.join()
                    response = q.get()
                    results.append(response)
                    
            generate_report(results)
            logger.info("Process completed in %s seconds" % (time.time() - start_time))
        else:
            print('No unused subnets available.')
        return
    
    if args.delete_vpc:
        selection = select_delete_vpc()
        vpc = VpcConfiguration(selection).load()
        try:
            rollback(vpc.vpc)
        except VpcConfigurationError as e:
            logger.error(e)

    if args.create_vpc:
        validate_aws(awscfg, vpc_create=True)
        start_time = time.time()
        results = create_vpc_and_ngfw(awscfg, ngfw)
        generate_report(results)
        logger.info("Process completed in %s seconds" % (time.time() - start_time))
    
    session.logout()

if __name__ == '__main__':
    main()