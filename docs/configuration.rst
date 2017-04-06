Configuration
=============

Stonesoft deployer requires credential information for AWS EC2 and an API Client credential for Stonesoft Management Center.

These credentials will be used to make modifications in their respective environments.

YAML configuration is used to provide common settings that will be consistent across deployment executions. This 
section will describe the configuration options available.

If a setting is tagged as not required, it can be entirely omitted from the configuration.

Other required settings will be validated before operations are performed on either AWS or Stonesoft SMC.

.. note::

   It is recommended to run ``ngfw_launcher configure`` the first time to get a template YAML
   file.

The remaining configuration information will explain the configuration file sections and relevant settings.

Key things to note:

When Stonesoft is installed in AWS, it will carve out the smallest possible subnet for the 'untrust', or
internet side, typically this is a /28. When running the installer you can specify which VPC subnet to use
if inserting Stonesoft into an existing VPC (versus creating a new VPC with this same tool).

A firewall policy will be dynamically created named ``Default_AWS`` unless overidden in the configuration
YML file using the ``firewall_policy`` setting.

If a client AMI is specified, a client instance will be spun up on the 'trust' side network. An inbound access
and NAT rule is automatically created in SMC based on the client's native IP address. The client can be any
client AMI. In addition, to configure client inbound ports, set ``inbound_nat`` to define inbound to AWS
port and redirect_port to client.


AWS options
-----------

AWS options can be provided to simplify deployment and maintain a common location for credential
and other preference information. Some settings for AWS are mandatory and will affect how the 
NGFW will be deployed. 

See the following AWS available options below:

+------------------------+--------------------------------+----------+----------+
| Option                 | Description                    | Type     | Required |
|                        |                                |          |          |
+========================+================================+==========+==========+
| aws_access_key_id      | AWS access key                 | str      | No       |
+------------------------+--------------------------------+----------+----------+
| aws_secret_access_key  | AWS secret key                 | str      | No       |
+------------------------+--------------------------------+----------+----------+
| aws_keypair            | AWS keypair for launch         | str      | Yes      |
|                        | configuration                  |          |          |
+------------------------+--------------------------------+----------+----------+
| aws_instance_type      | Instance type to launch        | str      | Yes      |
|                        | (t2.micro, c4.large, etc)      |          |          |
+------------------------+--------------------------------+----------+----------+
| aws_region             | AWS region for launch instance | str      | No       |
+------------------------+--------------------------------+----------+----------+

.. note::
   ``aws_access_key_id`` and ``aws_secret_access_key`` are optional settings. If 
   these are omitted, boto3 will attempt to retrieve credential information through 
   it's normal process.

If ``aws_region`` is not provided, a prompt menu will be displayed and require user interaction to
select the region. The region may also be provided in boto3 client locations.

In addition to the settings above, if creating a new VPC and NGFW configuration the following
settings are available:

+------------------------+--------------------------------+----------+----------+
| Option                 | Description                    | Type     | Required |
|                        |                                |          |          |
+========================+================================+==========+==========+
| vpc_subnet             | VPC subnet to create           | str      | Yes      | 
|                        | (192.168.3.0/24)               |          |          |
+------------------------+--------------------------------+----------+----------+
| vpc_public             | Public subnet                  | str      | Yes      |
|                        | (192.168.3.240/28)             |          |          |
+------------------------+--------------------------------+----------+----------+
| vpc_private            | Private subnet (192.168.3.0/25)| str      | Yes      |
+------------------------+--------------------------------+----------+----------+
| aws_client_ami         | Client AMI to launch in private| str      | No       |
|                        | subnet (optional)              |          |          |
+------------------------+--------------------------------+----------+----------+

.. note::
   ``vpc_private`` and ``vpc_public`` need to be networks contained within the VPC subnet
   
``aws_client_ami`` is only used when creating a new VPC. It is a convenience option to
automatically spin up a new host machine behind Stonesoft NGFW for testing. If you want
to automatically create a firewall rule to allow the inbound traffic, see the ``inbound_nat``
setting in the ngfw configuration section below.		
   
NGFW options
------------

Stonesoft NGFW options are available to provide common configuration settings to enable or
disable on the deployed instance. 

+------------------------+--------------------------------+----------+----------+
| Option                 | Description                    | Type     | Required |
|                        |                                |          |          |
+========================+================================+==========+==========+
| antivirus              | Enable AV (False)              | boolean  | No       | 
+------------------------+--------------------------------+----------+----------+
| gti                    | Enable Global Threat           | boolean  | No       |
|                        | Intelligence (False)           |          |          |
+------------------------+--------------------------------+----------+----------+
| default_nat            | Enable NAT outbound (True)     | boolean  | No       |
+------------------------+--------------------------------+----------+----------+
| inbound_nat            | Inbound NAT dest and redirect  | int      | No       |
+------------------------+--------------------------------+----------+----------+
| firewall_policy        | Layer 3 Firewall Policy name   | str      | No       |
+------------------------+--------------------------------+----------+----------+
| nat_address            | NAT address of SMC if behind   | str      | No       |
|                        | NAT IP                         |          |          |
+------------------------+--------------------------------+----------+----------+
| dns                    | DNS servers (required if AV or | list     | No       |
|                        | GTI is enabled)                |          |          |
+------------------------+--------------------------------+----------+----------+

.. note::
   ``firewall_policy`` is not a required field, however because a policy is required to
   deploy the NGFW, a default policy named "Default_AWS" will be created allowing access 
   from the private subnet outbound. If ``firewall_policy`` is  defined, an attempt will 
   be made to validate the policy exists before running the automation.
   
If Antivirus or GTI is set to true, DNS settings will be required.

.. note:: 
   If SMC is behind a NAT device, provide a ``nat_address`` with the public IP address
   where the SMC can be contacted. 

``Inbound_nat`` is used to specify the destination port to allow for inbound connections
and the redirect port is used as the port to redirect to the internal client. For example,
you might set 'dest_port' to 2222, and redirect_port to '22' if you wanted to allow
inbound SSH on port 2222 and have it redirected to the internal client on port 22.

::

	inbound_nat:
	  redirect_port: 22
	  dest_port: 2222
   
    
If VPN is required, you can optionally add VPN specific settings into the NGFW configuration:

+------------------------+--------------------------------+----------+----------+
| Option                 | Description                    | Type     | Required |
|                        |                                |          |          |
+========================+================================+==========+==========+
| vpn_policy             | VPN Policy name                | str      | No       | 
+------------------------+--------------------------------+----------+----------+
| vpn_role               | VPN role (central|satellite)   | str      | No       |
+------------------------+--------------------------------+----------+----------+
| vpn_networks           | VPN networks                   | list     | No       | 
|                        | (1.1.1.0/24, 2.2.2.0/24)       |          |          |
+------------------------+--------------------------------+----------+----------+

``vpn_role`` - whether FW will act as a hub (central) gateway, or spoke (satellite) VPN; *default: central*
``vpn_networks`` - define the remote networks to grant access to for this VPN
   

SMC options
-----------

Stonesoft Management Server provides an API interface to all management capabilities for
NGFW. Settings provided for SMC are used for connectivity purposes. `smc-python <https://github.com/gabstopper/smc-python>`_ 
is used to interface with all configurations within SMC.

+------------------------+--------------------------------+----------+----------+
| Option                 | Description                    | Type     | Required |
|                        |                                |          |          |
+========================+================================+==========+==========+
| smc_address            | IP Address of Stonsoft         | str      | No       |
|                        | Management Center              |          |          | 
+------------------------+--------------------------------+----------+----------+
| smc_apikey             | API Client auth key            | str      | No       |
+------------------------+--------------------------------+----------+----------+
| smc_port               | SMC API port (8082/tcp)        | str/int  | No       |
+------------------------+--------------------------------+----------+----------+
| api_version            | SMC API Version (latest)       | str      | No       |
+------------------------+--------------------------------+----------+----------+
| smc_ssl                | Use SSL for API (False)        | boolean  | No       |
+------------------------+--------------------------------+----------+----------+
| verify_ssl             | Verify SSL Sessions (False)    | boolean  | No       |
+------------------------+--------------------------------+----------+----------+
| ssl_cert_file          | Client cert file for validation| str      | No       |
+------------------------+--------------------------------+----------+----------+
| timeout                | API Client timeout (10s)       | str/int  | No       |
+------------------------+--------------------------------+----------+----------+

.. note::
   All SMC options can be omitted if storing smc-python credentials in ~/.smcrc

Example configuration file:

::

	AWS:
	  aws_access_key_id: xxxxxxxxxxxxxxxxxx
	  aws_client_ami: ami-38cd975d
	  aws_instance_type: t2.micro
	  aws_keypair: blah-foo
	  aws_region: us-west-1
	  aws_secret_access_key: xxxxxxxxxxxxxxx
	  ngfw_ami: ami-xxxxxxxx
	  vpc_private: 192.168.4.0/25
	  vpc_public: 192.168.4.240/28
	  vpc_subnet: 192.168.4.0/24
	NGFW:
	  antivirus: true
	  default_nat: true
	  inbound_nat: 
    	dest_port: 2222
    	redirect_port: 22
	  gti: false
	  dns:
	  - 8.8.8.8
	  firewall_policy: Layer 3 Virtual FW Policy
	  nat_address: 1.1.1.1
	  vpn:
	    vpn_networks: ''
	    vpn_policy: Amazon AWS
	    vpn_role: central
	SMC:
	  smc_address: 172.18.1.xxx
	  smc_apikey: xxxxxxxxxxxxxxxxxxxxxx
	  smc_port: '8082'
	  smc_ssl: false
	  verify_ssl: true
	  ssl_cert_file: /Users/blah/mycert.pem
	  

	     
   