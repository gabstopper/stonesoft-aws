###Deploy Stonesoft NGFW into AWS

Python based tool to auto-deploy Stonesoft NGFW into Amazon Web Services.

This provides the automation to deploy Stonesoft NGFW into an existing AWS VPC or to create a new AWS VPC and attach
the Stonesoft NGFW. The process self registers the NGFW into the Stonesoft Management Center (SMC) and auto-creates all 
configurations to make this a fully manageable cloud FW in minutes. 

In addition to deployment, it is possible to list running NGFW instances in a VPC as well as remove individual instances
or all instances in a specific VPC. 

A simple prompting menu is provided to step you through the process and requires a valid AWS and an SMC API Client credential
to automate the object creation. These credentials are used to enumerate and perform the admin operations on both AWS and SMC.
 
####Features:
* Deploy Stonesoft NGFW in existing AWS VPC
* Deploy Stonesoft NGFW and create new VPC
* Site-to-Site VPN from AWS cloud to on-prem
* Full provisioning of NGFW in Stonesoft Management Center
* Auto-rollback of VPC and NGFW in case of operational failures during processing
* Automation for adding/removing devices flexibilty through either prompt menu or YAML expressions

####Requirements:
Stonsoft Management Center >= 6.1

smc-python >=0.4.1

python 2.7.x, 3.4, 3.5

####Installation:

```
virtualenv venv
. venv/bin/activate
pip install git+https://github.com/gabstopper/stonesoft-aws.git --process-dependency-links
```


####Quick Start:


After installation, program can be run by:

```
ngfw_launcher -h
```

Available options:
```
Stonesoft NGFW AWS Launcher

positional arguments:
  configure             Initial configuration wizard

optional arguments:
  -h, --help            show this help message and exit
  -y YAML, --yaml YAML  Specify yaml configuration file name
  -d, --delete          Delete a VPC (menu)
  -c, --create          Create a VPC with NGFW
  -r, --remove          Remove NGFW from VPC (menu)
  -a, --add             Add NGFW to existing VPC (menu)
  -l, --list            List NGFW installed in VPC (menu)
  -v, --verbose         Enable verbose logging
```

It is recommended to run 'configure' the first time through which will provide proper formatting for the 
yaml configuration. Once run the first time, subsequent runs can be done using -y \<yaml\>.

```
ngfw_launcher configure
```

YAML configuration can be used to provide settings when creating an entirely new VPC, otherwise if adding Stonesoft NGFW to 
an existing VPC, use --add. This will provide a menu of lists walking through the configuration, allowing you to specify
which availability zones to install into (or ALL) for a given region.

####Configuration Options

Configuration can be provided in a yaml file to enable hands off automation for deployment. There are three main configuraton sections with several fields being optional.

These are documented below:
___

#####AWS Configuration Options:

| Option | Description | Type | Required |
| :------| :-----------| :--- | :------- |
| aws_access_key_id | AWS access key. Optional if stored in AWS credential locations | str | False |
| aws_secret_access_key | AWS secret key. Optional if stored in AWS credential locations | str | False | 
| aws_instance_type | Instance type to launch in (t2.micro, etc) | str | True | 
| aws_keypair | Keypair for connecting to NGFW AWS AMI instance | str | True |
| aws_region | AWS region to launch instance. If not provided, menu will be displayed| str | False |
| vpc_subnet | VPC subnet to create, i.e. 192.168.3.0/24 | str | False |
| vpc_public | VPC public network, should be within network specified for vpc_subnet, i.e. 192.168.3.0/25 | str | False | 
| vpc_private | VPC private network, should be within network specified for vpc_subnet, i.e. 192.168.3.240/28 | str | False |
| ngfw_ami | Stonesoft NGFW AMI id to launch | str | True |
| aws_client | Whether to launch an AWS client host on public subnet | boolean | False |
| aws_client_ami | AWS Client AMI. Required if aws_client is True | str | False |


##### Stonesoft NGFW Configuration Options:

| Option | Description | Type | Required |
| :------| :---------- | :--- | :------- |
|antivirus | Enable AntiVirus on NGFW (default: False) | boolean | False |
|gti | Enable GTI on NGFW (default: False) | boolean | False |
|default_nat | Enable default NAT on NGFW (default: True) | boolean | False |
|firewall_policy | Layer 3 Firewall Policy to assign NGFW | str | True |
|location | Location to assign NGFW. Used when SMC is behind NAT | str | True |
|dns | DNS to assign NGFW. Required if AV/GTI are True| list | False |
|vpn_policy |Assign to VPN policy | str | False |
|vpn_role |Role for VPN gateway (central/satellite) (default: central) | str | True |


##### Stonesoft Management Center (SMC) Configuration Options:

| Option | Description | Type | Required |
| :------| :---------- | :--- | :------- |
|smc_address |IP Address of Stonsoft Management Center | str | False |
|smc_apikey | API Client key used for authentication | str | False |
|smc_port | Port for SMC API (default: 8082) | str/int | False |
|api_version | Specific version of API (default: latest) | str | False |
|smc_ssl | Whether to use SSL to SMC API (default: False) | boolean | False |
|verify_ssl | If using SSL, whether to verify client cert (default: False) | boolean | False |
|ssl_cert_file | Full path to cert file if validating SSL client cert | str | True |
|timeout | Timeout between client and SMC API (default: 10) | int |False|

Credential information for AWS and Stonesoft SMC is optional within the yaml file if provided in each respective preference files.

SMC credential information can be stored in either ~/.smcrc or the file specified with -y <yaml file>. If the
credentials are in yaml, they will be used. If omitted from yaml, ~/.smcrc will be checked. 

AWS credentials can be stored in a similar fashion. If stored in the yaml configuration, the access_key and id will be retrieved when 
-y <yaml file> is specified. If they are omitted, credentials are obtained through normal boto3 methods such as ~/.aws/credentials, etc.

___

Deploy Stonesoft NGFW into an existing VPC with verbose logging:
```
ngfw_launcher -y /path/to/config.yml --add --verbose
```

Remove Stonesoft NGFW from an existing VPC:

```
ngfw_launcher.py -y /path/to/config.yml --remove
```

List all NGFW instances running in VPC:

```
ngfw_launcher.py -y /path/to/config.yml --list
```

Delete a VPC created using this tool:

```
ngfw_launcher.py -y /path/to/config.yml --delete
```

Create a new VPC with NGFW. Note, this requires vpc_subnet, vpc_private and vpc_public settings in
the yaml configuration:

```
ngfw_launcher.py -y /path/to/config.yml --create --verbose
```

