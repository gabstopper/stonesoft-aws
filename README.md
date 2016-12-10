###Deploy Stonesoft NGFW into AWS

Python based tool to auto-deploy Stonesoft NGFW into Amazon Web Services.

####Features:
* Create a full VPC and define subnets, then auto-attach a Stonesoft NGFW
* Full provisioning of NGFW in Stonesoft Management Center
* Auto-rollback of VPC and NGFW in case of operational failures during processing

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
ngfw_launcher -h ..... 
```

Available options:
```
Stonesoft NGFW AWS Launcher

optional arguments:
  -h, --help            show this help message and exit
  -i, --interactive     Use interactive prompt mode
  -y YAML, --yaml YAML  Specify yaml configuration file name
  -d, --delete          Delete a VPC using prompt mode
  -r, --remove          Remove ngfw from vpc (menu)
  -a, --add             Add ngfw to vpc (menu)
  -n, --nolog           Disable logging to console
```

It is recommended to run -i <interactive mode> the first time through which will provide proper formatting for the 
yaml configuration automatically. Once run the first time, subsequent runs can be done using -y <yaml>.

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
| vpc_subnet | VPC subnet to create, i.e. 192.168.3.0/24 | str | True |
| vpc_public | VPC public network, should be within network specified for vpc_subnet, i.e. 192.168.3.0/25 | str | True | 
| vpc_private | VPC private network, should be within network specified for vpc_subnet, i.e. 192.168.3.240/28 | str | True |
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
|location | Location to assign NGFW. Used when SMC is behind NAT | str | False |
|dns | DNS to assign NGFW. Required if AV/GTI are True| list | False |
|name |Temporary name to assign NGFW. By default, firewalls are renamed to instance ID| str | False |
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

Launch in interactive mode (writes out yaml file):

```python
ngfw_launcher.py -i
```

Launch using yaml file without logging:

```python
ngfw_launcher.py -y /path/to/config.yml -n
```

Launch using yaml and delete an existing VPC, disable logging (this is interactive as delete prompts based on available VPC's using AWS credentials):

```python
ngfw_launcher.py -y /path/to/config.yml --delete -n
```

Launch using yaml and add NGFW to an existing VPC (user input required):

```python
ngfw_launcher.py -y /path/to/config.yml --add
```

Launch using yaml and remove NGFW from an existing VPC (user input required):

```python
ngfw_launcher.py -y /path/to/config.yml --add
```


