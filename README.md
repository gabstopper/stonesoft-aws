###Deploy Stonesoft NGFW into AWS

Python based tool to auto-deploy Stonesoft NGFW into Amazon Web Services.

####Features:
* Create a full VPC and define subnets, then auto-attach a Stonesoft NGFW
* Full provisioning of NGFW in Stonesoft Management Center
* Auto-rollback of VPC and NGFW in case of operational failures during processing

####Requirements:
Stonsoft Management Center >= 6.1

smc-python >=0.4.0

python 2.7.x, 3.4, 3.5

####Installation:

```python
virtualenv venv
. venv/bin/activate
pip install git+https://github.com/gabstopper/stonesoft-aws.git --process-dependency-links
```

####Quick Start:


After installation, program can be run by:

```python
ngfw_launcher -h ..... 
```

When launching, you have several switches available:

+ -i: Enter interactive mode, prompting for all settings. SMC and AWS credentials can be omitted if stored in respective ~.smcrc or .aws/credentials files

+ -y <yaml file>: File to pull credential and configuration information from

+ -l: no log (good for devops deploys where you want to suppress output) - will still log ERROR

+ -d: delete existing VPC and running instances using menu prompt

It is recommended to run -i <interactive mode> the first time through which will provide proper formatting for the 
yaml configuration automatically. Once run the first time, subsequent runs can be done using -y <yaml>.

####Configuration Options

Configuration can be provided in a yaml file to enable hands off automation for deployment. There are three main configuraton sections with several fields being optional.

These are documented below:
___

#####AWS Configuration Options:

| Option | Description |
| :------| :-----------|
| aws_access_key_id (string)| AWS access key. Optional if stored in AWS credential locations |
| aws_secret_access_key (str)| AWS secret key. Optional if stored in AWS credential locations |
| aws_instance_type (str)| Instance type to launch in (t2.micro, etc). Required. |
| aws_keypair (str)| Keypair for connecting to NGFW AWS AMI instance. Required. |
| aws_region (str)| AWS region to launch instance. Required. If not provided, menu will be displayed|
| vpc_subnet (str)| VPC subnet to create, i.e. 192.168.3.0/24. Required. |
| vpc_public (str)| VPC public network, should be within network specified for vpc_subnet, i.e. 192.168.3.0/25. Required.|
| vpc_private (str)| VPC private network, should be within network specified for vpc_subnet, i.e. 192.168.3.240/28. Required.|
| ngfw_ami (str) | Stonesoft NGFW AMI id to launch. Required. |
| aws_client (True/False)| Whether to launch an AWS client host on public subnet. Optional. |
| aws_client_ami (str)| AWS Client AMI. Required if aws_client is True |


##### Stonesoft NGFW Configuration Options:

| Option | Description |
| :------| :-----------|
|antivirus (True/False)| Enable AntiVirus on NGFW. Optional.|
|gti (True/False)| Enable GTI on NGFW. Optional.|
|default_nat (True/False)| Enable default NAT on NGFW. Default True|
|firewall_policy (str) | Layer 3 Firewall Policy to assign NGFW. Required|
|location (str)| Location to assign NGFW. Used when SMC is behind NAT. Optional.|
|dns (list)| DNS to assign NGFW. Required if AV/GTI are True|
|name (str)|Temporary name to assign NGFW. By default, firewalls are renamed to instance ID|
|vpn_policy (str)|Assign to VPN policy. Optional.|
|vpn_role (str)|Role for VPN gateway (central/satellite). Default: Central|

##### Stonesoft Management Center (SMC) Configuration Options:

| Option | Description |
| :------| :-----------|
|smc_address (str)|IP Address of Stonsoft Management Center. Optional.|
|smc_apikey (str)| API Client key used for authentication. Optional.|
|smc_port (str)| Port for SMC API. Default 8082|
|api_version (str) | Specific version of API. Default: latest|
|smc_ssl (True/False)| Whether to use SSL to SMC API. Optional.|
|verify_ssl (True/False)| If using SSL, whether to verify client cert. Optional.|
|ssl_cert_file (str)| Full path to cert file if validating SSL client cert. Optional.|
|timeout (int) | Timeout between client and SMC API. Optional. Default: 10s|

Credential information for AWS and Stonesoft SMC is optional within the yaml file if provided in each respective preference files.

SMC credential information can be stored in either ~.smcrc or the file specified with -y <yaml file>. If the
credentials are in yaml, they will be used. If omitted from yaml, ~.smcrc will be checked. 

AWS credentials can be stored in a similar fashion. If stored in the yaml configuration, the access_key and id will be retrieved when 
-y <yaml file> is specified. If they are omitted, credentials are obtained through normal boto3 methods such as ~/.aws/credentials, etc.

___

Launch in interactive mode (writes out yaml file):

```python
ngfw_launcher.py -i
```

Launch using yaml file without logging:

```python
ngfw_launcher.py -y /path/to/config.yml -l
```

Launch using yaml and delete an existing VPC, disable logging (this is interactive as delete prompts based on available VPC's using AWS credentials):

```python
ngfw_launcher.py -d /path/to/config.yml -d -l
```


