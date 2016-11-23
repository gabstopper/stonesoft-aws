###Deploy Stonesoft NGFW into AWS

Python based tool to auto-deploy Stonesoft NGFW into Amazon Web Services.

####Features:
* Create a full VPC and subnets and auto-attach a Stonesoft NGFW
* Full provisioning of NGFW in Stonesoft Management Center
* Auto-rollback of VPC and NGFW in case of operational failures during processing

####Requirements:
Stonsoft Management Center >= 6.1

smc-python >=0.3.8

python 2.7.x

####Installation:

```python
virtualenv venv
. venv/bin/activate
pip install git+https://github.com/gabstopper/stonesoft-aws.git --process-dependency-links
```

**Note: Installing using pip will install required dependencies

After installation, program can be run by either:

```python
ngfw_launcher .....
python -m ngfw_launcher ...
```

When launching, you have several switches available:

+ -i: Enter interactive mode, prompting for all settings. SMC and AWS credentials can be omitted if stored in respective ~.smcrc or .aws/credentials files

+ -y <yaml file>: File to pull credential and configuration information from

+ -n: no log (good for devops deploys where you want to suppress output) - will still log ERROR

+ -d: delete existing VPC and running instances using menu prompt

As mentioned above, SMC credential information can be stored in either ~.smcrc or the file specified with -y <yaml file>. If the
credentials are in yaml, they will be used. If omitted from yaml, ~.smcrc will be checked. 

AWS credentials can be stored in a similar fashion. If stored in a yaml file, the access_key and id will be retrieved when 
-y <yaml file> is specified. If they are omitted from the yaml file, credentials are obtained through normal boto3 methods
such as ~/.aws/credentials, etc.

It is recommended to run -i <interactive mode> the first time through which will provide proper formatting for the 
yaml configuration automatically. Once run the first time, subsequent runs can be done using -y <yaml>.
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

___

Launch in interactive mode (writes out yaml file):

```python
ngfw-launcher.py -i
```

Launch using yaml file without logging:

```python
ngfw-launcher.py -y /path/to/config.yml -n
```

Launch using yaml and delete an existing VPC, disable logging (this is interactive as delete prompts based on available VPC's using AWS credentials):

```python
python ngfw-launcher.py -d /path/to/config.yml -d -n
```


