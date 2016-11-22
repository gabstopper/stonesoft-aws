###Deploy Stonesoft NGFW into AWS

Python based tool to auto-deploy Stonesoft NGFW into Amazon Web Services.

Features:
* Create a full VPC and subnets and auto-attach a NGFW
* Full provisioning of NGFW in Stonesoft Management Center
* Auto-rollback of VPC and NGFW in case of operational failures during processing

Requirements:
Stonsoft Management Center >= 6.1

When launching, you have several switches available:

-i -> Enter interactive mode, prompting for all settings. If SMC login settings are stored in ~.smcrc, these can be omitted

-y <yaml file> -> File to pull credential and configuration information from

-n -> no log (good for devops deploys where you want to suppress output) - will still log ERROR

-d -> delete existing VPC and running instances using menu prompt

As mentioned above, SMC credential information can be stored in either ~.smcrc or the file specified with -y <yaml file>. If the
credentials are in yaml, they will be used. If omitted from yaml, ~.smcrc will be checked. 

AWS credentials can be stored in a similar fashion. If stored in <yaml file>, the access_key and id will be retrieved when 
-y <yaml file> is specified. If they are omitted from the yaml file, credentials are obtained through normal boto3 methods
such as ~/.aws/credentials, etc.

It is recommended to run -i <interactive mode> the first time through which will provide proper formatting for the 
yaml configuration automatically. Once run the first time, subsequent runs can be done using -y <yaml>.

Launch in interactive mode (writes out yaml file):

```python
python launcher.py -i
```

Launch using yaml file without logging:

```python
python launcher.py -y /path/to/config.yml -n
```

Launch using yaml and delete an existing VPC, disable logging:

```python
python launcher.py -d /path/to/config.yml -d -n
```


