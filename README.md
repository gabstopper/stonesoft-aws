[![Documentation Status](https://readthedocs.org/projects/stonesoft-aws/badge/?version=latest)](http://stonesoft-aws.readthedocs.io/en/latest/?badge=latest)

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
Stonsoft Management Center >= 6.2

smc-python >=0.4.10

python 2.7.x, 3.4, 3.5

####Installation:

```
virtualenv venv
. venv/bin/activate
pip install git+https://github.com/gabstopper/stonesoft-aws.git
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
  -d, --delete_vpc      Delete a VPC (menu)
  -c, --create_vpc      Create a VPC with NGFW
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

Examples of operations:
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
ngfw_launcher.py -y /path/to/config.yml --delete_vpc
```

Create a new VPC with NGFW. Note, this requires vpc_subnet, vpc_private and vpc_public settings in
the yaml configuration:

```
ngfw_launcher.py -y /path/to/config.yml --create_vpc --verbose
```

