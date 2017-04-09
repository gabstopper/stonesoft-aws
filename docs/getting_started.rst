Getting Started
===============

The following version requirements have been tested:

* Stonsoft Management Center >= 6.2
* smc-python >=0.4.1
* python 2.7.x, 3.4, 3.5


Installation of stonesoft-aws into a virtualenv:

::

	virtualenv venv
	. venv/bin/activate
	pip install git+https://github.com/gabstopper/stonesoft-aws.git --process-dependency-links

Once installed, you will have an executable, ``ngfw_launcher`` in your python path.

::

	Stonesoft NGFW AWS Launcher
	
	positional arguments:
	  configure             Initial configuration wizard
	
	optional arguments:
	  -h, --help            show this help message and exit
	  -y YAML, --yaml YAML  Specify yaml configuration file name
	  --delete_vpc          Delete a VPC (menu)
	  --create_vpc          Create a VPC with NGFW
	  -r, --remove          Remove NGFW from VPC (menu)
	  -a, --add             Add NGFW to existing VPC (menu)
	  -l, --list            List NGFW installed in VPC (menu)
	  -la, --listall        List all NGFW instances in AZs
	  -v, --verbose         Enable verbose logging
	  --version             show program's version number and exit

It is recommended to start by running ``ngfw_launcher configure`` to step through the configuration questions that
will help build a yaml configuration file that can be re-used for multiple executions.

Some action options will display an interactive menu which retrieves data from AWS to get up to date configuration data.

