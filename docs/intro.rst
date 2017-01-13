Introduction
============

Stonesoft deploy for AWS provides a command line method to fully provision and automate deployment of NGFW into 
Amazon Web Services and Stonesoft Management Center. A full provision can be done in a manner of minutes.

Features include:

*	Creating a new VPC with NGFW
*	Deploy into an existing VPC
*	Full provision of NGFW into Security Management Center
*	Deployment as Inline Gateway or Secure NAT Gateway
*	Automated policy configuration (includes VPN)
*	VPN Gateway
*	IDS/IPS

Use Cases:

*	Segment VPC Peering subnets to protect sensitive servers
*	Full Mesh VPN from region-to-region back to Corporate
*	Secure NAT Gateway for private host internet connectivity
*	High performance, unified management and visibility for cloud instances

Inline Gateway
--------------

Stonesoft can be configured with a multi-interface FW as an inline secure gateway. This configuration creates a ‘public’ subnet that will use the AWS Internet Gateway as the next hop network. Additional interfaces are attached to the subnet/s associated with the ‘private’ (existing) subnets and act as the next hop gateway for all traffic.

In this scenario, NGFW provides enhanced performance and tighter control over inbound/outbound traffic. A use case for this scenario is protection between a VPC peering where you might require more visibility or inspection capabilities, like from a database subnet to a web tier subnet.

*	Inline traffic from individual subnet/s
*	Enhanced performance (faster TX/RX in inline vs. NAT Gateway)
*	NAT redirection / PAT
*	IPS/IDS
*	VPN
*	DPI with optional transparent Proxy services

When deploying into an existing VPC, this configuration will create a public subnet using the VPC network address space, using the first available /28 subnet on the high end of the VPC network. It will create a single Stonesoft network interface (eth0) for management and have a single network interface attached to the subnet network. 

The Main routing table will be untouched and inherited by the public subnet. A new route table will be created for the inline subnet and assigned a next hop for 0.0.0.0/0 using the NGFW network interface (ethX) attached to the subnet.

No explicit NAT rule is required in Stonesoft policy as Default NAT will be enabled and auto-associate internal subnets to source NAT using the NGFW auto-assigned address.


NAT Gateway
-----------

Deploying as a Secure NAT Gateway provides the benefit of having a simplified deployment of a single instance (or multiple) FW in a single VPC. The primary benefits allowing for outbound or
Inbound traffic management including:

*	NAT redirection / PAT
*	IPS/IDS
*	VPN
*	DPI with optional transparent Proxy services

When deploying into an existing VPC, this configuration will create a public subnet using the VPC network address space, using the first available /28 subnet on the high end of the VPC network. It will create a single Stonesoft network interface (eth0) for management and have a single network interface attached to the subnet network. 

Subnets selected will use a custom route table that copies any existing routes and uses Stonesoft as the gateway for the 0.0.0.0/0 network.

VPN Gateway
-----------

Either Inline Gateway or NAT Gateway can be used as a VPN gateway instance within AWS. It is more typical to leverage the Inline Gateway role as a VPN
gateway.
Using Stonesoft as a VPN gateway in AWS may provide simplified configuration and visibility with other Stonesoft Firewalls managed from Stonesoft
Management Center. 

.. note:: 
   It is possible to use native AWS Virtual Private Gateways and configure Stonesoft as a Customer Gateway using RBVPN with either static routing or
   BGP
