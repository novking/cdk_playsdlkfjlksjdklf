from aws_cdk import Stack
from aws_cdk import aws_ec2
from aws_cdk import aws_networkfirewall as networkfirewall
from aws_cdk import Fn, CfnOutput, CfnTag

import typing

class FirewallStack(Stack):
    def _create_firewall_policy(self):
        rule_string = """
        pass http any any -> any any (http.host; content:"aws.amazon.com"; endswith; msg:"Allow HTTP access to AWS services"; sid:1000001; rev:1;)
        pass tls any any -> any any (tls.sni; content:"aws.amazon.com"; startswith; nocase; endswith; msg:"Permit HTTPS access to aws.amazon.com"; sid:1000003; rev:1;)
        drop tcp any any -> any any (msg:"Deny all other TCP traffic"; sid:1000004; rev:1;)
        drop icmp any any -> any any (msg:"Block all ICMP traffic"; sid:1000005; rev:1;)
        """

        rule_group = networkfirewall.CfnRuleGroup(
            self,
            "AaronRG123",
            capacity=100,  # Specify appropriate capacity
            type="STATEFUL",
            rule_group_name="AaronRG123",
            rule_group={"rulesSource": {"rulesString": rule_string}},
        )

        # Define firewall policy
        firewall_policy = networkfirewall.CfnFirewallPolicy(
            self,
            "AaronFirewallPolicy12",
            firewall_policy_name="AaronFirewallPolicy1",
            firewall_policy=networkfirewall.CfnFirewallPolicy.FirewallPolicyProperty(
                stateless_default_actions=["aws:drop"],
                stateless_fragment_default_actions=["aws:drop"],
                stateful_rule_group_references=[
                    {"resourceArn": rule_group.attr_rule_group_arn}
                ],
            ),
            description="Firewall policy to manage traffic",
        )

        return firewall_policy

    def _create_internet_gateway(self, vpc: aws_ec2.Vpc):
        # Create an Internet Gateway
        igw = aws_ec2.CfnInternetGateway(
            self,
            f"IGW-Firewall-Test",
            tags=[CfnTag(key="name", value="IGW-Firewall-Test")],
        )

        # Attach the Internet Gateway to the VPC
        igw_attachment = aws_ec2.CfnVPCGatewayAttachment(
            self,
            "IGWAttach-Firewall-Test",
            vpc_id=vpc.vpc_id,
            internet_gateway_id=igw.ref,
        )
        return igw

    def _create_igw_route_table(
        self, vpc: aws_ec2.Vpc, igw: aws_ec2.CfnInternetGateway
    ):
        igw_route_table = aws_ec2.CfnRouteTable(
            self,
            "IGW-RT-Firewall-Test",
            vpc_id=vpc.vpc_id,
            tags=[CfnTag(key="Name", value="IGW-RT-Firewall-Test")],
        )

        aws_ec2.CfnGatewayRouteTableAssociation(
            self,
            f"IGW-RT-Firewall-Test-Association",
            route_table_id=igw_route_table.ref,
            gateway_id=igw.ref,
        )
        return igw_route_table

    def __init__(self, scope, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        vpc = aws_ec2.Vpc(
            self,
            "FirewallVPC",
            max_azs=3,
            cidr="10.0.0.0/16",
            create_internet_gateway=False,
            subnet_configuration=[
                aws_ec2.SubnetConfiguration(
                    name="FirewallSubnet",
                    subnet_type=aws_ec2.SubnetType.PUBLIC,
                    cidr_mask=26,
                ),
                aws_ec2.SubnetConfiguration(
                    name="PublicSubnet",
                    subnet_type=aws_ec2.SubnetType.PUBLIC,
                    cidr_mask=21,
                ),
                aws_ec2.SubnetConfiguration(
                    name="PrivateSubnet",
                    subnet_type=aws_ec2.SubnetType.PRIVATE_WITH_NAT,
                    cidr_mask=21,
                ),
            ],
        )

        # Assign vpc to instance and access from other stacks
        self.vpc = vpc


        igw = self._create_internet_gateway(vpc)
        igw_route_table = self._create_igw_route_table(vpc, igw)


        # Map for future reference
        self.az_to_public_subnet: typing.Dict[str, aws_ec2.ISubnet] = {}
        for subnet in self.vpc.select_subnets(subnet_group_name="PublicSubnet").subnets:
            self.az_to_public_subnet[subnet.availability_zone] = subnet

        self.az_to_firewall_subnet: typing.Dict[str, aws_ec2.ISubnet] = {}
        for subnet in self.vpc.select_subnets(
            subnet_group_name="FirewallSubnet"
        ).subnets:
            self.az_to_firewall_subnet[subnet.availability_zone] = subnet

        self.az_to_private_subnet: typing.Dict[str, aws_ec2.ISubnet] = {}
        for subnet in self.vpc.private_subnets:
            self.az_to_private_subnet[subnet.availability_zone] = subnet



        # Route table for the workload subnets
        workload_route_table_dict: typing.Dict[str, aws_ec2.CfnRouteTable] = {}
        for i, az in enumerate(vpc.availability_zones):
            workload_route_table_dict[az] = aws_ec2.CfnRouteTable(
                self,
                f"Workload-RT-Firewall-Test-{az}",
                vpc_id=vpc.vpc_id,
                tags=[CfnTag(key="Name", value=f"Workload-RT-Firewall-Test-{az}")],
            )

        # Associate the route tables with the subnets
        for az, route_table in workload_route_table_dict.items():
            self.az_to_public_subnet[az].node.try_remove_child("RouteTableAssociation")
            self.az_to_public_subnet[az].node.try_remove_child("RouteTable")
            aws_ec2.CfnSubnetRouteTableAssociation(
                self,
                f"WorkloadRTAssocWorkload1{az}",
                subnet_id=self.az_to_public_subnet[az].subnet_id,
                route_table_id=route_table.ref,
            )

        # Route table for the firewall subnets. FirewallRouteTable
        firewall_route_table_dict: typing.Dict[str, aws_ec2.CfnRouteTable] = {}
        for i, az in enumerate(vpc.availability_zones):
            firewall_route_table_dict[az] = aws_ec2.CfnRouteTable(
                self,
                f"Firewall-RT-Firewall-Test-{az}",
                vpc_id=vpc.vpc_id,
                tags=[CfnTag(key="Name", value=f"Firewall-RT-Firewall-Test-{az}")],
            )

        # Associate the firewall route table with the firewall subnets
        for az, route_table in firewall_route_table_dict.items():
            self.az_to_firewall_subnet[az].node.try_remove_child("RouteTableAssociation")
            self.az_to_firewall_subnet[az].node.try_remove_child("RouteTable")
            aws_ec2.CfnSubnetRouteTableAssociation(
                self,
                f"FirewallRTAssocWorkload1{az}",
                subnet_id=self.az_to_firewall_subnet[az].subnet_id,
                route_table_id=route_table.ref,
            )

            aws_ec2.CfnRoute(self, f"FirewallRoute{az}", route_table_id=route_table.ref, destination_cidr_block="0.0.0.0/0", gateway_id=igw.ref)

        # Create a Firewall
        firewall_policy = self._create_firewall_policy()
        firewall = networkfirewall.CfnFirewall(
            self,
            "Firewall-Test",
            firewall_name="Firewall-Test",
            firewall_policy_arn=firewall_policy.attr_firewall_policy_arn,
            subnet_mappings=[
                networkfirewall.CfnFirewall.SubnetMappingProperty(
                    subnet_id=firewall_subnet_id
                )
                for firewall_subnet_id in [
                    subnet.subnet_id
                    for subnet in vpc.select_subnets(
                        subnet_group_name="FirewallSubnet"
                    ).subnets
                ]
            ],
            vpc_id=vpc.vpc_id,
            tags=[CfnTag(key="name", value="Firewall-Test")],
        )


        # workload route to firewall subnet via VPCE
        for az, _ in workload_route_table_dict.items():
            attr_endpoint = Fn.select(i, firewall.attr_endpoint_ids)
            endpoint = Fn.select(1, Fn.split(":", attr_endpoint))
            aws_ec2.CfnRoute(
                self,
                f"WorkloadToFirewallRoute{az}",
                route_table_id=workload_route_table_dict[az].ref,
                destination_cidr_block="0.0.0.0/0",
                vpc_endpoint_id=endpoint,
            )

        # IGW ingress route. Map IGW to workload subnets
        for i, subnet in enumerate(vpc.select_subnets(subnet_group_name="PublicSubnet").subnets):
            attr_endpoint = Fn.select(i, firewall.attr_endpoint_ids)
            endpoint = Fn.select(1, Fn.split(":", attr_endpoint))

            attr_endpoint = Fn.select(i, firewall.attr_endpoint_ids)  # attr_endpoint_ids = ["us-west-1:vpce-0a1b2c3d4e5f6g7h8"] $Token()
            true_az = Fn.select(0, Fn.split(":", attr_endpoint))  # this won't work. it's a temp token and not a real value
            # same problem, no answer: https://github.com/aws/aws-cdk/discussions/27108
            # true_az = Fn.select(0, Fn.split(":", Fn.select(i, firewall.attr_endpoint_ids)))  # this won't work. it's a temp token and not a real value
            aws_ec2.CfnRoute(
                self,
                f"IGWIngressToPublicSubnetCider{az}{i}",
                route_table_id=igw_route_table.ref,
                destination_cidr_block=self.az_to_public_subnet[true_az].ipv4_cidr_block,
                vpc_endpoint_id=endpoint,
            )

            Fn.split("a", firewall.attr_endpoint_ids, 2)
