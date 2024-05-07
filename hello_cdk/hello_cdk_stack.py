from aws_cdk import Stack
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_networkfirewall as networkfirewall
from aws_cdk import Fn, CfnOutput, CfnTag


class FirewallStack(Stack):
    def __init__(self, scope, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # Create a VPC with 2 public subnets
        vpc = ec2.Vpc(
            self,
            "MyVpc",
            cidr="10.0.0.0/16",
            max_azs=2,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    cidr_mask=24,
                    name="WorkerloadSubnet",
                    subnet_type=ec2.SubnetType.PUBLIC,
                ),
                ec2.SubnetConfiguration(
                    cidr_mask=24,
                    name="FirewallSubnet",
                    subnet_type=ec2.SubnetType.PUBLIC,
                ),
            ],
            create_internet_gateway=False
        )

                # Create an Internet Gateway
        igw = ec2.CfnInternetGateway(self, "AaronternetGateway12", tags=[CfnTag(
                key="name",
                value="AaronternetGateway12"
            )])

        # Attach the Internet Gateway to the VPC
        igw_attachment = ec2.CfnVPCGatewayAttachment(
            self, "AaronIGWAttach4", vpc_id=vpc.vpc_id, internet_gateway_id=igw.ref
        )

        

        firewall_subnet_selection = vpc.select_subnets(
            subnet_group_name="FirewallSubnet"
        )
        firewall_subnet_id = Fn.select(0, firewall_subnet_selection.subnet_ids)

        workload_subnet_selection = vpc.select_subnets(
            subnet_group_name="WorkerloadSubnet"
        )
        workload_subnet_selection_id = Fn.select(
            0, workload_subnet_selection.subnet_ids
        )

        # Create and configure route tables
        # Route table for the firewall subnet
        firewall_route_table = ec2.CfnRouteTable(
            self,
            "AAFirewallRouteTable1",
            vpc_id=vpc.vpc_id,
            tags=[CfnTag(key="Name", value="AAFirewallRouteTable1")],
        )

        # Default route through the internet gateway for the firewall subnet
        ec2.CfnRoute(
            self,
            "AAFirewallDefaultRoute",
            route_table_id=firewall_route_table.ref,
            destination_cidr_block="0.0.0.0/0",
            gateway_id=igw.ref,
        )

        # Route table for the workload subnet
        workload_route_table = ec2.CfnRouteTable(
            self,
            "AAWorkloadRouteTable1",
            vpc_id=vpc.vpc_id,
            tags=[CfnTag(key="Name", value="AAWorkloadRouteTable1")],
        )


        igw_route_table = ec2.CfnRouteTable(
            self,
            "AA-IGW-RouteTable1",
            vpc_id=vpc.vpc_id,
            tags=[CfnTag(key="Name", value="AA-IGW-RouteTable1")],
        )

        ec2.CfnGatewayRouteTableAssociation(
            self,
            f"AARTAssocIGW",
            route_table_id=igw_route_table.ref,
            gateway_id=igw.ref,
        )

        

        # Associate route tables with the subnets
        ec2.CfnSubnetRouteTableAssociation(
            self,
            f"AARTAssocFirewall",
            subnet_id=firewall_subnet_id,
            route_table_id=firewall_route_table.ref,
        )

        ec2.CfnSubnetRouteTableAssociation(
            self,
            f"AARTAssocWorkload",
            subnet_id=workload_subnet_selection_id,
            route_table_id=workload_route_table.ref,
        )


        CfnOutput(self, "FirewallSubnetId", value=firewall_subnet_id)
        CfnOutput(self, "WorkloadSubnetId", value=workload_subnet_selection_id)
        CfnOutput(self, "workload_route_table", value=workload_route_table.attr_route_table_id)


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

        # Create a Network Firewall in the firewall subnet
        firewall = networkfirewall.CfnFirewall(
            self,
            "MyFirewall12",
            firewall_name="MyFirewall12",
            firewall_policy_arn=firewall_policy.attr_firewall_policy_arn,
            subnet_mappings=[
                networkfirewall.CfnFirewall.SubnetMappingProperty(
                    subnet_id=firewall_subnet_id
                )
            ],
            vpc_id=vpc.vpc_id,
        )


        # Routes for the workload subnet
        # ec2.CfnRoute(
        #     self,
        #     "AAWorkloadToLocal",
        #     route_table_id=workload_route_table.ref,
        #     destination_cidr_block="0.0.0.0/0",
        #     vpc_endpoint_id=Fn.select(0, firewall.attr_endpoint_ids),
        # )

        
        

        CfnOutput(self, "firewall_endpoints", value=Fn.select(0, firewall.attr_endpoint_ids))


        # ec2.CfnRoute(
        #     self,
        #     "AAWorkloadToFirewall",
        #     route_table_id=workload_route_table.ref,
        #     destination_cidr_block="0.0.0.0/0",
        #     gateway_id=Fn.select(0, firewall.attr_endpoint_ids),
        # )



        # workload route to firewall subnet via VPCE
        endpoint_str = Fn.select(0, firewall.attr_endpoint_ids)

        ec2.CfnRoute(
            self,
            "AAWorkloadToFirewall",
            route_table_id=workload_route_table.ref,
            destination_cidr_block="0.0.0.0/0",
            vpc_endpoint_id=Fn.select(1, Fn.split(":", endpoint_str)),
        )

        ec2.CfnRoute(
            self,
            "AAIGWDefaultRoute",
            route_table_id=igw_route_table.ref,
            destination_cidr_block="10.0.0.0/24",
            vpc_endpoint_id=Fn.select(1, Fn.split(":", endpoint_str)),
        )


    # sudo su
    # yum install -y httpd
    # systemctl start httpd.service
    # systemctl enable httpd.service
    # echo "Hello World from $(hostname -f)" > /var/www/html/index.html
