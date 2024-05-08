from aws_cdk import Stack
from aws_cdk import aws_ec2
from aws_cdk import aws_networkfirewall as networkfirewall
from aws_cdk import Fn, CfnOutput, CfnTag


class FirewallStack(Stack):
    
    def _create_firewall(self, vpc: aws_ec2.Vpc, firewall_subnet_id: str, stage_id: str):
        rule_string = """
        pass http any any -> any any (http.host; content:"aws.amazon.com"; endswith; msg:"Allow HTTP access to AWS services"; sid:1000001; rev:1;)
        pass tls any any -> any any (tls.sni; content:"aws.amazon.com"; startswith; nocase; endswith; msg:"Permit HTTPS access to aws.amazon.com"; sid:1000003; rev:1;)
        drop tcp any any -> any any (msg:"Deny all other TCP traffic"; sid:1000004; rev:1;)
        drop icmp any any -> any any (msg:"Block all ICMP traffic"; sid:1000005; rev:1;)
        """

        rule_group = networkfirewall.CfnRuleGroup(
            self,
            f"CLEANLAB-{stage_id}-RuleGroup",
            capacity=100,  # Specify appropriate capacity
            type="STATEFUL",
            rule_group_name=f"CLEANLAB-{stage_id}-RuleGroup",
            rule_group={"rulesSource": {"rulesString": rule_string}},
        )

        # Define firewall policy
        firewall_policy = networkfirewall.CfnFirewallPolicy(
            self,
            f"CLEANLAB-{stage_id}-FirewallPolicy",
            firewall_policy_name=f"CLEANLAB-{stage_id}-FirewallPolicy",
            firewall_policy=networkfirewall.CfnFirewallPolicy.FirewallPolicyProperty(
                stateless_default_actions=["aws:forward_to_sfe"],
                stateless_fragment_default_actions=["aws:drop"],
                stateful_rule_group_references=[
                    {"resourceArn": rule_group.attr_rule_group_arn}
                ],
            ),
            description="Cleanlab firewall policy to manage traffic",
        )

        # Create a Network Firewall in the firewall subnet
        firewall = networkfirewall.CfnFirewall(
            self,
            f"CLEANLAB-{stage_id}-Firewall",
            firewall_name=f"CLEANLAB-{stage_id}-Firewall",
            firewall_policy_arn=firewall_policy.attr_firewall_policy_arn,
            subnet_mappings=[
                networkfirewall.CfnFirewall.SubnetMappingProperty(
                    subnet_id=firewall_subnet_id
                )
            ],
            vpc_id=vpc.vpc_id,
        )
        return firewall
    
    def __init__(self, scope, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        aaron_stage_id = "AaronStage"
        # ------------------------------------ VPC ----------------------------------- #
        if not True:
            vpc = aws_ec2.Vpc(
                self,
                CONFIG.CLEANLAB_STUDIO_VPC_ID,
                max_azs=max_azs,
                nat_gateways=nat_gateways,
            )

        else: # CONFIG.IS_VPC == True
            workload_subnet_name = f"CLEANLAB-{aaron_stage_id}-WorkerloadSubnet"
            firewall_subnet_name = f"CLEANLAB-{aaron_stage_id}-FirewallSubnet"
            private_subnet_name = f"CLEANLAB-{aaron_stage_id}-PrivateSubnet"
            
            vpc = aws_ec2.Vpc(
                self,
                "Firewall_VPC",
                max_azs=1,
                cidr="10.0.0.0/16",
                create_internet_gateway=False,
                subnet_configuration=[
                    aws_ec2.SubnetConfiguration(
                        cidr_mask=20,
                        name=workload_subnet_name,
                        subnet_type=aws_ec2.SubnetType.PUBLIC,
                    ),
                    aws_ec2.SubnetConfiguration(
                        cidr_mask=24,
                        name=firewall_subnet_name,
                        subnet_type=aws_ec2.SubnetType.PUBLIC,
                    ),
                    aws_ec2.SubnetConfiguration(
                        cidr_mask=20,
                        name=private_subnet_name,
                        subnet_type=aws_ec2.SubnetType.PRIVATE_WITH_NAT,
                    ),
                ],
            )
            
            # Create an Internet Gateway
            igw = aws_ec2.CfnInternetGateway(self, f"{aaron_stage_id}-igw", tags=[CfnTag(
                    key="Name",
                    value=f"{aaron_stage_id}-igw"
                )])

            # Attach the Internet Gateway to the VPC
            igw_attachment = aws_ec2.CfnVPCGatewayAttachment(
                self, f"{aaron_stage_id}-igw-attachment", vpc_id=vpc.vpc_id, internet_gateway_id=igw.ref
            )

            firewall_subnet_selection = vpc.select_subnets(
                subnet_group_name=firewall_subnet_name
            )
            firewall_subnet_id = Fn.select(0, firewall_subnet_selection.subnet_ids)

            workload_subnet_selection = vpc.select_subnets(
                subnet_group_name=workload_subnet_name
            )
            workload_subnet_selection_id = Fn.select(
                0, workload_subnet_selection.subnet_ids
            )
            

            ### Create Route Tables
            # Route table for the firewall subnet
            firewall_route_table = aws_ec2.CfnRouteTable(
                self,
                f"{aaron_stage_id}-FirewallRouteTable",
                vpc_id=vpc.vpc_id,
                tags=[CfnTag(key="Name", value=f"{aaron_stage_id}-FirewallRouteTable")],
            )

            # Route table for the workload subnet
            workload_route_table = aws_ec2.CfnRouteTable(
                self,
                f"{aaron_stage_id}-WorkloadRouteTable",
                vpc_id=vpc.vpc_id,
                tags=[CfnTag(key="Name", value=f"{aaron_stage_id}-WorkloadRouteTable")],
            )

            # Route table for the IGW
            igw_route_table = aws_ec2.CfnRouteTable(
                self,
                f"{aaron_stage_id}-IGW-RouteTable",
                vpc_id=vpc.vpc_id,
                tags=[CfnTag(key="Name", value=f"{aaron_stage_id}-IGW-RouteTable")],
            )

            ### Associate Route Tables
            aws_ec2.CfnGatewayRouteTableAssociation(
                self,
                f"{aaron_stage_id}-IGW-RouteTableAssociation",
                route_table_id=igw_route_table.ref,
                gateway_id=igw.ref,
            )
            
            # Remove the default route and route association
            vpc.select_subnets(subnet_group_name=firewall_subnet_name).subnets[0].node.try_remove_child("RouteTableAssociation")
            vpc.select_subnets(subnet_group_name=firewall_subnet_name).subnets[0].node.try_remove_child("RouteTable")

            vpc.select_subnets(subnet_group_name=workload_subnet_name).subnets[0].node.try_remove_child("RouteTableAssociation")
            vpc.select_subnets(subnet_group_name=workload_subnet_name).subnets[0].node.try_remove_child("RouteTable")
             
            # Associate route tables with the subnets
            aws_ec2.CfnSubnetRouteTableAssociation(
                self,
                f"CLEANLAB-{aaron_stage_id}-FirewallRouteTableAssociation",
                subnet_id=firewall_subnet_id,
                route_table_id=firewall_route_table.ref,
            )

            aws_ec2.CfnSubnetRouteTableAssociation(
                self,
                f"CLEANLAB-{aaron_stage_id}-WorkloadRouteTableAssociation",
                subnet_id=workload_subnet_selection_id,
                route_table_id=workload_route_table.ref,
            )

            ### Create Firewall
            firewall = self._create_firewall(vpc, firewall_subnet_id, aaron_stage_id)

            ### Routing
            # Route Firewall -> IGW
            aws_ec2.CfnRoute(
                self,
                f"{aaron_stage_id}-FirewallRouteToIGW",
                route_table_id=firewall_route_table.ref,
                destination_cidr_block="0.0.0.0/0",
                gateway_id=igw.ref,
            )

            endpoint_ref = Fn.select(1, Fn.split(":", Fn.select(0, firewall.attr_endpoint_ids)))
            
            # Route Workload -> Firewall
            aws_ec2.CfnRoute(
                self,
                f"CLEANLAB-{aaron_stage_id}-WorkloadRouteToFirewall",
                route_table_id=workload_route_table.ref,
                destination_cidr_block="0.0.0.0/0",
                vpc_endpoint_id=endpoint_ref,
            )

            # Route IGW -> Workload
            aws_ec2.CfnRoute(
                self,
                f"CLEANLAB-{aaron_stage_id}-IGWRouteToWorkload",
                route_table_id=igw_route_table.ref,
                destination_cidr_block=workload_subnet_selection.subnets[0].ipv4_cidr_block,
                vpc_endpoint_id=endpoint_ref,
            )
