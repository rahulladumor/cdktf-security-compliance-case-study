package main

import (
	"fmt"
	"github.com/aws/constructs-go/constructs/v10"
	"github.com/aws/jsii-runtime-go"
	"github.com/cdktf/cdktf-provider-aws-go/aws/v19/acmcertificate"
	"github.com/cdktf/cdktf-provider-aws-go/aws/v19/acmcertificatevalidation"
	"github.com/cdktf/cdktf-provider-aws-go/aws/v19/autoscalinggroup"
	"github.com/cdktf/cdktf-provider-aws-go/aws/v19/cloudtrail"
	"github.com/cdktf/cdktf-provider-aws-go/aws/v19/cloudwatchloggroup"
	"github.com/cdktf/cdktf-provider-aws-go/aws/v19/cloudwatchmetricalarm"
	"github.com/cdktf/cdktf-provider-aws-go/aws/v19/dataawsami"
	"github.com/cdktf/cdktf-provider-aws-go/aws/v19/dataawsavailabilityzones"
	"github.com/cdktf/cdktf-provider-aws-go/aws/v19/dbinstance"
	"github.com/cdktf/cdktf-provider-aws-go/aws/v19/dbsubnetgroup"
	"github.com/cdktf/cdktf-provider-aws-go/aws/v19/eip"
	"github.com/cdktf/cdktf-provider-aws-go/aws/v19/iaminstanceprofile"
	"github.com/cdktf/cdktf-provider-aws-go/aws/v19/iamrole"
	"github.com/cdktf/cdktf-provider-aws-go/aws/v19/iamrolepolicyattachment"
	"github.com/cdktf/cdktf-provider-aws-go/aws/v19/internetgateway"
	"github.com/cdktf/cdktf-provider-aws-go/aws/v19/kmskey"
	"github.com/cdktf/cdktf-provider-aws-go/aws/v19/launchtemplate"
	"github.com/cdktf/cdktf-provider-aws-go/aws/v19/lb"
	"github.com/cdktf/cdktf-provider-aws-go/aws/v19/lblistener"
	"github.com/cdktf/cdktf-provider-aws-go/aws/v19/lbtargetgroup"
	"github.com/cdktf/cdktf-provider-aws-go/aws/v19/natgateway"
	"github.com/cdktf/cdktf-provider-aws-go/aws/v19/networkacl"
	"github.com/cdktf/cdktf-provider-aws-go/aws/v19/networkaclassociation"
	"github.com/cdktf/cdktf-provider-aws-go/aws/v19/networkaclrule"
	"github.com/cdktf/cdktf-provider-aws-go/aws/v19/provider"
	"github.com/cdktf/cdktf-provider-aws-go/aws/v19/route"
	"github.com/cdktf/cdktf-provider-aws-go/aws/v19/route53healthcheck"
	"github.com/cdktf/cdktf-provider-aws-go/aws/v19/route53record"
	"github.com/cdktf/cdktf-provider-aws-go/aws/v19/route53zone"
	"github.com/cdktf/cdktf-provider-aws-go/aws/v19/routetable"
	"github.com/cdktf/cdktf-provider-aws-go/aws/v19/routetableassociation"
	"github.com/cdktf/cdktf-provider-aws-go/aws/v19/s3bucket"
	"github.com/cdktf/cdktf-provider-aws-go/aws/v19/s3bucketpublicaccessblock"
	"github.com/cdktf/cdktf-provider-aws-go/aws/v19/s3bucketserversideencryptionconfiguration"
	"github.com/cdktf/cdktf-provider-aws-go/aws/v19/secretsmanagersecret"
	"github.com/cdktf/cdktf-provider-aws-go/aws/v19/secretsmanagersecretversion"
	"github.com/cdktf/cdktf-provider-aws-go/aws/v19/securitygroup"
	"github.com/cdktf/cdktf-provider-aws-go/aws/v19/ssmparameter"
	"github.com/cdktf/cdktf-provider-aws-go/aws/v19/subnet"
	"github.com/cdktf/cdktf-provider-aws-go/aws/v19/vpc"
	"github.com/hashicorp/terraform-cdk-go/cdktf"
	"os"
)

type InfrastructureStackConfig struct {
	Region      string
	Environment string
}

type InfrastructureStack struct {
	cdktf.TerraformStack
}

type CompleteInfrastructure struct {
	VPC                   vpc.Vpc
	LoadBalancer          lb.Lb
	Database              dbinstance.DbInstance
	ReadReplica           dbinstance.DbInstance
	WebASG                autoscalinggroup.AutoscalingGroup
	AppASG                autoscalinggroup.AutoscalingGroup
	S3Bucket              s3bucket.S3Bucket
	KMSKey                kmskey.KmsKey
	DatabaseSecret        secretsmanagersecret.SecretsmanagerSecret
	HostedZone            route53zone.Route53Zone
	Certificate           acmcertificate.AcmCertificate
	CertificateValidation acmcertificatevalidation.AcmCertificateValidation
	HealthCheck           route53healthcheck.Route53HealthCheck
}

// Helper function to merge tags
func mergeTags(base *map[string]*string, additional *map[string]*string) *map[string]*string {
	result := make(map[string]*string)
	if base != nil {
		for k, v := range *base {
			result[k] = v
		}
	}
	if additional != nil {
		for k, v := range *additional {
			result[k] = v
		}
	}
	return &result
}

func NewCompleteInfrastructure(scope constructs.Construct, id *string, region string, envSuffix string) *CompleteInfrastructure {
	// Get standard tags
	tags := &map[string]*string{
		"Project":     jsii.String("Migration"),
		"Creator":     jsii.String("CloudEngineer"),
		"Environment": jsii.String("production"),
		"Region":      jsii.String(region),
		"CostCenter":  jsii.String("IT-Infrastructure"),
	}

	// Configuration
	vpcCidr := "10.0.0.0/16"
	domainName := fmt.Sprintf("migration-%s.example.com", region) // Replace with your domain
	companyIpRanges := []*string{
		jsii.String("203.0.113.0/24"),  // Company office IP range
		jsii.String("198.51.100.0/24"), // Company VPN range
	}

	// Create KMS Key for encryption
	kmsKey := kmskey.NewKmsKey(scope, jsii.String("migration-kms-key"), &kmskey.KmsKeyConfig{
		Description: jsii.String(fmt.Sprintf("KMS key for migration resources in %s", region)),
		Policy: jsii.String(`{
			"Version": "2012-10-17",
			"Statement": [
				{
					"Sid": "Enable IAM User Permissions",
					"Effect": "Allow",
					"Principal": {
						"AWS": "arn:aws:iam::*:root"
					},
					"Action": "kms:*",
					"Resource": "*"
				},
				{
					"Sid": "Allow CloudTrail to encrypt logs",
					"Effect": "Allow",
					"Principal": {
						"Service": "cloudtrail.amazonaws.com"
					},
					"Action": [
						"kms:GenerateDataKey*",
						"kms:DescribeKey"
					],
					"Resource": "*"
				}
			]
		}`),
		Tags: tags,
	})

	// Create S3 bucket for CloudTrail and application data
	s3Bucket := s3bucket.NewS3Bucket(scope, jsii.String("migration-s3-bucket"), &s3bucket.S3BucketConfig{
		Bucket: jsii.String(fmt.Sprintf("migration-bucket-%s-%s-%d", region, envSuffix, 12345)), // Add random suffix in production
		Tags:   tags,
	})

	// Configure S3 bucket encryption
	s3bucketserversideencryptionconfiguration.NewS3BucketServerSideEncryptionConfigurationA(scope, jsii.String("s3-bucket-encryption"), &s3bucketserversideencryptionconfiguration.S3BucketServerSideEncryptionConfigurationAConfig{
		Bucket: s3Bucket.Id(),
		Rule: &[]*s3bucketserversideencryptionconfiguration.S3BucketServerSideEncryptionConfigurationRuleA{
			{
				ApplyServerSideEncryptionByDefault: &s3bucketserversideencryptionconfiguration.S3BucketServerSideEncryptionConfigurationRuleApplyServerSideEncryptionByDefaultA{
					KmsMasterKeyId: kmsKey.Arn(),
					SseAlgorithm:   jsii.String("aws:kms"),
				},
			},
		},
	})

	// Block public access to S3 bucket
	s3bucketpublicaccessblock.NewS3BucketPublicAccessBlock(scope, jsii.String("s3-bucket-pab"), &s3bucketpublicaccessblock.S3BucketPublicAccessBlockConfig{
		Bucket:                s3Bucket.Id(),
		BlockPublicAcls:       jsii.Bool(true),
		BlockPublicPolicy:     jsii.Bool(true),
		IgnorePublicAcls:      jsii.Bool(true),
		RestrictPublicBuckets: jsii.Bool(true),
	})

	// Create database password in Secrets Manager
	dbSecret := secretsmanagersecret.NewSecretsmanagerSecret(scope, jsii.String("db-secret"), &secretsmanagersecret.SecretsmanagerSecretConfig{
		Name:        jsii.String(fmt.Sprintf("migration/database/%s-%s", region, envSuffix)),
		Description: jsii.String("Database master password for migration infrastructure"),
		Tags:        tags,
	})

	secretsmanagersecretversion.NewSecretsmanagerSecretVersion(scope, jsii.String("db-secret-version"), &secretsmanagersecretversion.SecretsmanagerSecretVersionConfig{
		SecretId:     dbSecret.Id(),
		SecretString: jsii.String(`{"password":"TempPassword123#"}`),
	})

	// Store configuration in Parameter Store
	ssmparameter.NewSsmParameter(scope, jsii.String("vpc-cidr-param"), &ssmparameter.SsmParameterConfig{
		Name:  jsii.String(fmt.Sprintf("/migration/%s/vpc-cidr", region)),
		Type:  jsii.String("String"),
		Value: jsii.String(vpcCidr),
		Tags:  tags,
	})

	ssmparameter.NewSsmParameter(scope, jsii.String("domain-param"), &ssmparameter.SsmParameterConfig{
		Name:  jsii.String(fmt.Sprintf("/migration/%s/domain", region)),
		Type:  jsii.String("String"),
		Value: jsii.String(domainName),
		Tags:  tags,
	})

	// Get availability zones
	azs := dataawsavailabilityzones.NewDataAwsAvailabilityZones(scope, jsii.String("azs"), &dataawsavailabilityzones.DataAwsAvailabilityZonesConfig{
		State: jsii.String("available"),
	})

	// Create VPC
	mainVpc := vpc.NewVpc(scope, jsii.String("main-vpc"), &vpc.VpcConfig{
		CidrBlock:          jsii.String(vpcCidr),
		EnableDnsHostnames: jsii.Bool(true),
		EnableDnsSupport:   jsii.Bool(true),
		Tags: mergeTags(tags, &map[string]*string{
			"Name": jsii.String(fmt.Sprintf("migration-vpc-%s-%s", region, envSuffix)),
		}),
	})

	// Create Internet Gateway
	igw := internetgateway.NewInternetGateway(scope, jsii.String("internet-gateway"), &internetgateway.InternetGatewayConfig{
		VpcId: mainVpc.Id(),
		Tags: mergeTags(tags, &map[string]*string{
			"Name": jsii.String(fmt.Sprintf("migration-igw-%s-%s", region, envSuffix)),
		}),
	})

	// Create Network ACLs for additional security
	publicNetworkAcl := networkacl.NewNetworkAcl(scope, jsii.String("public-network-acl"), &networkacl.NetworkAclConfig{
		VpcId: mainVpc.Id(),
		Tags: mergeTags(tags, &map[string]*string{
			"Name": jsii.String(fmt.Sprintf("public-network-acl-%s-%s", region, envSuffix)),
		}),
	})

	// Public Network ACL Rules
	networkaclrule.NewNetworkAclRule(scope, jsii.String("public-nacl-inbound-http"), &networkaclrule.NetworkAclRuleConfig{
		NetworkAclId: publicNetworkAcl.Id(),
		RuleNumber:   jsii.Number(100),
		Protocol:     jsii.String("tcp"),
		RuleAction:   jsii.String("allow"),
		FromPort:     jsii.Number(80),
		ToPort:       jsii.Number(80),
		CidrBlock:    jsii.String("0.0.0.0/0"),
	})

	networkaclrule.NewNetworkAclRule(scope, jsii.String("public-nacl-inbound-https"), &networkaclrule.NetworkAclRuleConfig{
		NetworkAclId: publicNetworkAcl.Id(),
		RuleNumber:   jsii.Number(110),
		Protocol:     jsii.String("tcp"),
		RuleAction:   jsii.String("allow"),
		FromPort:     jsii.Number(443),
		ToPort:       jsii.Number(443),
		CidrBlock:    jsii.String("0.0.0.0/0"),
	})

	networkaclrule.NewNetworkAclRule(scope, jsii.String("public-nacl-inbound-ephemeral"), &networkaclrule.NetworkAclRuleConfig{
		NetworkAclId: publicNetworkAcl.Id(),
		RuleNumber:   jsii.Number(120),
		Protocol:     jsii.String("tcp"),
		RuleAction:   jsii.String("allow"),
		FromPort:     jsii.Number(1024),
		ToPort:       jsii.Number(65535),
		CidrBlock:    jsii.String("0.0.0.0/0"),
	})

	networkaclrule.NewNetworkAclRule(scope, jsii.String("public-nacl-outbound-all"), &networkaclrule.NetworkAclRuleConfig{
		NetworkAclId: publicNetworkAcl.Id(),
		RuleNumber:   jsii.Number(100),
		Protocol:     jsii.String("-1"),
		RuleAction:   jsii.String("allow"),
		CidrBlock:    jsii.String("0.0.0.0/0"),
		Egress:       jsii.Bool(true),
	})

	privateNetworkAcl := networkacl.NewNetworkAcl(scope, jsii.String("private-network-acl"), &networkacl.NetworkAclConfig{
		VpcId: mainVpc.Id(),
		Tags: mergeTags(tags, &map[string]*string{
			"Name": jsii.String(fmt.Sprintf("private-network-acl-%s-%s", region, envSuffix)),
		}),
	})

	// Private Network ACL Rules - Allow from VPC CIDR
	networkaclrule.NewNetworkAclRule(scope, jsii.String("private-nacl-inbound-vpc"), &networkaclrule.NetworkAclRuleConfig{
		NetworkAclId: privateNetworkAcl.Id(),
		RuleNumber:   jsii.Number(100),
		Protocol:     jsii.String("-1"),
		RuleAction:   jsii.String("allow"),
		CidrBlock:    jsii.String(vpcCidr),
	})

	networkaclrule.NewNetworkAclRule(scope, jsii.String("private-nacl-inbound-ephemeral"), &networkaclrule.NetworkAclRuleConfig{
		NetworkAclId: privateNetworkAcl.Id(),
		RuleNumber:   jsii.Number(110),
		Protocol:     jsii.String("tcp"),
		RuleAction:   jsii.String("allow"),
		FromPort:     jsii.Number(1024),
		ToPort:       jsii.Number(65535),
		CidrBlock:    jsii.String("0.0.0.0/0"),
	})

	networkaclrule.NewNetworkAclRule(scope, jsii.String("private-nacl-outbound-all"), &networkaclrule.NetworkAclRuleConfig{
		NetworkAclId: privateNetworkAcl.Id(),
		RuleNumber:   jsii.Number(100),
		Protocol:     jsii.String("-1"),
		RuleAction:   jsii.String("allow"),
		CidrBlock:    jsii.String("0.0.0.0/0"),
		Egress:       jsii.Bool(true),
	})

	// Create subnets
	var publicSubnets []subnet.Subnet
	var privateSubnets []subnet.Subnet
	var databaseSubnets []subnet.Subnet
	var publicSubnetIds []*string
	var privateSubnetIds []*string
	var databaseSubnetIds []*string

	for i := 0; i < 3; i++ {
		azIndex := i % 3

		// Public Subnet
		pubSubnet := subnet.NewSubnet(scope, jsii.String(fmt.Sprintf("public-subnet-%d", i)), &subnet.SubnetConfig{
			VpcId:               mainVpc.Id(),
			CidrBlock:           jsii.String(fmt.Sprintf("10.0.%d.0/24", i*10+1)),
			AvailabilityZone:    cdktf.Token_AsString(cdktf.Fn_Element(azs.Names(), jsii.Number(azIndex)), nil),
			MapPublicIpOnLaunch: jsii.Bool(true),
			Tags: mergeTags(tags, &map[string]*string{
				"Name": jsii.String(fmt.Sprintf("public-subnet-%d-%s-%s", i+1, region, envSuffix)),
				"Type": jsii.String("Public"),
			}),
		})
		publicSubnets = append(publicSubnets, pubSubnet)
		publicSubnetIds = append(publicSubnetIds, pubSubnet.Id())

		// Private Subnet
		privSubnet := subnet.NewSubnet(scope, jsii.String(fmt.Sprintf("private-subnet-%d", i)), &subnet.SubnetConfig{
			VpcId:            mainVpc.Id(),
			CidrBlock:        jsii.String(fmt.Sprintf("10.0.%d.0/24", i*10+2)),
			AvailabilityZone: cdktf.Token_AsString(cdktf.Fn_Element(azs.Names(), jsii.Number(azIndex)), nil),
			Tags: mergeTags(tags, &map[string]*string{
				"Name": jsii.String(fmt.Sprintf("private-subnet-%d-%s-%s", i+1, region, envSuffix)),
				"Type": jsii.String("Private"),
			}),
		})
		privateSubnets = append(privateSubnets, privSubnet)
		privateSubnetIds = append(privateSubnetIds, privSubnet.Id())

		// Database Subnet
		dbSubnet := subnet.NewSubnet(scope, jsii.String(fmt.Sprintf("database-subnet-%d", i)), &subnet.SubnetConfig{
			VpcId:            mainVpc.Id(),
			CidrBlock:        jsii.String(fmt.Sprintf("10.0.%d.0/24", i*10+3)),
			AvailabilityZone: cdktf.Token_AsString(cdktf.Fn_Element(azs.Names(), jsii.Number(azIndex)), nil),
			Tags: mergeTags(tags, &map[string]*string{
				"Name": jsii.String(fmt.Sprintf("database-subnet-%d-%s-%s", i+1, region, envSuffix)),
				"Type": jsii.String("Database"),
			}),
		})
		databaseSubnets = append(databaseSubnets, dbSubnet)
		databaseSubnetIds = append(databaseSubnetIds, dbSubnet.Id())

		// NAT Gateway
		natEip := eip.NewEip(scope, jsii.String(fmt.Sprintf("nat-eip-%d", i)), &eip.EipConfig{
			Domain: jsii.String("vpc"),
			Tags: mergeTags(tags, &map[string]*string{
				"Name": jsii.String(fmt.Sprintf("nat-eip-%d-%s-%s", i+1, region, envSuffix)),
			}),
		})

		natGw := natgateway.NewNatGateway(scope, jsii.String(fmt.Sprintf("nat-gateway-%d", i)), &natgateway.NatGatewayConfig{
			AllocationId: natEip.Id(),
			SubnetId:     pubSubnet.Id(),
			Tags: mergeTags(tags, &map[string]*string{
				"Name": jsii.String(fmt.Sprintf("nat-gateway-%d-%s-%s", i+1, region, envSuffix)),
			}),
		})

		// Private Route Table
		privRouteTable := routetable.NewRouteTable(scope, jsii.String(fmt.Sprintf("private-route-table-%d", i)), &routetable.RouteTableConfig{
			VpcId: mainVpc.Id(),
			Tags: mergeTags(tags, &map[string]*string{
				"Name": jsii.String(fmt.Sprintf("private-rt-%d-%s-%s", i+1, region, envSuffix)),
			}),
		})

		route.NewRoute(scope, jsii.String(fmt.Sprintf("private-route-%d", i)), &route.RouteConfig{
			RouteTableId:         privRouteTable.Id(),
			DestinationCidrBlock: jsii.String("0.0.0.0/0"),
			NatGatewayId:         natGw.Id(),
		})

		routetableassociation.NewRouteTableAssociation(scope, jsii.String(fmt.Sprintf("private-rta-%d", i)), &routetableassociation.RouteTableAssociationConfig{
			SubnetId:     privSubnet.Id(),
			RouteTableId: privRouteTable.Id(),
		})

		routetableassociation.NewRouteTableAssociation(scope, jsii.String(fmt.Sprintf("database-rta-%d", i)), &routetableassociation.RouteTableAssociationConfig{
			SubnetId:     dbSubnet.Id(),
			RouteTableId: privRouteTable.Id(),
		})
	}

	// Public Route Table
	publicRouteTable := routetable.NewRouteTable(scope, jsii.String("public-route-table"), &routetable.RouteTableConfig{
		VpcId: mainVpc.Id(),
		Tags: mergeTags(tags, &map[string]*string{
			"Name": jsii.String(fmt.Sprintf("public-rt-%s-%s", region, envSuffix)),
		}),
	})

	route.NewRoute(scope, jsii.String("public-route"), &route.RouteConfig{
		RouteTableId:         publicRouteTable.Id(),
		DestinationCidrBlock: jsii.String("0.0.0.0/0"),
		GatewayId:            igw.Id(),
	})

	for i, pubSubnet := range publicSubnets {
		routetableassociation.NewRouteTableAssociation(scope, jsii.String(fmt.Sprintf("public-rta-%d", i)), &routetableassociation.RouteTableAssociationConfig{
			SubnetId:     pubSubnet.Id(),
			RouteTableId: publicRouteTable.Id(),
		})

		// Associate public subnets with public Network ACL
		networkaclassociation.NewNetworkAclAssociation(scope, jsii.String(fmt.Sprintf("public-nacl-assoc-%d", i)), &networkaclassociation.NetworkAclAssociationConfig{
			NetworkAclId: publicNetworkAcl.Id(),
			SubnetId:     pubSubnet.Id(),
		})
	}

	// Associate private and database subnets with private Network ACL
	for i, privSubnet := range privateSubnets {
		networkaclassociation.NewNetworkAclAssociation(scope, jsii.String(fmt.Sprintf("private-nacl-assoc-%d", i)), &networkaclassociation.NetworkAclAssociationConfig{
			NetworkAclId: privateNetworkAcl.Id(),
			SubnetId:     privSubnet.Id(),
		})
	}

	for i, dbSubnet := range databaseSubnets {
		networkaclassociation.NewNetworkAclAssociation(scope, jsii.String(fmt.Sprintf("database-nacl-assoc-%d", i)), &networkaclassociation.NetworkAclAssociationConfig{
			NetworkAclId: privateNetworkAcl.Id(),
			SubnetId:     dbSubnet.Id(),
		})
	}

	// Security Groups
	albSG := securitygroup.NewSecurityGroup(scope, jsii.String("alb-security-group"), &securitygroup.SecurityGroupConfig{
		Name:        jsii.String(fmt.Sprintf("alb-sg-%s-%s", region, envSuffix)),
		Description: jsii.String("Security group for Application Load Balancer"),
		VpcId:       mainVpc.Id(),
		Ingress: &[]*securitygroup.SecurityGroupIngress{
			{
				Description: jsii.String("HTTPS from company IPs"),
				FromPort:    jsii.Number(443),
				ToPort:      jsii.Number(443),
				Protocol:    jsii.String("tcp"),
				CidrBlocks:  &companyIpRanges,
			},
			{
				Description: jsii.String("HTTP from company IPs"),
				FromPort:    jsii.Number(80),
				ToPort:      jsii.Number(80),
				Protocol:    jsii.String("tcp"),
				CidrBlocks:  &companyIpRanges,
			},
		},
		Egress: &[]*securitygroup.SecurityGroupEgress{
			{
				Description: jsii.String("All outbound traffic"),
				FromPort:    jsii.Number(0),
				ToPort:      jsii.Number(0),
				Protocol:    jsii.String("-1"),
				CidrBlocks:  &[]*string{jsii.String("0.0.0.0/0")},
			},
		},
		Tags: mergeTags(tags, &map[string]*string{
			"Name": jsii.String(fmt.Sprintf("alb-sg-%s-%s", region, envSuffix)),
		}),
	})

	webSG := securitygroup.NewSecurityGroup(scope, jsii.String("web-security-group"), &securitygroup.SecurityGroupConfig{
		Name:        jsii.String(fmt.Sprintf("web-sg-%s-%s", region, envSuffix)),
		Description: jsii.String("Security group for web tier instances"),
		VpcId:       mainVpc.Id(),
		Ingress: &[]*securitygroup.SecurityGroupIngress{
			{
				Description:    jsii.String("HTTP from ALB"),
				FromPort:       jsii.Number(80),
				ToPort:         jsii.Number(80),
				Protocol:       jsii.String("tcp"),
				SecurityGroups: &[]*string{albSG.Id()},
			},
			{
				Description: jsii.String("SSH from company IPs"),
				FromPort:    jsii.Number(22),
				ToPort:      jsii.Number(22),
				Protocol:    jsii.String("tcp"),
				CidrBlocks:  &companyIpRanges,
			},
		},
		Egress: &[]*securitygroup.SecurityGroupEgress{
			{
				Description: jsii.String("All outbound traffic"),
				FromPort:    jsii.Number(0),
				ToPort:      jsii.Number(0),
				Protocol:    jsii.String("-1"),
				CidrBlocks:  &[]*string{jsii.String("0.0.0.0/0")},
			},
		},
		Tags: mergeTags(tags, &map[string]*string{
			"Name": jsii.String(fmt.Sprintf("web-sg-%s-%s", region, envSuffix)),
		}),
	})

	appSG := securitygroup.NewSecurityGroup(scope, jsii.String("app-security-group"), &securitygroup.SecurityGroupConfig{
		Name:        jsii.String(fmt.Sprintf("app-sg-%s-%s", region, envSuffix)),
		Description: jsii.String("Security group for application tier instances"),
		VpcId:       mainVpc.Id(),
		Ingress: &[]*securitygroup.SecurityGroupIngress{
			{
				Description:    jsii.String("Application port from web tier"),
				FromPort:       jsii.Number(8080),
				ToPort:         jsii.Number(8080),
				Protocol:       jsii.String("tcp"),
				SecurityGroups: &[]*string{webSG.Id()},
			},
		},
		Egress: &[]*securitygroup.SecurityGroupEgress{
			{
				Description: jsii.String("All outbound traffic"),
				FromPort:    jsii.Number(0),
				ToPort:      jsii.Number(0),
				Protocol:    jsii.String("-1"),
				CidrBlocks:  &[]*string{jsii.String("0.0.0.0/0")},
			},
		},
		Tags: mergeTags(tags, &map[string]*string{
			"Name": jsii.String(fmt.Sprintf("app-sg-%s-%s", region, envSuffix)),
		}),
	})

	dbSG := securitygroup.NewSecurityGroup(scope, jsii.String("database-security-group"), &securitygroup.SecurityGroupConfig{
		Name:        jsii.String(fmt.Sprintf("db-sg-%s-%s", region, envSuffix)),
		Description: jsii.String("Security group for database instances"),
		VpcId:       mainVpc.Id(),
		Ingress: &[]*securitygroup.SecurityGroupIngress{
			{
				Description:    jsii.String("MySQL from application tier"),
				FromPort:       jsii.Number(3306),
				ToPort:         jsii.Number(3306),
				Protocol:       jsii.String("tcp"),
				SecurityGroups: &[]*string{appSG.Id()},
			},
		},
		Tags: mergeTags(tags, &map[string]*string{
			"Name": jsii.String(fmt.Sprintf("db-sg-%s-%s", region, envSuffix)),
		}),
	})

	// IAM Role for EC2
	ec2Role := iamrole.NewIamRole(scope, jsii.String("ec2-role"), &iamrole.IamRoleConfig{
		Name: jsii.String(fmt.Sprintf("ec2-migration-role-%s-%s", region, envSuffix)),
		AssumeRolePolicy: jsii.String(`{
			"Version": "2012-10-17",
			"Statement": [
				{
					"Action": "sts:AssumeRole",
					"Effect": "Allow",
					"Principal": {
						"Service": "ec2.amazonaws.com"
					}
				}
			]
		}`),
		Tags: tags,
	})

	iamrolepolicyattachment.NewIamRolePolicyAttachment(scope, jsii.String("ec2-cloudwatch-policy"), &iamrolepolicyattachment.IamRolePolicyAttachmentConfig{
		Role:      ec2Role.Name(),
		PolicyArn: jsii.String("arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"),
	})

	iamrolepolicyattachment.NewIamRolePolicyAttachment(scope, jsii.String("ec2-ssm-policy"), &iamrolepolicyattachment.IamRolePolicyAttachmentConfig{
		Role:      ec2Role.Name(),
		PolicyArn: jsii.String("arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"),
	})

	ec2Profile := iaminstanceprofile.NewIamInstanceProfile(scope, jsii.String("ec2-instance-profile"), &iaminstanceprofile.IamInstanceProfileConfig{
		Name: jsii.String(fmt.Sprintf("ec2-migration-profile-%s-%s", region, envSuffix)),
		Role: ec2Role.Name(),
		Tags: tags,
	})

	// CloudWatch Log Groups (centralized logging as per PROMPT requirements)
	cloudwatchloggroup.NewCloudwatchLogGroup(scope, jsii.String("web-log-group"), &cloudwatchloggroup.CloudwatchLogGroupConfig{
		Name:            jsii.String(fmt.Sprintf("/migration/web/%s-%s", region, envSuffix)),
		RetentionInDays: jsii.Number(30),
		Tags:            tags,
	})

	cloudwatchloggroup.NewCloudwatchLogGroup(scope, jsii.String("app-log-group"), &cloudwatchloggroup.CloudwatchLogGroupConfig{
		Name:            jsii.String(fmt.Sprintf("/migration/app/%s-%s", region, envSuffix)),
		RetentionInDays: jsii.Number(30),
		Tags:            tags,
	})

	// CloudTrail Log Group for API activity monitoring (PROMPT requirement #8)
	cloudwatchloggroup.NewCloudwatchLogGroup(scope, jsii.String("cloudtrail-log-group"), &cloudwatchloggroup.CloudwatchLogGroupConfig{
		Name:            jsii.String(fmt.Sprintf("/migration/cloudtrail/%s-%s", region, envSuffix)),
		RetentionInDays: jsii.Number(90),
		Tags:            tags,
	})

	// Database Subnet Group
	dbSubnetGroup := dbsubnetgroup.NewDbSubnetGroup(scope, jsii.String("db-subnet-group"), &dbsubnetgroup.DbSubnetGroupConfig{
		Name:      jsii.String(fmt.Sprintf("migration-db-subnet-group-%s-%s", region, envSuffix)),
		SubnetIds: &databaseSubnetIds,
		Tags: mergeTags(tags, &map[string]*string{
			"Name": jsii.String(fmt.Sprintf("db-subnet-group-%s-%s", region, envSuffix)),
		}),
	})

	// RDS Database with Secrets Manager and KMS encryption
	database := dbinstance.NewDbInstance(scope, jsii.String("primary-database"), &dbinstance.DbInstanceConfig{
		Identifier:       jsii.String(fmt.Sprintf("migration-primary-db-%s-%s", region, envSuffix)),
		Engine:           jsii.String("mysql"),
		EngineVersion:    jsii.String("8.0"),
		InstanceClass:    jsii.String("db.t3.micro"),
		AllocatedStorage: jsii.Number(20),
		StorageType:      jsii.String("gp2"),
		StorageEncrypted: jsii.Bool(true),
		KmsKeyId:         kmsKey.Arn(),

		DbName:                   jsii.String("migrationdb"),
		Username:                 jsii.String("admin"),
		ManageMasterUserPassword: jsii.Bool(true),
		MasterUserSecretKmsKeyId: kmsKey.Arn(),

		VpcSecurityGroupIds: &[]*string{dbSG.Id()},
		DbSubnetGroupName:   dbSubnetGroup.Name(),

		BackupRetentionPeriod: jsii.Number(7),
		BackupWindow:          jsii.String("03:00-04:00"),
		MaintenanceWindow:     jsii.String("sun:04:00-sun:05:00"),

		MultiAz:                 jsii.Bool(true),
		PubliclyAccessible:      jsii.Bool(false),
		DeletionProtection:      jsii.Bool(true),
		SkipFinalSnapshot:       jsii.Bool(false),
		FinalSnapshotIdentifier: jsii.String(fmt.Sprintf("migration-final-snapshot-%s-%s", region, envSuffix)),

		Tags: mergeTags(tags, &map[string]*string{
			"Name": jsii.String(fmt.Sprintf("primary-database-%s-%s", region, envSuffix)),
		}),
	})

	// Create read replica for cross-region disaster recovery (will be created in other region)
	var readReplica dbinstance.DbInstance
	if region == "us-west-2" {
		// Create read replica pointing to us-east-1 primary
		readReplica = dbinstance.NewDbInstance(scope, jsii.String("read-replica-database"), &dbinstance.DbInstanceConfig{
			Identifier:              jsii.String(fmt.Sprintf("migration-read-replica-%s-%s", region, envSuffix)),
			ReplicateSourceDb:       jsii.String(fmt.Sprintf("migration-primary-db-us-east-1-%s", envSuffix)),
			InstanceClass:           jsii.String("db.t3.micro"),
			PubliclyAccessible:      jsii.Bool(false),
			AutoMinorVersionUpgrade: jsii.Bool(true),
			StorageEncrypted:        jsii.Bool(true),
			KmsKeyId:                kmsKey.Arn(),
			Tags: mergeTags(tags, &map[string]*string{
				"Name": jsii.String(fmt.Sprintf("read-replica-database-%s-%s", region, envSuffix)),
			}),
		})
	}

	// Get latest Amazon Linux 2 AMI
	ami := dataawsami.NewDataAwsAmi(scope, jsii.String("amazon-linux"), &dataawsami.DataAwsAmiConfig{
		MostRecent: jsii.Bool(true),
		Owners:     &[]*string{jsii.String("amazon")},
		Filter: &[]*dataawsami.DataAwsAmiFilter{
			{
				Name:   jsii.String("name"),
				Values: &[]*string{jsii.String("amzn2-ami-hvm-*-x86_64-gp2")},
			},
		},
	})

	// User data for web tier
	webUserData := `#!/bin/bash
yum update -y
yum install -y httpd
systemctl start httpd
systemctl enable httpd
echo '<h1>Web Server - $(hostname -f)</h1>' > /var/www/html/index.html`

	// Launch Template for Web Tier
	webLT := launchtemplate.NewLaunchTemplate(scope, jsii.String("web-launch-template"), &launchtemplate.LaunchTemplateConfig{
		Name:         jsii.String(fmt.Sprintf("web-lt-%s-%s", region, envSuffix)),
		Description:  jsii.String("Launch template for web tier instances"),
		ImageId:      ami.Id(),
		InstanceType: jsii.String("t3.micro"),

		VpcSecurityGroupIds: &[]*string{webSG.Id()},

		IamInstanceProfile: &launchtemplate.LaunchTemplateIamInstanceProfile{
			Name: ec2Profile.Name(),
		},

		UserData: cdktf.Fn_Base64encode(cdktf.Fn_RawString(jsii.String(webUserData))),
	})

	// Launch Template for App Tier
	appUserData := `#!/bin/bash
yum update -y
yum install -y java-11-openjdk-devel
echo 'Application Server - $(hostname -f)' > /tmp/app-status.txt`

	appLT := launchtemplate.NewLaunchTemplate(scope, jsii.String("app-launch-template"), &launchtemplate.LaunchTemplateConfig{
		Name:         jsii.String(fmt.Sprintf("app-lt-%s-%s", region, envSuffix)),
		Description:  jsii.String("Launch template for application tier instances"),
		ImageId:      ami.Id(),
		InstanceType: jsii.String("t3.small"),

		VpcSecurityGroupIds: &[]*string{appSG.Id()},

		IamInstanceProfile: &launchtemplate.LaunchTemplateIamInstanceProfile{
			Name: ec2Profile.Name(),
		},

		UserData: cdktf.Fn_Base64encode(cdktf.Fn_RawString(jsii.String(appUserData))),
	})

	// Create Route 53 Hosted Zone
	hostedZone := route53zone.NewRoute53Zone(scope, jsii.String("hosted-zone"), &route53zone.Route53ZoneConfig{
		Name: jsii.String(domainName),
		Tags: tags,
	})

	// Create ACM Certificate
	certificate := acmcertificate.NewAcmCertificate(scope, jsii.String("ssl-certificate"), &acmcertificate.AcmCertificateConfig{
		DomainName:       jsii.String(domainName),
		ValidationMethod: jsii.String("DNS"),
		SubjectAlternativeNames: &[]*string{
			jsii.String(fmt.Sprintf("*.%s", domainName)),
		},
		Lifecycle: &cdktf.TerraformResourceLifecycle{
			CreateBeforeDestroy: jsii.Bool(true),
		},
		Tags: tags,
	})

	// DNS validation for ACM certificate
	certificateValidation := acmcertificatevalidation.NewAcmCertificateValidation(scope, jsii.String("cert-validation"), &acmcertificatevalidation.AcmCertificateValidationConfig{
		CertificateArn: certificate.Arn(),
		ValidationRecordFqdns: &[]*string{
			// This would normally be populated by certificate validation records
			jsii.String(fmt.Sprintf("_validation.%s", domainName)),
		},
	})

	// Application Load Balancer
	alb := lb.NewLb(scope, jsii.String("application-load-balancer"), &lb.LbConfig{
		Name:             jsii.String(fmt.Sprintf("migration-alb-%s-%s", region, envSuffix)),
		LoadBalancerType: jsii.String("application"),
		Subnets:          &publicSubnetIds,
		SecurityGroups:   &[]*string{albSG.Id()},
		Tags: mergeTags(tags, &map[string]*string{
			"Name": jsii.String(fmt.Sprintf("migration-alb-%s-%s", region, envSuffix)),
		}),
	})

	// Target Group for Web Tier
	webTG := lbtargetgroup.NewLbTargetGroup(scope, jsii.String("web-target-group"), &lbtargetgroup.LbTargetGroupConfig{
		Name:     jsii.String(fmt.Sprintf("web-tg-%s-%s", region, envSuffix)),
		Port:     jsii.Number(80),
		Protocol: jsii.String("HTTP"),
		VpcId:    mainVpc.Id(),
		HealthCheck: &lbtargetgroup.LbTargetGroupHealthCheck{
			Enabled:            jsii.Bool(true),
			HealthyThreshold:   jsii.Number(2),
			UnhealthyThreshold: jsii.Number(2),
			Timeout:            jsii.Number(5),
			Interval:           jsii.Number(30),
			Path:               jsii.String("/"),
			Matcher:            jsii.String("200"),
		},
		Tags: mergeTags(tags, &map[string]*string{
			"Name": jsii.String(fmt.Sprintf("web-tg-%s-%s", region, envSuffix)),
		}),
	})

	// HTTP Listener (redirect to HTTPS)
	lblistener.NewLbListener(scope, jsii.String("alb-listener-http"), &lblistener.LbListenerConfig{
		LoadBalancerArn: alb.Arn(),
		Port:            jsii.Number(80),
		Protocol:        jsii.String("HTTP"),
		DefaultAction: &[]*lblistener.LbListenerDefaultAction{
			{
				Type: jsii.String("redirect"),
				Redirect: &lblistener.LbListenerDefaultActionRedirect{
					Port:       jsii.String("443"),
					Protocol:   jsii.String("HTTPS"),
					StatusCode: jsii.String("HTTP_301"),
				},
			},
		},
	})

	// HTTPS Listener
	lblistener.NewLbListener(scope, jsii.String("alb-listener-https"), &lblistener.LbListenerConfig{
		LoadBalancerArn: alb.Arn(),
		Port:            jsii.Number(443),
		Protocol:        jsii.String("HTTPS"),
		CertificateArn:  certificate.Arn(),
		SslPolicy:       jsii.String("ELBSecurityPolicy-TLS-1-2-2017-01"),
		DefaultAction: &[]*lblistener.LbListenerDefaultAction{
			{
				Type:           jsii.String("forward"),
				TargetGroupArn: webTG.Arn(),
			},
		},
	})

	// Auto Scaling Group for Web Tier
	webASG := autoscalinggroup.NewAutoscalingGroup(scope, jsii.String("web-auto-scaling-group"), &autoscalinggroup.AutoscalingGroupConfig{
		Name:                   jsii.String(fmt.Sprintf("web-asg-%s-%s", region, envSuffix)),
		VpcZoneIdentifier:      &privateSubnetIds,
		MinSize:                jsii.Number(2),
		MaxSize:                jsii.Number(6),
		DesiredCapacity:        jsii.Number(3),
		HealthCheckType:        jsii.String("ELB"),
		HealthCheckGracePeriod: jsii.Number(300),
		TargetGroupArns:        &[]*string{webTG.Arn()},
		LaunchTemplate: &autoscalinggroup.AutoscalingGroupLaunchTemplate{
			Id:      webLT.Id(),
			Version: jsii.String("$Latest"),
		},
		Tag: &[]*autoscalinggroup.AutoscalingGroupTag{
			{
				Key:               jsii.String("Name"),
				Value:             jsii.String(fmt.Sprintf("web-asg-%s-%s", region, envSuffix)),
				PropagateAtLaunch: jsii.Bool(true),
			},
		},
	})

	// Auto Scaling Group for App Tier
	appASG := autoscalinggroup.NewAutoscalingGroup(scope, jsii.String("app-auto-scaling-group"), &autoscalinggroup.AutoscalingGroupConfig{
		Name:                   jsii.String(fmt.Sprintf("app-asg-%s-%s", region, envSuffix)),
		VpcZoneIdentifier:      &privateSubnetIds,
		MinSize:                jsii.Number(2),
		MaxSize:                jsii.Number(8),
		DesiredCapacity:        jsii.Number(4),
		HealthCheckType:        jsii.String("EC2"),
		HealthCheckGracePeriod: jsii.Number(300),
		LaunchTemplate: &autoscalinggroup.AutoscalingGroupLaunchTemplate{
			Id:      appLT.Id(),
			Version: jsii.String("$Latest"),
		},
		Tag: &[]*autoscalinggroup.AutoscalingGroupTag{
			{
				Key:               jsii.String("Name"),
				Value:             jsii.String(fmt.Sprintf("app-asg-%s-%s", region, envSuffix)),
				PropagateAtLaunch: jsii.Bool(true),
			},
		},
	})

	// Create Route 53 health check for the ALB
	healthCheck := route53healthcheck.NewRoute53HealthCheck(scope, jsii.String("alb-health-check"), &route53healthcheck.Route53HealthCheckConfig{
		Fqdn:             alb.DnsName(),
		Port:             jsii.Number(443),
		Type:             jsii.String("HTTPS"),
		ResourcePath:     jsii.String("/"),
		RequestInterval:  jsii.Number(30),
		FailureThreshold: jsii.Number(3),
		Tags: mergeTags(tags, &map[string]*string{
			"Name": jsii.String(fmt.Sprintf("alb-health-check-%s-%s", region, envSuffix)),
		}),
	})

	// Create Route 53 DNS record
	route53record.NewRoute53Record(scope, jsii.String("dns-record"), &route53record.Route53RecordConfig{
		ZoneId: hostedZone.ZoneId(),
		Name:   jsii.String(domainName),
		Type:   jsii.String("A"),
		Alias: &route53record.Route53RecordAlias{
			Name:                 alb.DnsName(),
			ZoneId:               alb.ZoneId(),
			EvaluateTargetHealth: jsii.Bool(true),
		},
		SetIdentifier: jsii.String(region),
		FailoverRoutingPolicy: &route53record.Route53RecordFailoverRoutingPolicy{
			Type: jsii.String(func() string {
				if region == "us-east-1" {
					return "PRIMARY"
				}
				return "SECONDARY"
			}()),
		},
		HealthCheckId: healthCheck.Id(),
	})

	// CloudWatch Alarms for monitoring
	cloudwatchmetricalarm.NewCloudwatchMetricAlarm(scope, jsii.String("high-cpu-alarm"), &cloudwatchmetricalarm.CloudwatchMetricAlarmConfig{
		AlarmName:          jsii.String(fmt.Sprintf("high-cpu-alarm-%s-%s", region, envSuffix)),
		ComparisonOperator: jsii.String("GreaterThanThreshold"),
		EvaluationPeriods:  jsii.Number(2),
		MetricName:         jsii.String("CPUUtilization"),
		Namespace:          jsii.String("AWS/EC2"),
		Period:             jsii.Number(120),
		Statistic:          jsii.String("Average"),
		Threshold:          jsii.Number(80),
		AlarmDescription:   jsii.String("This metric monitors ec2 cpu utilization"),
		Dimensions: &map[string]*string{
			"AutoScalingGroupName": webASG.Name(),
		},
		Tags: tags,
	})

	cloudwatchmetricalarm.NewCloudwatchMetricAlarm(scope, jsii.String("alb-target-response-time"), &cloudwatchmetricalarm.CloudwatchMetricAlarmConfig{
		AlarmName:          jsii.String(fmt.Sprintf("alb-response-time-%s-%s", region, envSuffix)),
		ComparisonOperator: jsii.String("GreaterThanThreshold"),
		EvaluationPeriods:  jsii.Number(2),
		MetricName:         jsii.String("TargetResponseTime"),
		Namespace:          jsii.String("AWS/ApplicationELB"),
		Period:             jsii.Number(300),
		Statistic:          jsii.String("Average"),
		Threshold:          jsii.Number(2),
		AlarmDescription:   jsii.String("This metric monitors ALB target response time"),
		Dimensions: &map[string]*string{
			"LoadBalancer": alb.ArnSuffix(),
		},
		Tags: tags,
	})

	cloudwatchmetricalarm.NewCloudwatchMetricAlarm(scope, jsii.String("database-cpu-alarm"), &cloudwatchmetricalarm.CloudwatchMetricAlarmConfig{
		AlarmName:          jsii.String(fmt.Sprintf("database-cpu-alarm-%s-%s", region, envSuffix)),
		ComparisonOperator: jsii.String("GreaterThanThreshold"),
		EvaluationPeriods:  jsii.Number(2),
		MetricName:         jsii.String("CPUUtilization"),
		Namespace:          jsii.String("AWS/RDS"),
		Period:             jsii.Number(300),
		Statistic:          jsii.String("Average"),
		Threshold:          jsii.Number(75),
		AlarmDescription:   jsii.String("This metric monitors RDS CPU utilization"),
		Dimensions: &map[string]*string{
			"DBInstanceIdentifier": database.Id(),
		},
		Tags: tags,
	})

	// CloudTrail for API activity monitoring
	cloudTrailBucket := s3bucket.NewS3Bucket(scope, jsii.String("cloudtrail-bucket"), &s3bucket.S3BucketConfig{
		Bucket: jsii.String(fmt.Sprintf("migration-cloudtrail-%s-%s-%d", region, envSuffix, 54321)),
		Tags:   tags,
	})

	s3bucketserversideencryptionconfiguration.NewS3BucketServerSideEncryptionConfigurationA(scope, jsii.String("cloudtrail-bucket-encryption"), &s3bucketserversideencryptionconfiguration.S3BucketServerSideEncryptionConfigurationAConfig{
		Bucket: cloudTrailBucket.Id(),
		Rule: &[]*s3bucketserversideencryptionconfiguration.S3BucketServerSideEncryptionConfigurationRuleA{
			{
				ApplyServerSideEncryptionByDefault: &s3bucketserversideencryptionconfiguration.S3BucketServerSideEncryptionConfigurationRuleApplyServerSideEncryptionByDefaultA{
					KmsMasterKeyId: kmsKey.Arn(),
					SseAlgorithm:   jsii.String("aws:kms"),
				},
			},
		},
	})

	cloudtrail.NewCloudtrail(scope, jsii.String("migration-cloudtrail"), &cloudtrail.CloudtrailConfig{
		Name:                       jsii.String(fmt.Sprintf("migration-cloudtrail-%s-%s", region, envSuffix)),
		S3BucketName:               cloudTrailBucket.Id(),
		IncludeGlobalServiceEvents: jsii.Bool(true),
		IsMultiRegionTrail:         jsii.Bool(false), // Per-region trail
		EnableLogging:              jsii.Bool(true),
		KmsKeyId:                   kmsKey.Arn(),
		CloudWatchLogsGroupArn:     jsii.String(fmt.Sprintf("%s:*", fmt.Sprintf("/migration/cloudtrail/%s-%s", region, envSuffix))),
		Tags:                       tags,
	})

	// Target group attachment is handled via TargetGroupArns in the ASG configuration above

	return &CompleteInfrastructure{
		VPC:                   mainVpc,
		LoadBalancer:          alb,
		Database:              database,
		ReadReplica:           readReplica,
		WebASG:                webASG,
		AppASG:                appASG,
		S3Bucket:              s3Bucket,
		KMSKey:                kmsKey,
		DatabaseSecret:        dbSecret,
		HostedZone:            hostedZone,
		Certificate:           certificate,
		CertificateValidation: certificateValidation,
		HealthCheck:           healthCheck,
	}
}

func NewInfrastructureStack(scope constructs.Construct, id *string, config *InfrastructureStackConfig) *InfrastructureStack {
	stack := cdktf.NewTerraformStack(scope, id)

	// AWS Provider
	provider.NewAwsProvider(stack, jsii.String("aws"), &provider.AwsProviderConfig{
		Region: jsii.String(config.Region),
		DefaultTags: &[]*provider.AwsProviderDefaultTags{
			{
				Tags: &map[string]*string{
					"Project":     jsii.String("Migration"),
					"Creator":     jsii.String("CloudEngineer"),
					"Environment": jsii.String(config.Environment),
					"Region":      jsii.String(config.Region),
				},
			},
		},
	})

	// Get environment suffix
	envSuffix := os.Getenv("ENVIRONMENT_SUFFIX")
	if envSuffix == "" {
		envSuffix = "dev"
	}

	// Create the complete infrastructure
	infra := NewCompleteInfrastructure(stack, jsii.String("migration-infra"), config.Region, envSuffix)

	// Outputs
	cdktf.NewTerraformOutput(stack, jsii.String("vpc-id"), &cdktf.TerraformOutputConfig{
		Value: infra.VPC.Id(),
	})

	cdktf.NewTerraformOutput(stack, jsii.String("alb-dns"), &cdktf.TerraformOutputConfig{
		Value: infra.LoadBalancer.DnsName(),
	})

	cdktf.NewTerraformOutput(stack, jsii.String("database-endpoint"), &cdktf.TerraformOutputConfig{
		Value: infra.Database.Endpoint(),
	})

	return &InfrastructureStack{
		TerraformStack: stack,
	}
}

func NewMultiRegionInfrastructureStack(scope constructs.Construct, id *string, envSuffix string) cdktf.TerraformStack {
	stack := cdktf.NewTerraformStack(scope, id)

	// Configure remote backend for state persistence
	awsRegion := os.Getenv("AWS_REGION")
	if awsRegion == "" {
		awsRegion = "us-east-1"
	}

	terraformStateBucket := os.Getenv("TERRAFORM_STATE_BUCKET")
	if terraformStateBucket != "" {
		backend := cdktf.NewS3Backend(stack, &cdktf.S3BackendConfig{
			Bucket:  jsii.String(terraformStateBucket),
			Key:     jsii.String(fmt.Sprintf("cdktf/%s/terraform.tfstate", envSuffix)),
			Region:  jsii.String(awsRegion),
			Encrypt: jsii.Bool(true),
		})
		_ = backend // backend is used implicitly
	}

	// Create AWS providers for both regions
	eastProvider := provider.NewAwsProvider(stack, jsii.String("aws-east"), &provider.AwsProviderConfig{
		Region: jsii.String("us-east-1"),
		Alias:  jsii.String("east"),
	})

	westProvider := provider.NewAwsProvider(stack, jsii.String("aws-west"), &provider.AwsProviderConfig{
		Region: jsii.String("us-west-2"),
		Alias:  jsii.String("west"),
	})

	// Create infrastructure in us-east-1
	CreateRegionalInfrastructure(stack, "east", "us-east-1", envSuffix, eastProvider)

	// Create infrastructure in us-west-2
	CreateRegionalInfrastructure(stack, "west", "us-west-2", envSuffix, westProvider)

	return stack
}

func CreateRegionalInfrastructure(scope constructs.Construct, regionName string, regionCode string, envSuffix string, awsProvider provider.AwsProvider) {
	// Base tags for all resources
	baseTags := &map[string]*string{
		"Project":     jsii.String("Migration"),
		"Creator":     jsii.String("CloudEngineer"),
		"Environment": jsii.String("production"),
		"Region":      jsii.String(regionCode),
		"CostCenter":  jsii.String("IT-Infrastructure"),
	}

	// Create VPC with the required CIDR block
	vpcName := fmt.Sprintf("tap-vpc-%s-%s", regionCode, envSuffix)
	mainVpc := vpc.NewVpc(scope, jsii.String(fmt.Sprintf("vpc-%s", regionName)), &vpc.VpcConfig{
		CidrBlock:          jsii.String("10.0.0.0/16"),
		EnableDnsHostnames: jsii.Bool(true),
		EnableDnsSupport:   jsii.Bool(true),
		Provider:           awsProvider,
		Tags: mergeTags(baseTags, &map[string]*string{
			"Name": jsii.String(vpcName),
		}),
	})

	// Get availability zones for this region
	azs := dataawsavailabilityzones.NewDataAwsAvailabilityZones(scope, jsii.String(fmt.Sprintf("azs-%s", regionName)), &dataawsavailabilityzones.DataAwsAvailabilityZonesConfig{
		State:    jsii.String("available"),
		Provider: awsProvider,
	})

	// Create Internet Gateway
	igwName := fmt.Sprintf("tap-igw-%s-%s", regionCode, envSuffix)
	igw := internetgateway.NewInternetGateway(scope, jsii.String(fmt.Sprintf("igw-%s", regionName)), &internetgateway.InternetGatewayConfig{
		VpcId:    mainVpc.Id(),
		Provider: awsProvider,
		Tags: mergeTags(baseTags, &map[string]*string{
			"Name": jsii.String(igwName),
		}),
	})

	// Use CDKTF Fn.element to access availability zones
	firstAz := jsii.String(cdktf.Fn_Element(azs.Names(), jsii.Number(0)).(string))
	secondAz := jsii.String(cdktf.Fn_Element(azs.Names(), jsii.Number(1)).(string))

	// Create public subnets
	publicSubnet1Name := fmt.Sprintf("tap-public-subnet-1-%s-%s", regionCode, envSuffix)
	publicSubnet1 := subnet.NewSubnet(scope, jsii.String(fmt.Sprintf("public-subnet-1-%s", regionName)), &subnet.SubnetConfig{
		VpcId:               mainVpc.Id(),
		CidrBlock:           jsii.String("10.0.1.0/24"),
		AvailabilityZone:    firstAz,
		MapPublicIpOnLaunch: jsii.Bool(true),
		Provider:            awsProvider,
		Tags: mergeTags(baseTags, &map[string]*string{
			"Name": jsii.String(publicSubnet1Name),
			"Type": jsii.String("public"),
		}),
	})

	publicSubnet2Name := fmt.Sprintf("tap-public-subnet-2-%s-%s", regionCode, envSuffix)
	publicSubnet2 := subnet.NewSubnet(scope, jsii.String(fmt.Sprintf("public-subnet-2-%s", regionName)), &subnet.SubnetConfig{
		VpcId:               mainVpc.Id(),
		CidrBlock:           jsii.String("10.0.2.0/24"),
		AvailabilityZone:    secondAz,
		MapPublicIpOnLaunch: jsii.Bool(true),
		Provider:            awsProvider,
		Tags: mergeTags(baseTags, &map[string]*string{
			"Name": jsii.String(publicSubnet2Name),
			"Type": jsii.String("public"),
		}),
	})

	// Create EIPs for NAT Gateways
	eip1 := eip.NewEip(scope, jsii.String(fmt.Sprintf("eip-1-%s", regionName)), &eip.EipConfig{
		Domain:   jsii.String("vpc"),
		Provider: awsProvider,
		Tags: mergeTags(baseTags, &map[string]*string{
			"Name": jsii.String(fmt.Sprintf("tap-eip-1-%s-%s", regionCode, envSuffix)),
		}),
	})

	eip2 := eip.NewEip(scope, jsii.String(fmt.Sprintf("eip-2-%s", regionName)), &eip.EipConfig{
		Domain:   jsii.String("vpc"),
		Provider: awsProvider,
		Tags: mergeTags(baseTags, &map[string]*string{
			"Name": jsii.String(fmt.Sprintf("tap-eip-2-%s-%s", regionCode, envSuffix)),
		}),
	})

	// Create NAT Gateways
	natGw1Name := fmt.Sprintf("tap-nat-gw-1-%s-%s", regionCode, envSuffix)
	natGw1 := natgateway.NewNatGateway(scope, jsii.String(fmt.Sprintf("nat-gw-1-%s", regionName)), &natgateway.NatGatewayConfig{
		AllocationId: eip1.Id(),
		SubnetId:     publicSubnet1.Id(),
		Provider:     awsProvider,
		Tags: mergeTags(baseTags, &map[string]*string{
			"Name": jsii.String(natGw1Name),
		}),
	})

	natGw2Name := fmt.Sprintf("tap-nat-gw-2-%s-%s", regionCode, envSuffix)
	natGw2 := natgateway.NewNatGateway(scope, jsii.String(fmt.Sprintf("nat-gw-2-%s", regionName)), &natgateway.NatGatewayConfig{
		AllocationId: eip2.Id(),
		SubnetId:     publicSubnet2.Id(),
		Provider:     awsProvider,
		Tags: mergeTags(baseTags, &map[string]*string{
			"Name": jsii.String(natGw2Name),
		}),
	})

	// Create private subnets
	privateSubnet1Name := fmt.Sprintf("tap-private-subnet-1-%s-%s", regionCode, envSuffix)
	privateSubnet1 := subnet.NewSubnet(scope, jsii.String(fmt.Sprintf("private-subnet-1-%s", regionName)), &subnet.SubnetConfig{
		VpcId:            mainVpc.Id(),
		CidrBlock:        jsii.String("10.0.3.0/24"),
		AvailabilityZone: firstAz,
		Provider:         awsProvider,
		Tags: mergeTags(baseTags, &map[string]*string{
			"Name": jsii.String(privateSubnet1Name),
			"Type": jsii.String("private"),
		}),
	})

	privateSubnet2Name := fmt.Sprintf("tap-private-subnet-2-%s-%s", regionCode, envSuffix)
	privateSubnet2 := subnet.NewSubnet(scope, jsii.String(fmt.Sprintf("private-subnet-2-%s", regionName)), &subnet.SubnetConfig{
		VpcId:            mainVpc.Id(),
		CidrBlock:        jsii.String("10.0.4.0/24"),
		AvailabilityZone: secondAz,
		Provider:         awsProvider,
		Tags: mergeTags(baseTags, &map[string]*string{
			"Name": jsii.String(privateSubnet2Name),
			"Type": jsii.String("private"),
		}),
	})

	// Create database subnets
	dbSubnet1Name := fmt.Sprintf("tap-db-subnet-1-%s-%s", regionCode, envSuffix)
	dbSubnet1 := subnet.NewSubnet(scope, jsii.String(fmt.Sprintf("db-subnet-1-%s", regionName)), &subnet.SubnetConfig{
		VpcId:            mainVpc.Id(),
		CidrBlock:        jsii.String("10.0.5.0/24"),
		AvailabilityZone: firstAz,
		Provider:         awsProvider,
		Tags: mergeTags(baseTags, &map[string]*string{
			"Name": jsii.String(dbSubnet1Name),
			"Type": jsii.String("database"),
		}),
	})

	dbSubnet2Name := fmt.Sprintf("tap-db-subnet-2-%s-%s", regionCode, envSuffix)
	dbSubnet2 := subnet.NewSubnet(scope, jsii.String(fmt.Sprintf("db-subnet-2-%s", regionName)), &subnet.SubnetConfig{
		VpcId:            mainVpc.Id(),
		CidrBlock:        jsii.String("10.0.6.0/24"),
		AvailabilityZone: secondAz,
		Provider:         awsProvider,
		Tags: mergeTags(baseTags, &map[string]*string{
			"Name": jsii.String(dbSubnet2Name),
			"Type": jsii.String("database"),
		}),
	})

	// Create route tables
	publicRtName := fmt.Sprintf("tap-public-rt-%s-%s", regionCode, envSuffix)
	publicRt := routetable.NewRouteTable(scope, jsii.String(fmt.Sprintf("public-rt-%s", regionName)), &routetable.RouteTableConfig{
		VpcId:    mainVpc.Id(),
		Provider: awsProvider,
		Tags: mergeTags(baseTags, &map[string]*string{
			"Name": jsii.String(publicRtName),
		}),
	})

	// Add route to internet gateway
	route.NewRoute(scope, jsii.String(fmt.Sprintf("public-route-%s", regionName)), &route.RouteConfig{
		RouteTableId:         publicRt.Id(),
		DestinationCidrBlock: jsii.String("0.0.0.0/0"),
		GatewayId:            igw.Id(),
		Provider:             awsProvider,
	})

	privateRt1Name := fmt.Sprintf("tap-private-rt-1-%s-%s", regionCode, envSuffix)
	privateRt1 := routetable.NewRouteTable(scope, jsii.String(fmt.Sprintf("private-rt-1-%s", regionName)), &routetable.RouteTableConfig{
		VpcId:    mainVpc.Id(),
		Provider: awsProvider,
		Tags: mergeTags(baseTags, &map[string]*string{
			"Name": jsii.String(privateRt1Name),
		}),
	})

	// Add route to NAT gateway
	route.NewRoute(scope, jsii.String(fmt.Sprintf("private-route-1-%s", regionName)), &route.RouteConfig{
		RouteTableId:         privateRt1.Id(),
		DestinationCidrBlock: jsii.String("0.0.0.0/0"),
		NatGatewayId:         natGw1.Id(),
		Provider:             awsProvider,
	})

	privateRt2Name := fmt.Sprintf("tap-private-rt-2-%s-%s", regionCode, envSuffix)
	privateRt2 := routetable.NewRouteTable(scope, jsii.String(fmt.Sprintf("private-rt-2-%s", regionName)), &routetable.RouteTableConfig{
		VpcId:    mainVpc.Id(),
		Provider: awsProvider,
		Tags: mergeTags(baseTags, &map[string]*string{
			"Name": jsii.String(privateRt2Name),
		}),
	})

	// Add route to NAT gateway
	route.NewRoute(scope, jsii.String(fmt.Sprintf("private-route-2-%s", regionName)), &route.RouteConfig{
		RouteTableId:         privateRt2.Id(),
		DestinationCidrBlock: jsii.String("0.0.0.0/0"),
		NatGatewayId:         natGw2.Id(),
		Provider:             awsProvider,
	})

	// Associate route tables with subnets
	routetableassociation.NewRouteTableAssociation(scope, jsii.String(fmt.Sprintf("public-rta-1-%s", regionName)), &routetableassociation.RouteTableAssociationConfig{
		SubnetId:     publicSubnet1.Id(),
		RouteTableId: publicRt.Id(),
		Provider:     awsProvider,
	})

	routetableassociation.NewRouteTableAssociation(scope, jsii.String(fmt.Sprintf("public-rta-2-%s", regionName)), &routetableassociation.RouteTableAssociationConfig{
		SubnetId:     publicSubnet2.Id(),
		RouteTableId: publicRt.Id(),
		Provider:     awsProvider,
	})

	routetableassociation.NewRouteTableAssociation(scope, jsii.String(fmt.Sprintf("private-rta-1-%s", regionName)), &routetableassociation.RouteTableAssociationConfig{
		SubnetId:     privateSubnet1.Id(),
		RouteTableId: privateRt1.Id(),
		Provider:     awsProvider,
	})

	routetableassociation.NewRouteTableAssociation(scope, jsii.String(fmt.Sprintf("private-rta-2-%s", regionName)), &routetableassociation.RouteTableAssociationConfig{
		SubnetId:     privateSubnet2.Id(),
		RouteTableId: privateRt2.Id(),
		Provider:     awsProvider,
	})

	// Create Security Groups
	albSgName := fmt.Sprintf("tap-alb-sg-%s-%s", regionCode, envSuffix)
	albSg := securitygroup.NewSecurityGroup(scope, jsii.String(fmt.Sprintf("alb-sg-%s", regionName)), &securitygroup.SecurityGroupConfig{
		Name:        jsii.String(albSgName),
		Description: jsii.String("Security group for ALB"),
		VpcId:       mainVpc.Id(),
		Provider:    awsProvider,
		Ingress: &[]*securitygroup.SecurityGroupIngress{
			{
				Description: jsii.String("HTTP from company IP ranges"),
				FromPort:    jsii.Number(80),
				ToPort:      jsii.Number(80),
				Protocol:    jsii.String("tcp"),
				CidrBlocks:  &[]*string{jsii.String("203.0.113.0/24"), jsii.String("198.51.100.0/24")},
			},
			{
				Description: jsii.String("HTTPS from company IP ranges"),
				FromPort:    jsii.Number(443),
				ToPort:      jsii.Number(443),
				Protocol:    jsii.String("tcp"),
				CidrBlocks:  &[]*string{jsii.String("203.0.113.0/24"), jsii.String("198.51.100.0/24")},
			},
		},
		Egress: &[]*securitygroup.SecurityGroupEgress{
			{
				Description: jsii.String("All outbound traffic"),
				FromPort:    jsii.Number(0),
				ToPort:      jsii.Number(0),
				Protocol:    jsii.String("-1"),
				CidrBlocks:  &[]*string{jsii.String("0.0.0.0/0")},
			},
		},
		Tags: mergeTags(baseTags, &map[string]*string{
			"Name": jsii.String(albSgName),
		}),
	})

	webSgName := fmt.Sprintf("tap-web-sg-%s-%s", regionCode, envSuffix)
	webSg := securitygroup.NewSecurityGroup(scope, jsii.String(fmt.Sprintf("web-sg-%s", regionName)), &securitygroup.SecurityGroupConfig{
		Name:        jsii.String(webSgName),
		Description: jsii.String("Security group for web servers"),
		VpcId:       mainVpc.Id(),
		Provider:    awsProvider,
		Ingress: &[]*securitygroup.SecurityGroupIngress{
			{
				Description:    jsii.String("HTTP from ALB"),
				FromPort:       jsii.Number(80),
				ToPort:         jsii.Number(80),
				Protocol:       jsii.String("tcp"),
				SecurityGroups: &[]*string{albSg.Id()},
			},
			{
				Description: jsii.String("SSH from company IP ranges"),
				FromPort:    jsii.Number(22),
				ToPort:      jsii.Number(22),
				Protocol:    jsii.String("tcp"),
				CidrBlocks:  &[]*string{jsii.String("203.0.113.0/24"), jsii.String("198.51.100.0/24")},
			},
		},
		Egress: &[]*securitygroup.SecurityGroupEgress{
			{
				Description: jsii.String("All outbound traffic"),
				FromPort:    jsii.Number(0),
				ToPort:      jsii.Number(0),
				Protocol:    jsii.String("-1"),
				CidrBlocks:  &[]*string{jsii.String("0.0.0.0/0")},
			},
		},
		Tags: mergeTags(baseTags, &map[string]*string{
			"Name": jsii.String(webSgName),
		}),
	})

	dbSgName := fmt.Sprintf("tap-db-sg-%s-%s", regionCode, envSuffix)
	dbSg := securitygroup.NewSecurityGroup(scope, jsii.String(fmt.Sprintf("db-sg-%s", regionName)), &securitygroup.SecurityGroupConfig{
		Name:        jsii.String(dbSgName),
		Description: jsii.String("Security group for database"),
		VpcId:       mainVpc.Id(),
		Provider:    awsProvider,
		Ingress: &[]*securitygroup.SecurityGroupIngress{
			{
				Description:    jsii.String("MySQL from web servers"),
				FromPort:       jsii.Number(3306),
				ToPort:         jsii.Number(3306),
				Protocol:       jsii.String("tcp"),
				SecurityGroups: &[]*string{webSg.Id()},
			},
		},
		Tags: mergeTags(baseTags, &map[string]*string{
			"Name": jsii.String(dbSgName),
		}),
	})

	// Create Database Subnet Group
	dbSubnetGroupName := fmt.Sprintf("tap-db-subnet-group-%s-%s", regionCode, envSuffix)
	dbSubnetGroup := dbsubnetgroup.NewDbSubnetGroup(scope, jsii.String(fmt.Sprintf("db-subnet-group-%s", regionName)), &dbsubnetgroup.DbSubnetGroupConfig{
		Name:      jsii.String(dbSubnetGroupName),
		SubnetIds: &[]*string{dbSubnet1.Id(), dbSubnet2.Id()},
		Provider:  awsProvider,
		Tags: mergeTags(baseTags, &map[string]*string{
			"Name": jsii.String(dbSubnetGroupName),
		}),
	})

	// Create RDS MySQL Database
	dbName := fmt.Sprintf("tap-database-%s-%s", regionCode, envSuffix)
	database := dbinstance.NewDbInstance(scope, jsii.String(fmt.Sprintf("mysql-database-%s", regionName)), &dbinstance.DbInstanceConfig{
		Identifier:            jsii.String(dbName),
		Engine:                jsii.String("mysql"),
		EngineVersion:         jsii.String("8.0"),
		InstanceClass:         jsii.String("db.t3.micro"),
		AllocatedStorage:      jsii.Number(20),
		StorageType:           jsii.String("gp2"),
		StorageEncrypted:      jsii.Bool(true),
		DbName:                jsii.String("applicationdb"),
		Username:              jsii.String("admin"),
		Password:              jsii.String("TempPassword123#"),
		VpcSecurityGroupIds:   &[]*string{dbSg.Id()},
		DbSubnetGroupName:     dbSubnetGroup.Name(),
		BackupRetentionPeriod: jsii.Number(7),
		BackupWindow:          jsii.String("03:00-04:00"),
		MaintenanceWindow:     jsii.String("sun:04:00-sun:05:00"),
		MultiAz:               jsii.Bool(true),
		SkipFinalSnapshot:     jsii.Bool(true),
		DeletionProtection:    jsii.Bool(true),
		Provider:              awsProvider,
		Tags: mergeTags(baseTags, &map[string]*string{
			"Name": jsii.String(dbName),
		}),
	})

	// Get Amazon Linux 2023 AMI
	amiData := dataawsami.NewDataAwsAmi(scope, jsii.String(fmt.Sprintf("amazon-linux-%s", regionName)), &dataawsami.DataAwsAmiConfig{
		MostRecent: jsii.Bool(true),
		Owners:     &[]*string{jsii.String("amazon")},
		Provider:   awsProvider,
		Filter: &[]*dataawsami.DataAwsAmiFilter{
			{
				Name:   jsii.String("name"),
				Values: &[]*string{jsii.String("al2023-ami-*-x86_64")},
			},
			{
				Name:   jsii.String("virtualization-type"),
				Values: &[]*string{jsii.String("hvm")},
			},
		},
	})

	// User data script
	userData := `#!/bin/bash
yum update -y
yum install -y httpd
systemctl start httpd
systemctl enable httpd
echo '<h1>Hello from TAP Infrastructure in ` + regionCode + `!</h1>' > /var/www/html/index.html`

	// Create Launch Template
	ltName := fmt.Sprintf("tap-lt-%s-%s", regionCode, envSuffix)
	launchTemplate := launchtemplate.NewLaunchTemplate(scope, jsii.String(fmt.Sprintf("web-launch-template-%s", regionName)), &launchtemplate.LaunchTemplateConfig{
		Name:                jsii.String(ltName),
		ImageId:             amiData.Id(),
		InstanceType:        jsii.String("t3.micro"),
		VpcSecurityGroupIds: &[]*string{webSg.Id()},
		UserData:            cdktf.Fn_Base64encode(cdktf.Fn_RawString(&userData)),
		Provider:            awsProvider,
		// TagSpecifications are not supported in this CDKTF version
		Tags: mergeTags(baseTags, &map[string]*string{
			"Name": jsii.String(ltName),
		}),
	})

	// Create Application Load Balancer
	albName := fmt.Sprintf("tap-alb-%s-%s", regionCode, envSuffix)
	alb := lb.NewLb(scope, jsii.String(fmt.Sprintf("application-alb-%s", regionName)), &lb.LbConfig{
		Name:                     jsii.String(albName),
		LoadBalancerType:         jsii.String("application"),
		Subnets:                  &[]*string{publicSubnet1.Id(), publicSubnet2.Id()},
		SecurityGroups:           &[]*string{albSg.Id()},
		EnableDeletionProtection: jsii.Bool(false),
		Provider:                 awsProvider,
		Tags: mergeTags(baseTags, &map[string]*string{
			"Name": jsii.String(albName),
		}),
	})

	// Create Target Group
	tgName := fmt.Sprintf("tap-tg-%s-%s", regionCode, envSuffix)
	targetGroup := lbtargetgroup.NewLbTargetGroup(scope, jsii.String(fmt.Sprintf("web-tg-%s", regionName)), &lbtargetgroup.LbTargetGroupConfig{
		Name:       jsii.String(tgName),
		Port:       jsii.Number(80),
		Protocol:   jsii.String("HTTP"),
		VpcId:      mainVpc.Id(),
		TargetType: jsii.String("instance"),
		Provider:   awsProvider,
		HealthCheck: &lbtargetgroup.LbTargetGroupHealthCheck{
			Enabled:            jsii.Bool(true),
			HealthyThreshold:   jsii.Number(2),
			Interval:           jsii.Number(30),
			Matcher:            jsii.String("200"),
			Path:               jsii.String("/"),
			Port:               jsii.String("traffic-port"),
			Protocol:           jsii.String("HTTP"),
			Timeout:            jsii.Number(5),
			UnhealthyThreshold: jsii.Number(2),
		},
		Tags: mergeTags(baseTags, &map[string]*string{
			"Name": jsii.String(tgName),
		}),
	})

	// Create ALB Listener
	lblistener.NewLbListener(scope, jsii.String(fmt.Sprintf("web-listener-%s", regionName)), &lblistener.LbListenerConfig{
		LoadBalancerArn: alb.Arn(),
		Port:            jsii.Number(80),
		Protocol:        jsii.String("HTTP"),
		Provider:        awsProvider,
		DefaultAction: &[]*lblistener.LbListenerDefaultAction{
			{
				Type:           jsii.String("forward"),
				TargetGroupArn: targetGroup.Arn(),
			},
		},
	})

	// Create Auto Scaling Group
	asgName := fmt.Sprintf("tap-asg-%s-%s", regionCode, envSuffix)
	asg := autoscalinggroup.NewAutoscalingGroup(scope, jsii.String(fmt.Sprintf("web-asg-%s", regionName)), &autoscalinggroup.AutoscalingGroupConfig{
		Name:                   jsii.String(asgName),
		VpcZoneIdentifier:      &[]*string{privateSubnet1.Id(), privateSubnet2.Id()},
		TargetGroupArns:        &[]*string{targetGroup.Arn()},
		HealthCheckType:        jsii.String("ELB"),
		HealthCheckGracePeriod: jsii.Number(300),
		MinSize:                jsii.Number(2),
		MaxSize:                jsii.Number(6),
		DesiredCapacity:        jsii.Number(2),
		Provider:               awsProvider,
		EnabledMetrics: &[]*string{
			jsii.String("GroupMinSize"),
			jsii.String("GroupMaxSize"),
			jsii.String("GroupDesiredCapacity"),
			jsii.String("GroupInServiceInstances"),
			jsii.String("GroupTotalInstances"),
		},
		LaunchTemplate: &autoscalinggroup.AutoscalingGroupLaunchTemplate{
			Id:      launchTemplate.Id(),
			Version: jsii.String("$Latest"),
		},
		Tag: &[]*autoscalinggroup.AutoscalingGroupTag{
			{
				Key:               jsii.String("Name"),
				Value:             jsii.String(asgName),
				PropagateAtLaunch: jsii.Bool(true),
			},
			{
				Key:               jsii.String("Project"),
				Value:             jsii.String("Migration"),
				PropagateAtLaunch: jsii.Bool(true),
			},
			{
				Key:               jsii.String("Creator"),
				Value:             jsii.String("CloudEngineer"),
				PropagateAtLaunch: jsii.Bool(true),
			},
			{
				Key:               jsii.String("Environment"),
				Value:             jsii.String("production"),
				PropagateAtLaunch: jsii.Bool(true),
			},
			{
				Key:               jsii.String("Region"),
				Value:             jsii.String(regionCode),
				PropagateAtLaunch: jsii.Bool(true),
			},
			{
				Key:               jsii.String("CostCenter"),
				Value:             jsii.String("IT-Infrastructure"),
				PropagateAtLaunch: jsii.Bool(true),
			},
		},
	})

	// Create CloudWatch Log Group for application logs
	logGroupName := fmt.Sprintf("tap-log-group-%s-%s", regionCode, envSuffix)
	cloudwatchloggroup.NewCloudwatchLogGroup(scope, jsii.String(fmt.Sprintf("app-log-group-%s", regionName)), &cloudwatchloggroup.CloudwatchLogGroupConfig{
		Name:            jsii.String(fmt.Sprintf("/aws/ec2/%s", logGroupName)),
		RetentionInDays: jsii.Number(14),
		Provider:        awsProvider,
		Tags: mergeTags(baseTags, &map[string]*string{
			"Name": jsii.String(logGroupName),
		}),
	})

	// Outputs for this region
	cdktf.NewTerraformOutput(scope, jsii.String(fmt.Sprintf("vpc_id_%s", regionName)), &cdktf.TerraformOutputConfig{
		Value:       mainVpc.Id(),
		Description: jsii.String(fmt.Sprintf("ID of the VPC in %s", regionCode)),
	})

	cdktf.NewTerraformOutput(scope, jsii.String(fmt.Sprintf("alb_dns_name_%s", regionName)), &cdktf.TerraformOutputConfig{
		Value:       alb.DnsName(),
		Description: jsii.String(fmt.Sprintf("DNS name of the Application Load Balancer in %s", regionCode)),
	})

	cdktf.NewTerraformOutput(scope, jsii.String(fmt.Sprintf("database_endpoint_%s", regionName)), &cdktf.TerraformOutputConfig{
		Value:       database.Endpoint(),
		Description: jsii.String(fmt.Sprintf("RDS instance endpoint in %s", regionCode)),
		Sensitive:   jsii.Bool(true),
	})

	cdktf.NewTerraformOutput(scope, jsii.String(fmt.Sprintf("asg_name_%s", regionName)), &cdktf.TerraformOutputConfig{
		Value:       asg.Name(),
		Description: jsii.String(fmt.Sprintf("Name of the Auto Scaling Group in %s", regionCode)),
	})
}

func main() {
	app := cdktf.NewApp(nil)

	envSuffix := os.Getenv("ENVIRONMENT_SUFFIX")
	if envSuffix == "" {
		envSuffix = "dev"
	}

	// Single stack with multi-region deployment
	NewMultiRegionInfrastructureStack(app, jsii.String(fmt.Sprintf("SecurityComplianceStack%s", envSuffix)), envSuffix)

	app.Synth()
}
