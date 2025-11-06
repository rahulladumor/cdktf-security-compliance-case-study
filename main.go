package main

import (
	"fmt"
	"os"

	"github.com/aws/jsii-runtime-go"
	"github.com/hashicorp/terraform-cdk-go/cdktf"
)

func main() {
	app := cdktf.NewApp(nil)

	// Get environment suffix
	environmentSuffix := os.Getenv("ENVIRONMENT_SUFFIX")
	if environmentSuffix == "" {
		environmentSuffix = "dev"
	}
	environmentSuffix = fmt.Sprintf("cdktf-%s", environmentSuffix)

	// Create the main stack with comprehensive security configuration
	NewSecurityComplianceStack(app, jsii.String(fmt.Sprintf("SecurityComplianceStack%s", environmentSuffix)), &SecurityComplianceStackConfig{
		Region:      jsii.String("us-east-1"),
		Environment: jsii.String(environmentSuffix),
		Project:     jsii.String(""security-compliance"),
		Owner:       jsii.String("platform-team"),
		CostCenter:  jsii.String("engineering"),
		VpcCidr:     jsii.String("10.0.0.0/16"),
		AllowedIpRanges: []*string{
			// Example allowed IP ranges - replace with your actual IP ranges
			jsii.String("203.0.113.0/24"),  // Example office IP range
			jsii.String("198.51.100.0/24"), // Example VPN IP range
		},
	})

	app.Synth()
}
