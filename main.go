package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/deepfence/ThreatMapper/deepfence_utils/log"
	cloudmetadata "github.com/deepfence/cloud-scanner/cloud-metadata"
	"github.com/deepfence/cloud-scanner/internal/deepfence"
	"github.com/deepfence/cloud-scanner/service"
	"github.com/deepfence/cloud-scanner/util"
	"github.com/kelseyhightower/envconfig"
)

var (
	socketPath = flag.String("socket-path", "", "Path to socket")

	steampipeAWSPluginVersion     = fmt.Sprintf("aws@%s", os.Getenv("STEAMPIPE_AWS_PLUGIN_VERSION"))
	steampipeGCPPluginVersion     = fmt.Sprintf("gcp@%s", os.Getenv("STEAMPIPE_GCP_PLUGIN_VERSION"))
	steampipeAzurePluginVersion   = fmt.Sprintf("azure@%s", os.Getenv("STEAMPIPE_AZURE_PLUGIN_VERSION"))
	steampipeAzureADPluginVersion = fmt.Sprintf("azuread@%s", os.Getenv("STEAMPIPE_AZURE_AD_PLUGIN_VERSION"))
)

var Version string

func runServices(config util.Config, socketPath *string) {
	svc, err := service.NewComplianceScanService(config, socketPath)
	if err != nil {
		log.Error().Msgf("Error: %v", err)
		return
	}
	log.Info().Msgf("Registering with Deepfence management console")
	err = svc.RunRegisterServices()
	if err != nil {
		log.Fatal().Msgf("Error: %v", err)
	}
}

func main() {
	log.Info().Msgf("Starting cloud scanner, version: %s", Version)
	flag.Parse()

	if *socketPath == "" {
		log.Fatal().Msgf("socket-path is not set")
	}

	var config util.Config
	err := envconfig.Process("", &config)
	if err != nil {
		log.Fatal().Msg(err.Error())
	}

	err = log.Initialize(config.LogLevel)
	if err != nil {
		log.Fatal().Msg(err.Error())
	}

	if config.CloudProvider != "" && config.AccountID != "" && config.CloudRegion != "" {
		config.CloudMetadata = cloudmetadata.CloudMetadata{
			CloudProvider: config.CloudProvider,
			ID:            config.AccountID,
			Region:        config.CloudRegion,
		}
	} else {
		config.CloudMetadata, err = util.GetCloudMetadata()
		if err != nil {
			log.Fatal().Msg(err.Error())
		}
		config.CloudProvider = config.CloudMetadata.CloudProvider
		if config.CloudMetadata.ID != "" {
			config.AccountID = config.CloudMetadata.ID
		}
		if config.CloudMetadata.Region != "" {
			config.CloudRegion = config.CloudMetadata.Region
		}
	}

	if config.AccountID == "" {
		log.Fatal().Msgf("unable to retrieve account ID from metadata service, please set env CLOUD_ACCOUNT_ID")
	}

	if config.CloudProvider != util.CloudProviderAWS && config.CloudProvider != util.CloudProviderGCP && config.CloudProvider != util.CloudProviderAzure {
		log.Fatal().Msgf("invalid CLOUD_PROVIDER - should be one of aws, azure, gcp")
	}

	if config.SuccessSignalUrl != "" {
		deepfence.SendSuccessfulDeploymentSignal(config.SuccessSignalUrl)
	}

	if config.IsOrganizationDeployment {
		if config.OrganizationID == "" {
			log.Fatal().Msgf("CLOUD_ORGANIZATION_ID is required in organization deployment")
		}
	}

	switch config.CloudProvider {
	case util.CloudProviderAWS:
		if config.AWSCredentialSource != "EcsContainer" && config.AWSCredentialSource != "Ec2InstanceMetadata" && config.AWSCredentialSource != "Environment" {
			log.Fatal().Msgf("invalid AWS_CREDENTIAL_SOURCE - should be one of EcsContainer, Ec2InstanceMetadata, Environment")
		}
		if config.IsOrganizationDeployment && config.RoleName == "" {
			log.Fatal().Msgf("ROLE_NAME is required in aws installation")
		}
	default:
		config.AWSCredentialSource = ""
	}

	config.NodeID = util.GetNodeID(config.CloudProvider, config.AccountID)
	config.Version = Version

	configJson, err := json.MarshalIndent(config, "", "\t")
	if err == nil {
		log.Info().Msgf("Using config: %s", string(configJson))
	}

	// Disable plugins of other clouds
	var uninstallPlugins []string
	var deletePluginConfigs []string
	switch config.CloudProvider {
	case util.CloudProviderAWS:
		uninstallPlugins = []string{steampipeGCPPluginVersion, steampipeAzurePluginVersion, steampipeAzureADPluginVersion}
		deletePluginConfigs = []string{util.HomeDirectory + "/.steampipe/config/gcp.spc", util.HomeDirectory + "/.steampipe/config/azure.spc", util.HomeDirectory + "/.steampipe/config/azuread.spc"}
	case util.CloudProviderGCP:
		uninstallPlugins = []string{steampipeAWSPluginVersion, steampipeAzurePluginVersion, steampipeAzureADPluginVersion}
		deletePluginConfigs = []string{util.HomeDirectory + "/.steampipe/config/aws.spc", util.HomeDirectory + "/.steampipe/config/azure.spc", util.HomeDirectory + "/.steampipe/config/azuread.spc"}
	case util.CloudProviderAzure:
		uninstallPlugins = []string{steampipeAWSPluginVersion, steampipeGCPPluginVersion}
		deletePluginConfigs = []string{util.HomeDirectory + "/.steampipe/config/aws.spc", util.HomeDirectory + "/.steampipe/config/gcp.spc"}
	}
	for _, configFile := range deletePluginConfigs {
		os.Remove(configFile)
	}
	for _, plugin := range uninstallPlugins {
		stdOut, stdErr := exec.Command("bash", "-c", fmt.Sprintf("steampipe plugin uninstall %s", plugin)).CombinedOutput()
		if stdErr != nil {
			log.Error().Msgf(string(stdOut))
			log.Error().Msgf(stdErr.Error())
		}
		time.Sleep(1 * time.Second)
	}

	runServices(config, socketPath)
}
