package util

import (
	"fmt"
	"os"

	cloudmetadata "github.com/deepfence/cloud-scanner/cloud-metadata"
)

const (
	CloudProviderAWS             = "aws"
	CloudProviderGCP             = "gcp"
	CloudProviderAzure           = "azure"
	NodeTypeCloudAccount         = "cloud-node"
	CloudComplianceScanIndexName = "cloud-compliance"
	StatusAlarm                  = "alarm"
	StatusOk                     = "ok"
	StatusInfo                   = "info"
	StatusSkip                   = "skip"
	StatusError                  = "error"
)

//var (
//	ComplianceBenchmarks = map[string]map[string]string{
//		CloudProviderAWS: {
//			"cis":   "benchmark.cis_v300",
//			"gdpr":  "benchmark.gdpr",
//			"hipaa": "benchmark.hipaa_final_omnibus_security_rule_2013",
//			"pci":   "benchmark.pci_dss_v321",
//			"soc2":  "benchmark.soc_2",
//			"nist":  "benchmark.nist_800_171_rev_2",
//		},
//		CloudProviderGCP: {
//			"cis":   "benchmark.cis_v300",
//			"hipaa": "benchmark.hipaa",
//			"nist":  "benchmark.nist_800_53_rev_5",
//			"pci":   "benchmark.pci_dss_v321",
//		},
//		CloudProviderAzure: {
//			"cis":   "benchmark.cis_v210",
//			"hipaa": "benchmark.hipaa_hitrust_v92",
//			"nist":  "benchmark.nist_sp_800_171_rev_2",
//			"pci":   "benchmark.pci_dss_v321",
//		},
//	}
//)

const (
	DeploymentModeKubernetes = "kubernetes"
	DeploymentModeDocker     = "docker"
)

type Config struct {
	ManagementConsoleUrl     string   `envconfig:"MGMT_CONSOLE_URL" validate:"required" json:"management_console_url"`
	ManagementConsolePort    string   `envconfig:"MGMT_CONSOLE_PORT" default:"443" json:"management_console_port"`
	DeepfenceKey             string   `envconfig:"DEEPFENCE_KEY" validate:"required" json:"-"`
	CloudProvider            string   `envconfig:"CLOUD_PROVIDER" json:"cloud_provider"`
	CloudRegion              string   `envconfig:"CLOUD_REGION" json:"cloud_region"`
	AccountID                string   `envconfig:"CLOUD_ACCOUNT_ID" json:"account_id"`
	DeployedAccountID        string   `envconfig:"DEPLOYED_ACCOUNT_ID" json:"deployed_account_id"`
	AccountName              string   `envconfig:"CLOUD_ACCOUNT_NAME" json:"account_name"`
	OrganizationID           string   `envconfig:"CLOUD_ORGANIZATION_ID" json:"organization_id"`
	IsOrganizationDeployment bool     `envconfig:"ORGANIZATION_DEPLOYMENT" default:"false" json:"is_organization_deployment"`
	RoleName                 string   `envconfig:"ROLE_NAME" json:"role_name"`
	AWSCredentialSource      string   `envconfig:"AWS_CREDENTIAL_SOURCE" json:"aws_credential_source"`
	CloudAuditLogsIDs        []string `envconfig:"CLOUD_AUDIT_LOG_IDS" json:"cloud_audit_logs_ids"`
	HttpServerRequired       bool     `envconfig:"HTTP_SERVER_REQUIRED" default:"false" json:"http_server_required"`
	SuccessSignalUrl         string   `envconfig:"SUCCESS_SIGNAL_URL" json:"success_signal_url"`
	LogLevel                 string   `envconfig:"DF_LOG_LEVEL" default:"info" json:"log_level"`
	ScanInactiveThreshold    int      `envconfig:"SCAN_INACTIVE_THRESHOLD" default:"21600" json:"scan_inactive_threshold"`
	CloudScannerPolicy       string   `envconfig:"CLOUD_SCANNER_POLICY" json:"cloud_scanner_policy"`
	DeploymentMode           string   `envconfig:"DEPLOYMENT_MODE" json:"deployment_mode"`

	CloudMetadata                cloudmetadata.CloudMetadata `ignored:"true" json:"cloud_metadata"`
	NodeID                       string                      `ignored:"true" json:"-"`
	Version                      string                      `ignored:"true" json:"version"`
	DatabasePersistenceSupported bool                        `ignored:"true" json:"database_persistence_supported"`
	InstallationID               string                      `ignored:"true" json:"installation_id"`
}

type MonitoredAccount struct {
	AccountID   string `json:"account_id"`
	AccountName string `json:"account_name"`
	NodeID      string `json:"node_id"`
}

type ComplianceDoc struct {
	Timestamp           string `json:"@timestamp"`
	Count               int    `json:"count,omitempty"`
	Reason              string `json:"reason"`
	Resource            string `json:"resource"`
	Status              string `json:"status"`
	Region              string `json:"region"`
	AccountID           string `json:"account_id"`
	Group               string `json:"group"`
	Service             string `json:"service"`
	Title               string `json:"title"`
	ComplianceCheckType string `json:"compliance_check_type"`
	CloudProvider       string `json:"cloud_provider"`
	NodeName            string `json:"node_name"`
	NodeID              string `json:"connected_node_id"`
	ScanID              string `json:"scan_id"`
	Type                string `json:"type"`
	ControlID           string `json:"control_id"`
	Description         string `json:"description"`
	Severity            string `json:"severity"`
}

type ComplianceSummary struct {
	Total                int     `json:"total"`
	Alarm                int     `json:"alarm"`
	Ok                   int     `json:"ok"`
	Info                 int     `json:"info"`
	Skip                 int     `json:"skip"`
	Error                int     `json:"error"`
	CompliancePercentage float32 `json:"compliance_percentage"`
}

type ComplianceTags struct {
	Benchmark string `json:"benchmark"`
	Category  string `json:"category"`
	Plugin    string `json:"plugin"`
	Service   string `json:"service"`
	Type      string `json:"type"`
}

type ComplianceControlResult struct {
	Reason     string `json:"reason"`
	Resource   string `json:"resource"`
	Status     string `json:"status"`
	Dimensions []struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	} `json:"dimensions"`
}

type ComplianceControl struct {
	Results     []ComplianceControlResult `json:"results"`
	ControlID   string                    `json:"control_id"`
	Description string                    `json:"description"`
	Severity    string                    `json:"severity"`
	Tags        ComplianceTags            `json:"tags"`
	Title       string                    `json:"title"`
}

type ComplianceGroup struct {
	GroupID        string         `json:"group_id"`
	Title          string         `json:"title"`
	Description    string         `json:"description"`
	Tags           ComplianceTags `json:"tags"`
	ComplianceType string         `json:"compliance_type"`
	Summary        struct {
		Status ComplianceSummary `json:"status"`
	} `json:"summary"`
	Groups   []ComplianceGroup   `json:"groups"`
	Controls []ComplianceControl `json:"controls"`
}

type CloudTrailDetails struct {
	AccountId string `json:"account_id"`
	TrailName string `json:"trail_name"`
}

type AccountsToRefresh struct {
	AccountID     string
	NodeID        string
	ResourceTypes []string
}

type RefreshMetadata struct {
	InProgressResourceType string `json:"in_progress"`
	CompletedResourceTypes int    `json:"completed"`
	TotalResourceTypes     int    `json:"total"`
}

var (
	HomeDirectory             string
	InstallDirectory          string
	SteampipeInstallDirectory string

	SteampipeAWSPluginVersion     = fmt.Sprintf("aws@%s", os.Getenv("STEAMPIPE_AWS_PLUGIN_VERSION"))
	SteampipeGCPPluginVersion     = fmt.Sprintf("gcp@%s", os.Getenv("STEAMPIPE_GCP_PLUGIN_VERSION"))
	SteampipeAzurePluginVersion   = fmt.Sprintf("azure@%s", os.Getenv("STEAMPIPE_AZURE_PLUGIN_VERSION"))
	SteampipeAzureADPluginVersion = fmt.Sprintf("azuread@%s", os.Getenv("STEAMPIPE_AZURE_AD_PLUGIN_VERSION"))
)

func init() {
	HomeDirectory = os.Getenv("HOME_DIR")
	if HomeDirectory == "" {
		HomeDirectory = "/home/deepfence"
	}

	InstallDirectory = os.Getenv("DF_INSTALL_DIR")
	if InstallDirectory == "" {
		InstallDirectory = "/home/deepfence"
	}

	SteampipeInstallDirectory = os.Getenv("STEAMPIPE_INSTALL_DIR")
	if SteampipeInstallDirectory == "" {
		SteampipeInstallDirectory = "/home/deepfence/.steampipe"
	}
}
