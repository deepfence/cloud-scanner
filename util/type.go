package util

import cloud_metadata "github.com/deepfence/cloud-scanner/cloud-metadata"

const (
	CloudProviderAWS             = "aws"
	CloudProviderGCP             = "gcp"
	CloudProviderAzure           = "azure"
	ModeCli                      = "cli"
	ModeService                  = "service"
	JsonOutput                   = "json"
	TableOutput                  = "table"
	TextOutput                   = "text"
	NodeTypeCloudProvider        = "cloud_provider"
	NodeTypeCloudAccount         = "cloud-node"
	charset                      = "abcdefghijklmnopqrstuvwxyz" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	CloudComplianceScanIndexName = "cloud-compliance"
	StatusAlarm                  = "alarm"
	StatusOk                     = "ok"
	StatusInfo                   = "info"
	StatusSkip                   = "skip"
	StatusError                  = "error"
)

var (
	ComplianceBenchmarks = map[string]map[string]string{
		CloudProviderAWS: {
			"cis":   "benchmark.cis_v200",
			"gdpr":  "benchmark.gdpr",
			"hipaa": "benchmark.hipaa_final_omnibus_security_rule_2013",
			"pci":   "benchmark.pci_dss_v321",
			"soc2":  "benchmark.soc_2",
			"nist":  "benchmark.nist_800_171_rev_2",
		},
		CloudProviderGCP: {
			"cis": "benchmark.cis_v200",
		},
		CloudProviderAzure: {
			"cis":   "benchmark.cis_v200",
			"hipaa": "benchmark.hipaa_hitrust_v92",
			"nist":  "benchmark.nist_sp_800_53_rev_5",
			"pci":   "benchmark.pci_dss_v321",
		},
	}
)

type Config struct {
	Mode                     string                       `json:"mode,omitempty"`
	Output                   string                       `json:"output,omitempty"`
	FileOutput               string                       `json:"-"`
	Quiet                    bool                         `json:"quiet,omitempty"`
	ManagementConsoleUrl     string                       `json:"management_console_url,omitempty"`
	ManagementConsolePort    string                       `json:"management_console_port,omitempty"`
	DeepfenceKey             string                       `json:"deepfence_key,omitempty"`
	ComplianceCheckTypes     []string                     `json:"compliance_check_types,omitempty"`
	ComplianceBenchmark      string                       `json:"compliance_benchmark,omitempty"`
	CloudProvider            string                       `json:"cloud_provider,omitempty"`
	ScanId                   string                       `json:"scan_id,omitempty"`
	NodeId                   string                       `json:"node_id,omitempty"`
	HostId                   string                       `json:"host_id,omitempty"`
	NodeName                 string                       `json:"node_name,omitempty"`
	CloudMetadata            cloud_metadata.CloudMetadata `json:"cloud_metadata,omitempty"`
	MultipleAccountIds       []string                     `json:"multiple_account_ids,omitempty"`
	OrgAccountId             string                       `json:"org_account_id,omitempty"`
	IsOrganizationDeployment bool                         `json:"is_organization_deployment,omitempty"`
	RolePrefix               string                       `json:"role_prefix,omitempty"`
	TableToRefresh           []string                     `json:"table_to_refresh,omitempty"`
	CloudAuditLogsIDs        []string                     `json:"cloud_audit_logs_ids,omitempty"`
	InactiveThreshold        int
	HttpServerRequired       bool
	Version                  string
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

type ScansResponse struct {
	Data PendingItems `json:"data"`
}

type PendingScanMap map[string]PendingScan

type PendingItems struct {
	Scans       PendingScanMap      `json:"scans"`
	CloudTrails []CloudTrailDetails `json:"cloudtrail_trails"`
	Refresh     string              `json:"refresh"`
}

type CloudTrailDetails struct {
	AccountId string `json:"account_id"`
	TrailName string `json:"trail_name"`
}

type Benchmark struct {
	Id             string   `json:"id"`
	ComplianceType string   `json:"compliance_type"`
	Controls       []string `json:"controls"`
}

type PendingScan struct {
	ScanId        string      `json:"scan_id"`
	AccountId     string      `json:"account_id"`
	ScanTypes     []string    `json:"scan_types"`
	Benchmarks    []Benchmark `json:"benchmarks"`
	StopRequested bool        `json:"stop_requested"`
}
