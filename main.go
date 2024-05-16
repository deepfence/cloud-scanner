package main

import (
	"encoding/json"
	"flag"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/deepfence/ThreatMapper/deepfence_utils/log"
	"github.com/deepfence/cloud-scanner/internal/deepfence"

	"github.com/deepfence/cloud-scanner/service"
	"github.com/deepfence/cloud-scanner/util"
)

var (
	CloudScannerSocket    = "/tmp/cloud-scanner.sock"
	output                = flag.String("output", util.TextOutput, "Output format: json, table or text")
	benchmark             = flag.String("benchmark", "all", "Benchmarks: cis, gdpr, hipaa, pci, soc2, nist")
	quiet                 = flag.Bool("quiet", false, "Don't display any output in stdout")
	socketPath            = flag.String("socket-path", CloudScannerSocket, "Path to socket")
	managementConsoleUrl  = flag.String("mgmt-console-url", "", "Deepfence Management Console URL")
	managementConsolePort = flag.Int("mgmt-console-port", 443, "Deepfence Management Console Port")
	deepfenceKey          = flag.String("deepfence-key", "", "Deepfence key for auth")
	httpServerRequired    = flag.Bool("http-server-required", false, "HTTP Service required")
	debug                 = flag.String("debug", "false", "set log level to debug")
	multipleAccountIds    = flag.String("multiple-acc-ids", "", "List of comma-separated account ids to monitor")
	orgAccountId          = flag.String("org-acc-id", "", "Account id of parent organization account")
	rolePrefix            = flag.String("role-prefix", "deepfence-cloud-scanner", "Prefix for role to be assumed in monitored accounts")
	successSignalUrl      = flag.String("success-signal-url", "", "URL to send notification for successful deployment of ECS Task")
	cloudAuditLogIDs      = flag.String("cloud-audit-log-ids", "", "Comma separated IDs of CloudTrail/Azure Monitor Logs/Cloud Audit Logs to enable refreshing cloud resources every hour")
	commaSplitRegex       = regexp.MustCompile(`\s*,\s*`)
	verbosity             = flag.String("verbose", "info", "log level")
	inactiveThreshold     = flag.Int("inactive-threshold", 3600, "Threshold for Inactive scan in seconds")
)

var Version string

func init() {
	CloudScannerSocket = os.Getenv("DF_INSTALL_DIR") + CloudScannerSocket
}

func runServices(config util.Config, socketPath *string) {
	s, err := json.MarshalIndent(config, "", "\t")
	if err == nil {
		log.Info().Msgf("Using config: %s", string(s))
	}
	svc, err := service.NewComplianceScanService(config, socketPath)
	if err != nil {
		log.Error().Msgf("Error: %v", err)
		return
	}
	log.Info().Msgf("Registering with Deepfence management console")
	err = svc.RunRegisterServices()
	if err != nil {
		log.Error().Msgf("Error: %v", err)
	}
}

func main() {
	log.Info().Msgf("Starting cloud scanner, version: %s", Version)
	flag.Parse()

	enableDebug := os.Getenv("DF_ENABLE_DEBUG") != ""
	if enableDebug {
		verbosity = debug
	}
	log.Initialize(*verbosity)

	if *successSignalUrl == "" {
		*successSignalUrl = os.Getenv("SUCCESS_SIGNAL_URL")
	}

	if *successSignalUrl != "" {
		deepfence.SendSuccessfulDeploymentSignal(*successSignalUrl)
	}

	var cloudAuditLogsIDs []string
	if *cloudAuditLogIDs == "" {
		*cloudAuditLogIDs = os.Getenv("CLOUD_AUDIT_LOG_IDS")
	}

	if *cloudAuditLogIDs != "" {
		cloudAuditLogsIDs = strings.Split(*cloudAuditLogIDs, ",")
	}

	if *rolePrefix == "" {
		*rolePrefix = os.Getenv("ROLE_PREFIX")
	}

	if !*httpServerRequired {
		temp := os.Getenv("HTTP_SERVER_REQUIRED")
		if temp == "true" {
			*httpServerRequired = true
		}
	}

	inactiveThresholdStr := os.Getenv("INACTIVE_THRESHOLD")
	if inactiveThresholdStr != "" {
		i, err := strconv.Atoi(inactiveThresholdStr)
		if err == nil {
			*inactiveThreshold = i
		} else {
			log.Warn().Msgf("Invalid INACTIVE_THRESHOLD, defaulting to: %d", *inactiveThreshold)
		}
	}

	config := util.Config{
		Output:                *output,
		Quiet:                 *quiet,
		ManagementConsoleUrl:  strings.TrimPrefix(*managementConsoleUrl, "https://"),
		ManagementConsolePort: strconv.Itoa(*managementConsolePort),
		DeepfenceKey:          *deepfenceKey,
		HttpServerRequired:    *httpServerRequired,
		RolePrefix:            *rolePrefix,
		CloudAuditLogsIDs:     cloudAuditLogsIDs,
		InactiveThreshold:     *inactiveThreshold,
		Version:               Version,
	}

	log.Info().Msgf("Env variables are:\n%s", strings.Join(os.Environ(), ","))

	if multipleAccountIds == nil || len(*multipleAccountIds) == 0 {
		*multipleAccountIds = os.Getenv("DF_MULTIPLE_ACC_ID")
		*orgAccountId = os.Getenv("DF_ORG_ACC_ID")
	}
	config.HostId = os.Getenv("DF_HOST_ID")
	if len(*multipleAccountIds) != 0 {
		if *orgAccountId == "" {
			log.Error().Msg("Error: Organization Account ID is mandatory for organization accounts setup")
			return
		}
		config.MultipleAccountIds = commaSplitRegex.Split(*multipleAccountIds, -1)
		config.OrgAccountId = *orgAccountId
		config.IsOrganizationDeployment = true
	}
	config.ComplianceBenchmark = *benchmark
	if len(config.ComplianceBenchmark) == 0 {
		config.ComplianceBenchmark = "all"
	}

	runServices(config, socketPath)
}
