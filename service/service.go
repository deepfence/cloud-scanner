package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/Jeffail/tunny"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ctl "github.com/deepfence/ThreatMapper/deepfence_utils/controls"
	"github.com/deepfence/ThreatMapper/deepfence_utils/log"
	"github.com/deepfence/cloud-scanner/cloud_resource_changes"
	"github.com/deepfence/cloud-scanner/internal/deepfence"
	"github.com/deepfence/cloud-scanner/scanner"
	"github.com/deepfence/cloud-scanner/util"
	"google.golang.org/api/cloudresourcemanager/v1"
)

const DefaultScanConcurrency = 1

var (
	scanConcurrency int
	scanPool        *tunny.Pool
	HomeDirectory   string
	jobCount        atomic.Int32
)

type ScanToExecute struct {
	ScanId      string
	ScanService *ComplianceScanService
}

type ComplianceScanService struct {
	scanner                    *scanner.CloudComplianceScan
	dfClient                   *deepfence.Client
	config                     util.Config
	RemainingScansMap          sync.Map
	StopScanMap                sync.Map
	runningScanMap             map[string]struct{}
	refreshResources           bool
	CloudTrails                []util.CloudTrailDetails
	SocketPath                 *string
	organizationAccountIDs     []util.MonitoredAccount
	organizationAccountIDsLock sync.RWMutex
	CloudResourceChanges       cloud_resource_changes.CloudResourceChanges
}

func init() {
	var err error
	scanConcurrency, err = strconv.Atoi(os.Getenv("SCAN_CONCURRENCY"))
	if err != nil {
		scanConcurrency = DefaultScanConcurrency
	}
	scanPool = tunny.NewFunc(scanConcurrency, executeScans)
	HomeDirectory = os.Getenv("HOME_DIR")
	if HomeDirectory == "" {
		HomeDirectory = "/home/deepfence"
	}
}

func NewComplianceScanService(config util.Config, socketPath *string) (*ComplianceScanService, error) {
	log.Debug().Msgf("NewComplianceScanService")
	cloudComplianceScan, err := scanner.NewCloudComplianceScan(config)
	if err != nil {
		log.Error().Msgf("scanner.NewCloudComplianceScan error: %s", err.Error())
		return nil, err
	}
	dfClient, err := deepfence.NewClient(config)
	if err != nil {
		log.Error().Msgf("deepfence.NewClient(config) error: %s", err.Error())
		return nil, err
	}
	var remainingScansMap, stopScanMap sync.Map
	runningScansMap := make(map[string]struct{})
	cloudTrails := make([]util.CloudTrailDetails, 0)
	cloudResourceChanges, err := cloud_resource_changes.NewCloudResourceChanges(config)
	if err != nil {
		return nil, err
	}
	return &ComplianceScanService{
		scanner:                cloudComplianceScan,
		dfClient:               dfClient,
		config:                 config,
		RemainingScansMap:      remainingScansMap,
		StopScanMap:            stopScanMap,
		runningScanMap:         runningScansMap,
		refreshResources:       false,
		CloudTrails:            cloudTrails,
		SocketPath:             socketPath,
		organizationAccountIDs: []util.MonitoredAccount{},
		CloudResourceChanges:   cloudResourceChanges,
	}, err
}

func (c *ComplianceScanService) GetOrganizationAccountIDs() []string {
	c.organizationAccountIDsLock.RLock()
	defer c.organizationAccountIDsLock.RUnlock()
	organizationAccountIDs := make([]string, len(c.organizationAccountIDs))
	for i, accountID := range c.organizationAccountIDs {
		organizationAccountIDs[i] = accountID.AccountID
	}
	return organizationAccountIDs
}

func (c *ComplianceScanService) GetOrganizationAccounts() []util.MonitoredAccount {
	c.organizationAccountIDsLock.RLock()
	defer c.organizationAccountIDsLock.RUnlock()
	return c.organizationAccountIDs
}

func getAWSCredentialsConfig(ctx context.Context, accountID, region, roleName string, verifyCredential bool) (aws.Config, error) {
	var cfg aws.Config
	var err error
	cfg, err = config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		log.Error().Msg(err.Error())
		return cfg, err
	}

	roleARN := fmt.Sprintf("arn:aws:iam::%s:role/%s", accountID, roleName)
	cfg.Credentials = aws.NewCredentialsCache(
		stscreds.NewAssumeRoleProvider(
			sts.NewFromConfig(cfg), roleARN,
			func(o *stscreds.AssumeRoleOptions) { o.TokenProvider = stscreds.StdinTokenProvider },
		),
	)
	if verifyCredential {
		iamClient := iam.NewFromConfig(cfg)
		_, err = iamClient.GetRole(ctx, &iam.GetRoleInput{RoleName: aws.String(roleName)})
		if err != nil {
			log.Error().Msg(err.Error())
			return cfg, err
		}
	}
	return cfg, err
}

func (c *ComplianceScanService) fetchAWSOrganizationAccountIDs() ([]util.AccountsToRefresh, error) {
	ctx := context.Background()
	cfg, err := getAWSCredentialsConfig(ctx, c.config.AccountID, c.config.CloudMetadata.Region, c.config.RoleName, false)
	if err != nil {
		return nil, err
	}

	organizationAccountIDs := []util.MonitoredAccount{}
	organizationsClient := organizations.NewFromConfig(cfg)
	var nextToken *string
	for {
		accounts, err := organizationsClient.ListAccounts(ctx, &organizations.ListAccountsInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, err
		}
		if len(accounts.Accounts) == 0 {
			break
		}
		for _, account := range accounts.Accounts {
			log.Debug().Msgf("Account ID %s - checking if IAM role exists for cloud scanner", *account.Id)
			_, err = getAWSCredentialsConfig(ctx, *account.Id, c.config.CloudMetadata.Region, c.config.RoleName, true)
			if err != nil {
				log.Debug().Msgf("Account ID %s is ignored, no IAM role found", *account.Id)
				continue
			}
			log.Debug().Msgf("Account ID %s - IAM role found", *account.Id)
			organizationAccountIDs = append(organizationAccountIDs, util.MonitoredAccount{
				AccountID:   *account.Id,
				AccountName: *account.Name,
				NodeID:      util.GetNodeID(c.config.CloudProvider, *account.Id),
			})
		}
		if accounts.NextToken == nil {
			break
		}
		nextToken = accounts.NextToken
	}

	c.organizationAccountIDsLock.Lock()

	accountsMap := make(map[string]struct{}, len(c.organizationAccountIDs))
	for _, account := range c.organizationAccountIDs {
		accountsMap[account.AccountID] = struct{}{}
	}

	var newAccounts []util.AccountsToRefresh
	for _, account := range organizationAccountIDs {
		if _, ok := accountsMap[account.AccountID]; !ok {
			newAccounts = append(newAccounts, util.AccountsToRefresh{
				AccountID: account.AccountID,
				NodeID:    account.NodeID,
			})
		}
	}

	c.organizationAccountIDs = organizationAccountIDs
	c.organizationAccountIDsLock.Unlock()

	return newAccounts, nil
}

func (c *ComplianceScanService) fetchGCPOrganizationProjects() ([]util.AccountsToRefresh, error) {
	projects, err := c.fetchGCPProjects()
	if err != nil {
		return nil, err
	}

	c.organizationAccountIDsLock.Lock()

	accountsMap := make(map[string]struct{}, len(c.organizationAccountIDs))
	for _, account := range c.organizationAccountIDs {
		accountsMap[account.AccountID] = struct{}{}
	}

	var newAccounts []util.AccountsToRefresh
	for _, account := range projects {
		if _, ok := accountsMap[account.AccountID]; !ok {
			newAccounts = append(newAccounts, util.AccountsToRefresh{
				AccountID: account.AccountID,
				NodeID:    account.NodeID,
			})
		}
	}

	c.organizationAccountIDs = projects
	c.organizationAccountIDsLock.Unlock()

	return newAccounts, nil
}

func (c *ComplianceScanService) fetchGCPProjects() ([]util.MonitoredAccount, error) {
	ctx := context.Background()
	crm, err := cloudresourcemanager.NewService(ctx)
	if err != nil {
		log.Error().Err(err).Msg("failed to fetch GCP projects")
		return nil, err
	}
	projectsRequest := crm.Projects.List().PageSize(1000)
	projectsResponse, err := projectsRequest.Do()
	if err != nil {
		log.Error().Err(err).Msg("failed to fetch GCP projects")
		return nil, err
	}

	organizationAccountIDs := make([]util.MonitoredAccount, len(projectsResponse.Projects))
	for i, project := range projectsResponse.Projects {
		organizationAccountIDs[i] = util.MonitoredAccount{
			AccountID:   project.ProjectId,
			AccountName: project.Name,
			NodeID:      util.GetNodeID(c.config.CloudProvider, project.ProjectId),
		}
	}
	return organizationAccountIDs, nil
}

func (c *ComplianceScanService) fetchAzureTenantSubscriptions() ([]util.MonitoredAccount, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, err
	}
	subscriptionClient, err := armsubscriptions.NewClient(cred, nil)
	if err != nil {
		return nil, err
	}

	organizationAccountIDs := []util.MonitoredAccount{}
	ctx := context.Background()
	listPager := subscriptionClient.NewListPager(nil)
	for listPager.More() {
		page, err := listPager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, val := range page.Value {
			organizationAccountIDs = append(organizationAccountIDs, util.MonitoredAccount{
				AccountID:   *val.SubscriptionID,
				AccountName: *val.DisplayName,
				NodeID:      util.GetNodeID(c.config.CloudProvider, *val.SubscriptionID),
			})
		}
	}
	return organizationAccountIDs, nil
}

func (c *ComplianceScanService) fetchAzureSubscriptions() ([]util.AccountsToRefresh, error) {
	organizationAccountIDs, err := c.fetchAzureTenantSubscriptions()
	if err != nil {
		log.Error().Err(err).Msg("failed to fetch Azure subscriptions")
		return nil, err
	}

	c.organizationAccountIDsLock.Lock()

	accountsMap := make(map[string]struct{}, len(c.organizationAccountIDs))
	for _, account := range c.organizationAccountIDs {
		accountsMap[account.AccountID] = struct{}{}
	}

	var newAccounts []util.AccountsToRefresh
	for _, account := range organizationAccountIDs {
		if _, ok := accountsMap[account.AccountID]; !ok {
			newAccounts = append(newAccounts, util.AccountsToRefresh{
				AccountID: account.AccountID,
				NodeID:    account.NodeID,
			})
		}
	}

	c.organizationAccountIDs = organizationAccountIDs
	c.organizationAccountIDsLock.Unlock()

	return newAccounts, nil
}

func (c *ComplianceScanService) RunRegisterServices() error {
	if c.config.HttpServerRequired {
		go c.runHttpServer()
	}
	var err error
	switch c.config.CloudProvider {
	case util.CloudProviderAWS:
		if c.config.IsOrganizationDeployment {
			_, err = c.fetchAWSOrganizationAccountIDs()
			if err != nil {
				log.Error().Msg(err.Error())

				fetchAWSOrganizationAccounts := func() error {
					var fetchErr error
					refreshTicker := time.NewTicker(2 * time.Minute)
					defer refreshTicker.Stop()
					stopTicker := time.NewTicker(10 * time.Minute)
					defer stopTicker.Stop()
					for {
						select {
						case <-refreshTicker.C:
							_, fetchErr = c.fetchAWSOrganizationAccountIDs()
							if fetchErr != nil {
								log.Error().Msg(fetchErr.Error())
							} else {
								return nil
							}
						case <-stopTicker.C:
							return fetchErr
						}
					}
				}
				err = fetchAWSOrganizationAccounts()
				if err != nil {
					return err
				}
			}
		}
		processAwsCredentials(c)
	case util.CloudProviderGCP:
		if c.config.IsOrganizationDeployment {
			_, err = c.fetchGCPOrganizationProjects()
			if err != nil {
				log.Warn().Msg(err.Error())
			}
		} else {
			projects, err := c.fetchGCPProjects()
			if err != nil {
				log.Warn().Msg(err.Error())
			} else {
				if len(projects) == 1 {
					c.config.AccountName = projects[0].AccountName
				}
			}
		}
		processGcpCredentials(c)
	case util.CloudProviderAzure:
		if c.config.IsOrganizationDeployment {
			_, err = c.fetchAzureSubscriptions()
			if err != nil {
				log.Warn().Msg(err.Error())
			}
		}
		processAzureCredentials(c)
	}

	log.Info().Msgf("Restarting the steampipe service")
	util.RestartSteampipeService()

	log.Info().Msgf("CloudResourceChanges Initialization started")
	err = c.CloudResourceChanges.Initialize()
	if err != nil {
		log.Warn().Msgf("%+v", err)
	}
	log.Info().Msgf("CloudResourceChanges Initialization completed")

	// Registration should be done first before starting other services
	err = c.dfClient.RegisterCloudAccount(c.GetOrganizationAccounts())
	if err != nil {
		log.Error().Msgf("Error in inital registering cloud account: %s", err.Error())

		registerCloudScanner := func() error {
			var registerErr error
			refreshTicker := time.NewTicker(30 * time.Second)
			defer refreshTicker.Stop()
			stopTicker := time.NewTicker(5 * time.Minute)
			defer stopTicker.Stop()
			for {
				select {
				case <-refreshTicker.C:
					registerErr = c.dfClient.RegisterCloudAccount(c.GetOrganizationAccounts())
					if registerErr != nil {
						log.Error().Msgf("Error in inital registering cloud account: %s", err.Error())
					} else {
						return nil
					}
				case <-stopTicker.C:
					return registerErr
				}
			}
		}
		err = registerCloudScanner()
		if err != nil {
			log.Error().Msgf("Error in inital registering cloud account: %s", err.Error())
			return err
		}
	}

	go c.loopRegister()

	if c.config.IsOrganizationDeployment {
		go c.refreshOrganizationAccountIDs()
	}

	go c.queryAndRegisterCloudResourcesPeriodically()
	go c.refreshResourcesFromTrailPeriodically()

	go c.listenForScans()
	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)
	<-done
	return nil
}

func processAzureCredentials(c *ComplianceScanService) {
	steampipeConfigFile := "connection \"azure_all\" {\n  type = \"aggregator\" \n plugin      = \"azure\" \n  connections = [\"azure_*\"] \n} \n"
	if c.config.IsOrganizationDeployment {
		for _, accountID := range c.GetOrganizationAccountIDs() {
			steampipeConfigFile += "\nconnection \"azure_" + strings.Replace(accountID, "-", "", -1) + "\" {\n  plugin = \"azure\"\n " +
				"  subscription_id = \"" + accountID + "\"\n" +
				"  tenant_id = \"" + c.config.OrganizationID + "\"\n" +
				"  client_id = \"" + os.Getenv("AZURE_CLIENT_ID") + "\"\n" +
				"  client_secret = \"" + os.Getenv("AZURE_CLIENT_SECRET") + "\"\n" +
				"  ignore_error_codes = [\"AccessDenied\", \"AccessDeniedException\", \"NotAuthorized\", \"UnauthorizedOperation\", \"AuthorizationError\"]\n}\n"
		}
	} else {
		steampipeConfigFile += "\nconnection \"azure_" + strings.Replace(c.config.AccountID, "-", "", -1) + "\" {\n  plugin = \"azure\"\n " +
			"  subscription_id = \"" + c.config.AccountID + "\"\n" +
			"  tenant_id = \"" + c.config.OrganizationID + "\"\n" +
			"  client_id = \"" + os.Getenv("AZURE_CLIENT_ID") + "\"\n" +
			"  client_secret = \"" + os.Getenv("AZURE_CLIENT_SECRET") + "\"\n" +
			"  ignore_error_codes = [\"AccessDenied\", \"AccessDeniedException\", \"NotAuthorized\", \"UnauthorizedOperation\", \"AuthorizationError\"]\n}\n"
	}
	err := saveFileOverwrite(HomeDirectory+"/.steampipe/config/azure.spc", steampipeConfigFile)
	if err != nil {
		log.Fatal().Msgf(err.Error())
	}
}

func processAwsCredentials(c *ComplianceScanService) {
	regionString := "regions = [\"*\"]\n"

	allAccountIDs := []string{}
	if c.config.IsOrganizationDeployment {
		allAccountIDs = c.GetOrganizationAccountIDs()
		if !util.InSlice(c.config.AccountID, allAccountIDs) {
			allAccountIDs = append(allAccountIDs, c.config.AccountID)
		}
	} else {
		allAccountIDs = []string{c.config.AccountID}
	}

	var steampipeConfigFile string
	var awsCredentialsFile string

	steampipeConfigFile = "connection \"aws_all\" {\n  type = \"aggregator\" \n plugin      = \"aws\" \n  connections = [\"aws_*\"] \n} \n"
	for _, accId := range allAccountIDs {
		if c.config.RoleName == "" {
			steampipeConfigFile += "\nconnection \"aws_" + accId + "\" {\n  plugin = \"aws\"\n  " + regionString + "  max_error_retry_attempts = 10\n  ignore_error_codes = [\"AccessDenied\", \"AccessDeniedException\", \"NotAuthorized\", \"UnauthorizedOperation\", \"AuthorizationError\"]\n}\n"
		} else {
			awsCredentialsFile += "\n[profile_" + accId + "]\nrole_arn = arn:aws:iam::" + accId + ":role/" + c.config.RoleName + "\ncredential_source = " + c.config.AWSCredentialSource + "\n"
			steampipeConfigFile += "\nconnection \"aws_" + accId + "\" {\n  plugin = \"aws\"\n  profile = \"profile_" + accId + "\"\n  " + regionString + "  max_error_retry_attempts = 10\n  ignore_error_codes = [\"AccessDenied\", \"AccessDeniedException\", \"NotAuthorized\", \"UnauthorizedOperation\", \"AuthorizationError\"]\n}\n"
		}
	}

	err := saveFileOverwrite(HomeDirectory+"/.steampipe/config/aws.spc", steampipeConfigFile)
	if err != nil {
		log.Fatal().Msgf(err.Error())
	}

	if len(awsCredentialsFile) > 0 {
		os.MkdirAll(HomeDirectory+"/.aws", os.ModePerm)
		err = saveFileOverwrite(HomeDirectory+"/.aws/credentials", awsCredentialsFile)
		if err != nil {
			log.Fatal().Msgf(err.Error())
		}
	}
}

func processGcpCredentials(c *ComplianceScanService) {
	steampipeConfigFile := "connection \"gcp_all\" {\n  type = \"aggregator\" \n plugin      = \"gcp\" \n  connections = [\"gcp_*\"] \n} \n"
	if c.config.IsOrganizationDeployment {
		for _, accountID := range c.GetOrganizationAccountIDs() {
			steampipeConfigFile += "connection \"gcp_" + strings.Replace(accountID, "-", "", -1) + "\" {\n  plugin  = \"gcp\"\n  project = \"" + accountID + "\"\n}\n"
		}
	} else {
		steampipeConfigFile += "connection \"gcp_" + strings.Replace(c.config.AccountID, "-", "", -1) + "\" {\n  plugin  = \"gcp\"\n  project = \"" + c.config.AccountID + "\"\n}\n"
	}
	err := saveFileOverwrite(HomeDirectory+"/.steampipe/config/gcp.spc", steampipeConfigFile)
	if err != nil {
		log.Fatal().Msgf(err.Error())
	}
}

func saveFileOverwrite(fileName string, fileContents string) error {
	f, err := os.OpenFile(fileName, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	if _, err = f.WriteString(fileContents); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return nil
}

func (c *ComplianceScanService) refreshOrganizationAccountIDs() {
	ticker := time.NewTicker(15 * time.Minute)
	for {
		select {
		case <-ticker.C:
			var newAccounts []util.AccountsToRefresh
			var err error
			if c.config.CloudProvider == util.CloudProviderAWS {
				if c.config.IsOrganizationDeployment {
					newAccounts, err = c.fetchAWSOrganizationAccountIDs()
					if err != nil {
						log.Warn().Msg(err.Error())
					}
				}
				processAwsCredentials(c)
			} else if c.config.CloudProvider == util.CloudProviderGCP {
				if c.config.IsOrganizationDeployment {
					newAccounts, err = c.fetchGCPOrganizationProjects()
					if err != nil {
						log.Warn().Msg(err.Error())
					}
				}
				processGcpCredentials(c)
			} else if c.config.CloudProvider == util.CloudProviderAzure {
				if c.config.IsOrganizationDeployment {
					newAccounts, err = c.fetchAzureSubscriptions()
					if err != nil {
						log.Warn().Msg(err.Error())
					}
				}
				processAzureCredentials(c)
			}

			if len(newAccounts) > 0 {
				err = c.dfClient.RegisterCloudAccount(c.GetOrganizationAccounts())
				if err != nil {
					log.Error().Msgf("Error in registering cloud account: %s", err.Error())
				}
				c.FetchCloudAccountResources(newAccounts, false)
			}
		}
	}
}

func (c *ComplianceScanService) loopRegister() {
	ticker := time.NewTicker(1 * time.Minute)
	var err error
	for {
		select {
		case <-ticker.C:
			err = c.dfClient.RegisterCloudAccount(c.GetOrganizationAccounts())
			if err != nil {
				log.Error().Msgf("Error in registering cloud account: %s", err.Error())
			}
		}
	}
}

func (c *ComplianceScanService) queryAndRegisterCloudResourcesPeriodically() {
	refreshTicker := time.NewTicker(12 * time.Hour)
	for {
		jobCount.Add(1)
		c.FetchCloudResources()
		jobCount.Add(-1)

		<-refreshTicker.C
	}
}

func (c *ComplianceScanService) refreshResourcesFromTrailPeriodically() {
	refreshTicker := time.NewTicker(1 * time.Hour)
	for {
		select {
		case <-refreshTicker.C:
			jobCount.Add(1)
			c.refreshResourcesFromTrail()
			jobCount.Add(-1)
		}
	}
}

func (c *ComplianceScanService) refreshResourcesFromTrail() {
	log.Info().Msg("Started updating cloud resources")
	cloudResourceTypesToRefresh, _ := c.CloudResourceChanges.GetResourceTypesToRefresh()
	if len(cloudResourceTypesToRefresh) == 0 {
		return
	}
	accountsToRefresh := make([]util.AccountsToRefresh, len(cloudResourceTypesToRefresh))
	index := 0
	for accountID, resourceTypes := range cloudResourceTypesToRefresh {
		accountsToRefresh[index] = util.AccountsToRefresh{
			AccountID:     accountID,
			NodeID:        util.GetNodeID(c.config.CloudProvider, accountID),
			ResourceTypes: resourceTypes,
		}
		index += 1
	}
	c.FetchCloudAccountResources(accountsToRefresh, false)
	log.Info().Msg("Updating cloud resources complete")
}

func executeScans(rInterface interface{}) interface{} {
	s, ok := rInterface.(*ScanToExecute)
	if !ok {
		log.Error().Msgf("Error processing compliance scan service")
		return false
	}
	c := s.ScanService
	log.Debug().Msgf("s.RemainingScansMap: %+v", c.RemainingScansMap)
	scanId := s.ScanId
	log.Info().Msgf("executeScans called for: %s", scanId)
	scanDetails, ok := c.RemainingScansMap.Load(scanId)
	if !ok {
		log.Error().Msgf("No scan found for scan id %s", scanId)
		return false
	}

	scan, ok := scanDetails.(ctl.CloudComplianceScanDetails)
	if !ok {
		log.Error().Msgf("Invalid scan details for scan id %s: %+v", scanId, scan)
		return false
	}

	if _, ok := c.runningScanMap[scanId]; !ok {
		log.Info().Msgf("Running scan with id: %s", scanId)
		c.runningScanMap[scanId] = struct{}{}
		err := c.scanner.ScanControl(&scan)
		if err != nil {
			log.Error().Msg(err.Error())
		}
		c.delayedRemoveFromRunningScanMap(scanId)
	} else {
		log.Info().Msgf("Scan already running with scanid: %s", scanId)
	}
	return true
}

func (c *ComplianceScanService) delayedRemoveFromRunningScanMap(scanId string) {
	// time.Sleep(5 * time.Minute)
	c.RemainingScansMap.Delete(scanId)
	delete(c.runningScanMap, scanId)
}

func (c *ComplianceScanService) runHttpServer() {
	log.Info().Msgf("Starting http server")
	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "hello world\n")
	})
	err := http.ListenAndServe(":8080", nil)
	log.Error().Msgf("Error in http.ListenAndServe: %s", err.Error())
}

func (c *ComplianceScanService) listenForScans() {
	err := os.Remove(*c.SocketPath)
	if err != nil {
		log.Debug().Msgf("Error in os.Remove: %s", err.Error())
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: *c.SocketPath, Net: "unix"})
	if err != nil {
		log.Error().Msgf("Error listening for scans: %s", err.Error())
		return
	}

	go func() {
		defer l.Close()

		log.Info().Msgf("Listening on %s ...", *c.SocketPath)

		for {
			conn, err := l.Accept()
			if err != nil {
				log.Error().Msgf("Error accepting: %v", err)
				continue
			}

			c.handleRequest(conn)
		}
	}()
}

type OtherScanDetails map[string]interface{}

type ScanDetails struct {
	Action           ctl.ActionID `json:"action"`
	OtherScanDetails `json:"args"`
}

func (c *ComplianceScanService) handleRequest(conn net.Conn) {
	log.Debug().Msg("New client connected.")
	defer func() {
		log.Debug().Msgf("Connection closed")
		conn.Close()
	}()

	d := json.NewDecoder(conn)
	for {
		if !d.More() {
			break
			//continue
		}
		var scanDetails ScanDetails
		err := d.Decode(&scanDetails)

		if err != nil {
			log.Error().Msgf("Error decoding message: %v", err)
			continue
		}

		action := scanDetails.Action
		switch action {
		case ctl.StartCloudComplianceScan:
			jsonString, err := json.Marshal(scanDetails.OtherScanDetails)
			if err != nil {
				log.Error().Err(err).Msg("marshal scanDetails.OtherScanDetails failed")
				continue
			}
			var args ctl.StartCloudComplianceScanRequest
			err = json.Unmarshal(jsonString, &args)
			if err != nil {
				log.Error().Err(err).Msg("parsing StartCloudComplianceScanRequest failed")
				continue
			}
			log.Info().Msgf("Received start scan request, scanId: %s", args.ScanDetails.ScanId)
			scanId := args.ScanDetails.ScanId
			if _, ok := c.RemainingScansMap.Load(scanId); !ok {
				log.Debug().Msgf("Adding pending scan for scan id as not present earlier: %s", scanId)
				c.RemainingScansMap.Store(scanId, args.ScanDetails)
			}
			s := &ScanToExecute{
				ScanId:      scanId,
				ScanService: c,
			}
			go func() {
				jobCount.Add(1)
				defer jobCount.Add(-1)
				scanPool.Process(s)
			}()
		case ctl.StopCloudComplianceScan:
			jsonString, err := json.Marshal(scanDetails.OtherScanDetails)
			if err != nil {
				log.Error().Err(err).Msg("marshal scanDetails.OtherScanDetails failed")
				continue
			}
			var args ctl.StopCloudComplianceScanRequest
			err = json.Unmarshal(jsonString, &args)
			if err != nil {
				log.Error().Err(err).Msg("parsing StopCloudComplianceScanRequest failed")
				continue
			}
			scanId := args.BinArgs["scan_id"]
			log.Info().Msgf("Received stop scan request, scanId: %s", scanId)
			if _, ok := c.StopScanMap.Load(scanId); !ok {
				log.Debug().Msgf("Adding pending stop scan for scan id as not present earlier: %s", scanId)
				c.StopScanMap.Store(scanId, struct{}{})
				go func() {
					err := c.scanner.StopScan(scanId)
					if err != nil {
						log.Error().Msgf("Error while stopping scan %s: %s", scanId, err.Error())
					}
					c.StopScanMap.Delete(scanId)
				}()
			}
		case ctl.RefreshResources:
			log.Info().Msgf("Received RefreshResources request")
			go func() {
				jobCount.Add(1)
				defer jobCount.Add(-1)
				// TODO: refresh for selected accounts
				c.FetchCloudResources()
			}()
		case ctl.CloudScannerJobCount:
			count := int(jobCount.Load())
			log.Debug().Msgf("Cloud scanner job count: %d", jobCount.Load())
			data := strconv.Itoa(count)
			_, err = conn.Write([]byte(data))
			if err != nil {
				log.Error().Msgf("Error writing job count to unix connection: %+v", err)
			}
		default:
			if _, ok := scanDetails.OtherScanDetails["GetCloudNodeID"]; !ok {
				log.Warn().Msgf("Default case, key GetCloudNodeID not found")
				continue
			}

			log.Info().Msgf("Received GetCloudNodeID request")
			nodeName := c.config.NodeID
			_, err = conn.Write([]byte(nodeName))
			if err != nil {
				log.Error().Msgf("Error writing CloudNodeID to unix connection: %+v", err)
			}
		}
	}
}
