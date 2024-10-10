package service

import (
	"context"
	"encoding/base64"
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
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	ctl "github.com/deepfence/ThreatMapper/deepfence_utils/controls"
	"github.com/deepfence/ThreatMapper/deepfence_utils/log"
	"github.com/deepfence/cloud-scanner/internal/deepfence"
	"github.com/deepfence/cloud-scanner/query_resource"
	"github.com/deepfence/cloud-scanner/scanner"
	"github.com/deepfence/cloud-scanner/util"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/option"
)

var (
	jobCount atomic.Int32
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
	ResourceRefreshService     *query_resource.ResourceRefreshService
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
	resourceRefreshService, err := query_resource.NewResourceRefreshService(config)
	if err != nil {
		return nil, err
	}
	return &ComplianceScanService{
		scanner:                cloudComplianceScan,
		dfClient:               dfClient,
		config:                 config,
		RemainingScansMap:      sync.Map{},
		StopScanMap:            sync.Map{},
		runningScanMap:         make(map[string]struct{}),
		refreshResources:       false,
		CloudTrails:            make([]util.CloudTrailDetails, 0),
		SocketPath:             socketPath,
		organizationAccountIDs: []util.MonitoredAccount{},
		ResourceRefreshService: resourceRefreshService,
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

func (c *ComplianceScanService) fetchAWSOrganizationAccountIDs() ([]util.AccountsToRefresh, error) {
	ctx := context.Background()
	cfg, err := util.GetAWSCredentialsConfig(ctx, c.config.AccountID, c.config.CloudMetadata.Region, c.config, false)
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
			_, err = util.GetAWSCredentialsConfig(ctx, *account.Id, c.config.CloudMetadata.Region, c.config, true)
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

	if c.config.IsOrganizationDeployment {
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

	return nil, nil
}

func (c *ComplianceScanService) fetchGCPProjects() ([]util.MonitoredAccount, error) {
	log.Info().Msg("Fetching GCP projects")
	ctx := context.Background()

	var crm *cloudresourcemanager.Service
	var err error

	if c.config.GCPCredentials != "" && strings.TrimSpace(c.config.GCPCredentials) != "" {
		// Save the GCP credentials to a file
		credentialFilePath, err := saveGCPCredentialsToFile(c.config.GCPCredentials)
		if err != nil {
			log.Error().Err(err).Msg("Failed to save GCP credentials to file, falling back to default authentication")
		} else {
			log.Info().Msgf("GCP credentials saved to file at: %s", credentialFilePath)
			clientOption := option.WithCredentialsFile(credentialFilePath)
			crm, err = cloudresourcemanager.NewService(ctx, clientOption)
			if err != nil {
				log.Error().Err(err).Msg("Failed to create GCP client with provided credentials, falling back to default authentication")
			}
		}
	}

	if crm == nil {
		crm, err = cloudresourcemanager.NewService(ctx)
		if err != nil {
			log.Error().Err(err).Msg("Failed to create GCP client with default authentication")
			return nil, err
		}
	}

	projectsRequest := crm.Projects.List().PageSize(1000)
	projectsResponse, err := projectsRequest.Do()
	if err != nil {
		log.Error().Err(err).Msg("Failed to fetch GCP projects")
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

func saveGCPCredentialsToFile(credentials string) (string, error) {

	configDir := util.HomeDirectory + "/.config/gcloud/"
	credentialFilePath := configDir + "application_default_credentials.json"

	// Check if the directory exists, create it if not
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		err = os.MkdirAll(configDir, 0700)
		if err != nil {
			return "", fmt.Errorf("failed to create directory: %w", err)
		}
	}

	credBytes, err := base64.StdEncoding.DecodeString(credentials)
	if err != nil {
		return "", fmt.Errorf("failed to decode GCP credentials: %w", err)
	}

	err = os.WriteFile(credentialFilePath, credBytes, 0600)
	if err != nil {
		return "", fmt.Errorf("failed to write credentials to file: %w", err)
	}

	return credentialFilePath, nil
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

	unixListener, err := c.createUnixSocket()
	if err != nil {
		return err
	}

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
			projects, err := c.fetchGCPOrganizationProjects()
			if err != nil || len(projects) == 0 {
				if err != nil {
					log.Error().Msg(err.Error())
				}

				fetchGCPOrganizationAccounts := func() error {
					var fetchErr error
					refreshTicker := time.NewTicker(2 * time.Minute)
					defer refreshTicker.Stop()
					stopTicker := time.NewTicker(10 * time.Minute)
					defer stopTicker.Stop()
					for {
						select {
						case <-refreshTicker.C:
							projects, fetchErr = c.fetchGCPOrganizationProjects()
							if fetchErr != nil {
								log.Error().Msg(fetchErr.Error())
							} else if len(projects) > 0 {
								return nil
							}
						case <-stopTicker.C:
							return fetchErr
						}
					}
				}
				err = fetchGCPOrganizationAccounts()
				if err != nil {
					return err
				}
			}
		} else if !c.config.IsOrganizationDeployment {
			if c.config.GCPCredentials != "" && strings.TrimSpace(c.config.GCPCredentials) != "" {
				saveGCPCredentialsToFile(c.config.GCPCredentials)
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

	// Registration should be done first before starting other services
	err = c.dfClient.RegisterCloudAccount(c.GetOrganizationAccounts(), true)
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
					registerErr = c.dfClient.RegisterCloudAccount(c.GetOrganizationAccounts(), true)
					if registerErr != nil {
						log.Error().Msgf("Error in initial registration of cloud account: %s", err.Error())
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
			log.Error().Msgf("Error in initial registration of cloud account: %s", err.Error())
			return err
		}
	}

	go c.loopRegister()

	if c.config.IsOrganizationDeployment {
		go c.refreshOrganizationAccountIDs()
	}

	go c.listenForScans(unixListener)

	c.ResourceRefreshService.Initialize()

	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)
	<-done
	return nil
}

func processAzureCredentials(c *ComplianceScanService) {
	steampipeConfigFile := "connection \"azure_all\" {\n  type = \"aggregator\" \n plugin      = \"" + util.SteampipeAzurePluginVersion + "\"\n  connections = [\"azure_*\"] \n} \n"
	if c.config.IsOrganizationDeployment {
		for _, accountID := range c.GetOrganizationAccountIDs() {
			steampipeConfigFile += "\nconnection \"azure_" + strings.Replace(accountID, "-", "", -1) + "\" {\n  plugin = \"" + util.SteampipeAzurePluginVersion + "\"\n " +
				"  subscription_id = \"" + accountID + "\"\n" +
				"  tenant_id = \"" + c.config.OrganizationID + "\"\n" +
				"  client_id = \"" + os.Getenv("AZURE_CLIENT_ID") + "\"\n" +
				"  client_secret = \"" + os.Getenv("AZURE_CLIENT_SECRET") + "\"\n" +
				"  ignore_error_codes = [\"AccessDenied\", \"AccessDeniedException\", \"NotAuthorized\", \"UnauthorizedOperation\", \"AuthorizationError\"]\n}\n"
		}
	} else {
		steampipeConfigFile += "\nconnection \"azure_" + strings.Replace(c.config.AccountID, "-", "", -1) + "\" {\n  plugin = \"" + util.SteampipeAzurePluginVersion + "\"\n " +
			"  subscription_id = \"" + c.config.AccountID + "\"\n" +
			"  tenant_id = \"" + c.config.OrganizationID + "\"\n" +
			"  client_id = \"" + os.Getenv("AZURE_CLIENT_ID") + "\"\n" +
			"  client_secret = \"" + os.Getenv("AZURE_CLIENT_SECRET") + "\"\n" +
			"  ignore_error_codes = [\"AccessDenied\", \"AccessDeniedException\", \"NotAuthorized\", \"UnauthorizedOperation\", \"AuthorizationError\"]\n}\n"
	}
	err := saveFileOverwrite(util.SteampipeInstallDirectory+"/config/azure.spc", steampipeConfigFile)
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

	if c.config.AWSCredentialSource == "ServiceAccount" {
		awsCredentialsFile += "[default]\nrole_arn = " + os.Getenv("AWS_ROLE_ARN") + "\nweb_identity_token_file = " + os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE") + "\n"
	}

	steampipeConfigFile = "connection \"aws_all\" {\n  type = \"aggregator\" \n plugin      = \"" + util.SteampipeAWSPluginVersion + "\"\n  connections = [\"aws_*\"] \n} \n"
	for _, accId := range allAccountIDs {
		if c.config.RoleName == "" {
			steampipeConfigFile += "\nconnection \"aws_" + accId + "\" {\n  plugin = \"" + util.SteampipeAWSPluginVersion + "\"\n  " + regionString + "  max_error_retry_attempts = 10\n  ignore_error_codes = [\"AccessDenied\", \"AccessDeniedException\", \"NotAuthorized\", \"UnauthorizedOperation\", \"AuthorizationError\"]\n}\n"
		} else {
			if accId == c.config.DeployedAccountID {
				steampipeConfigFile += "\nconnection \"aws_" + accId + "\" {\n  plugin = \"" + util.SteampipeAWSPluginVersion + "\"\n  " + regionString + "  max_error_retry_attempts = 10\n  ignore_error_codes = [\"AccessDenied\", \"AccessDeniedException\", \"NotAuthorized\", \"UnauthorizedOperation\", \"AuthorizationError\"]\n}\n"
			} else {
				awsCredentialsFile += "\n[profile_" + accId + "]\nrole_arn = arn:aws:iam::" + accId + ":role/" + c.config.RoleName + "\n"
				if c.config.AWSCredentialSource == "ServiceAccount" {
					awsCredentialsFile += "source_profile = default\n"
				} else {
					awsCredentialsFile += "credential_source = " + c.config.AWSCredentialSource + "\n"
				}
				steampipeConfigFile += "\nconnection \"aws_" + accId + "\" {\n  plugin = \"" + util.SteampipeAWSPluginVersion + "\"\n  profile = \"profile_" + accId + "\"\n  " + regionString + "  max_error_retry_attempts = 10\n  ignore_error_codes = [\"AccessDenied\", \"AccessDeniedException\", \"NotAuthorized\", \"UnauthorizedOperation\", \"AuthorizationError\"]\n}\n"
			}
		}
	}

	err := saveFileOverwrite(util.SteampipeInstallDirectory+"/config/aws.spc", steampipeConfigFile)
	if err != nil {
		log.Fatal().Msgf(err.Error())
	}

	if len(awsCredentialsFile) > 0 {
		os.MkdirAll(util.HomeDirectory+"/.aws", os.ModePerm)
		err = saveFileOverwrite(util.HomeDirectory+"/.aws/credentials", awsCredentialsFile)
		if err != nil {
			log.Fatal().Msgf(err.Error())
		}
	}
}

func processGcpCredentials(c *ComplianceScanService) {
	steampipeConfigFile := "connection \"gcp_all\" {\n  type = \"aggregator\" \n plugin      = \"" + util.SteampipeGCPPluginVersion + "\"\n  connections = [\"gcp_*\"] \n} \n"
	if c.config.IsOrganizationDeployment {
		for _, accountID := range c.GetOrganizationAccountIDs() {
			steampipeConfigFile += "connection \"gcp_" + strings.Replace(accountID, "-", "", -1) + "\" {\n  plugin  = \"" + util.SteampipeGCPPluginVersion + "\"\n  project = \"" + accountID + "\"\n}\n"
		}
	} else {
		steampipeConfigFile += "connection \"gcp_" + strings.Replace(c.config.AccountID, "-", "", -1) + "\" {\n  plugin  = \"" + util.SteampipeGCPPluginVersion + "\"\n  project = \"" + c.config.AccountID + "\"\n}\n"
	}
	err := saveFileOverwrite(util.SteampipeInstallDirectory+"/config/gcp.spc", steampipeConfigFile)
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
				err = c.dfClient.RegisterCloudAccount(c.GetOrganizationAccounts(), false)
				if err != nil {
					log.Error().Msgf("Error in registering cloud account: %s", err.Error())
				}

				log.Info().Msgf("Restarting the steampipe service")
				util.RestartSteampipeService()
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
			err = c.dfClient.RegisterCloudAccount(c.GetOrganizationAccounts(), false)
			if err != nil {
				log.Error().Msgf("Error in registering cloud account: %s", err.Error())
			}
		}
	}
}

func (c *ComplianceScanService) executeScans(scan ctl.CloudComplianceScanDetails) interface{} {
	log.Debug().Msgf("s.RemainingScansMap: %+v", &c.RemainingScansMap)
	log.Info().Msgf("executeScans called for account %s, scan id: %s", scan.AccountId, scan.ScanId)

	if _, ok := c.runningScanMap[scan.AccountId]; !ok {
		log.Info().Msgf("Running scan with id: %s", scan.ScanId)
		c.runningScanMap[scan.AccountId] = struct{}{}
		err := c.scanner.ScanControl(&scan)
		if err != nil {
			log.Error().Msg(err.Error())
		}
	} else {
		log.Info().Msgf("Scan already running with scanid: %s", scan.ScanId)
	}
	c.RemainingScansMap.Delete(scan.AccountId)
	delete(c.runningScanMap, scan.AccountId)
	return true
}

func (c *ComplianceScanService) runHttpServer() {
	log.Info().Msgf("Starting http server")
	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "hello world\n")
	})
	err := http.ListenAndServe(":8080", nil)
	log.Error().Msgf("Error in http.ListenAndServe: %s", err.Error())
}

func (c *ComplianceScanService) createUnixSocket() (*net.UnixListener, error) {
	err := os.Remove(*c.SocketPath)
	if err != nil {
		log.Debug().Msgf("Error in os.Remove: %s", err.Error())
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: *c.SocketPath, Net: "unix"})
	if err != nil {
		log.Error().Msgf("Error listening for scans: %s", err.Error())
		return nil, err
	}
	return l, nil
}

func (c *ComplianceScanService) listenForScans(l *net.UnixListener) {
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
	log.Trace().Msg("New client connected.")
	defer func() {
		log.Trace().Msgf("Connection closed")
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
			if _, ok := c.RemainingScansMap.Load(args.ScanDetails.AccountId); !ok {
				log.Debug().Msgf("Adding pending scan for scan id as not present earlier: %s", args.ScanDetails.ScanId)
				c.RemainingScansMap.Store(args.ScanDetails.AccountId, args.ScanDetails)
			}
			go func() {
				jobCount.Add(1)
				defer jobCount.Add(-1)
				c.executeScans(args.ScanDetails)
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
			jsonString, err := json.Marshal(scanDetails.OtherScanDetails)
			if err != nil {
				log.Error().Err(err).Msg("marshal scanDetails.OtherScanDetails failed")
				continue
			}
			var args ctl.RefreshResourcesRequest
			err = json.Unmarshal(jsonString, &args)
			if err != nil {
				log.Error().Err(err).Msg("parsing RefreshResourcesRequest failed")
				continue
			}
			log.Info().Msgf("Refreshing resources for account: %s", args.AccountID)
			go func() {
				c.ResourceRefreshService.FetchCloudAccountResources([]util.AccountsToRefresh{
					{
						AccountID: args.AccountID,
						NodeID:    args.NodeId,
					},
				}, false)
			}()
		case ctl.CloudScannerJobCount:
			count := int(jobCount.Load())
			log.Debug().Msgf("Cloud scanner job count: %d", count)
			data := strconv.Itoa(count)
			_, err = conn.Write([]byte(data))
			if err != nil {
				log.Error().Msgf("Error writing job count to unix connection: %+v", err)
			}
		case ctl.CloudScannerResourceRefreshCount:
			count := int(c.ResourceRefreshService.GetRefreshCount())
			log.Debug().Msgf("Cloud scanner refresh count: %d", count)
			data := strconv.Itoa(count)
			_, err = conn.Write([]byte(data))
			if err != nil {
				log.Error().Msgf("Error writing refresh count to unix connection: %+v", err)
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
