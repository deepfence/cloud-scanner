package service

import (
	"encoding/json"
	"errors"
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

	"github.com/Jeffail/tunny"
	ctl "github.com/deepfence/ThreatMapper/deepfence_utils/controls"
	cloud_metadata "github.com/deepfence/cloud-scanner/cloud-metadata"
	"github.com/deepfence/cloud-scanner/cloud_resource_changes"
	"github.com/deepfence/cloud-scanner/internal/deepfence"
	"github.com/deepfence/cloud-scanner/query_resource"
	"github.com/deepfence/cloud-scanner/scanner"
	"github.com/deepfence/cloud-scanner/util"
	"github.com/rs/zerolog/log"
)

const DefaultScanConcurrency = 1

var (
	scanConcurrency int
	scanPool        *tunny.Pool
	HomeDirectory   string
	wg              sync.WaitGroup
	jobCount        atomic.Int32
)

type CloudResources struct {
	sync.RWMutex
}

type ScanToExecute struct {
	ScanId      string
	ScanService *ComplianceScanService
}

type ComplianceScanService struct {
	scanner              *scanner.CloudComplianceScan
	dfClient             *deepfence.Client
	config               util.Config
	accountID            []string
	RemainingScansMap    sync.Map
	StopScanMap          sync.Map
	runningScanMap       map[string]struct{}
	refreshResources     bool
	cloudResources       *CloudResources
	CloudTrails          []util.CloudTrailDetails
	SocketPath           *string
	CloudResourceChanges cloud_resource_changes.CloudResourceChanges
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
	config.Quiet = true
	cloudComplianceScan, err := scanner.NewCloudComplianceScan(config)
	if err != nil {
		log.Error().Msgf("scanner.NewCloudComplianceScan error: %s", err.Error())
		return nil, err
	}
	config = cloudComplianceScan.GetConfig()
	dfClient, err := deepfence.NewClient(config)
	if err != nil {
		log.Error().Msgf("deepfence.NewClient(config) error: %s", err.Error())
		return nil, err
	}
	if config.CloudMetadata.ID == "" {
		log.Error().Msgf("empty cloud metadata id from deepfence.NewClient(config)")
		return nil, errors.New("could not fetch cloud account/subscription id")
	}
	var remainingScansMap, stopScanMap sync.Map
	runningScansMap := make(map[string]struct{})
	cloudTrails := make([]util.CloudTrailDetails, 0)
	cloudResourceChanges, err := cloud_resource_changes.NewCloudResourceChanges(config)
	if err != nil {
		return nil, err
	}
	return &ComplianceScanService{
		scanner:              cloudComplianceScan,
		dfClient:             dfClient,
		config:               config,
		RemainingScansMap:    remainingScansMap,
		StopScanMap:          stopScanMap,
		runningScanMap:       runningScansMap,
		refreshResources:     false,
		cloudResources:       &CloudResources{},
		CloudTrails:          cloudTrails,
		SocketPath:           socketPath,
		CloudResourceChanges: cloudResourceChanges,
	}, err
}

func (c *ComplianceScanService) RunRegisterServices() error {
	if c.config.HttpServerRequired {
		go c.runHttpServer()
	}
	if c.config.CloudProvider == cloud_metadata.CloudProviderAWS {
		processAwsCredentials(c)
	} else if c.config.CloudProvider == cloud_metadata.CloudProviderGCP {
		err := processGcpCredentials(c)
		if err != nil {
			log.Fatal().Msgf("%+v", err)
		}
	} else if c.config.CloudProvider == cloud_metadata.CloudProviderAzure {
		processAzureCredentials()
	}

	log.Info().Msgf("Restarting the steampipe service")
	util.RestartSteampipeService()

	log.Info().Msgf("CloudResourceChanges Initialization started")
	err := c.CloudResourceChanges.Initialize()
	if err != nil {
		log.Warn().Msgf("%+v", err)
	}
	log.Info().Msgf("CloudResourceChanges Initialization completed")

	go c.loopRegister()
	go c.queryAndRegisterCloudResources()

	go c.listenForScans()
	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)
	<-done
	return nil
}

func processAzureCredentials() {
	err := os.Remove(HomeDirectory + "/.steampipe/config/azure.spc")
	if err != nil {
		log.Warn().Msgf(err.Error())
	}
	f2, err := os.OpenFile(HomeDirectory+"/.steampipe/config/azure.spc", os.O_WRONLY|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal().Msgf(err.Error())
	}
	if _, err = f2.Write([]byte("\nconnection \"azure\" {\n  plugin = \"azure\"\n " +
		"  subscription_id = \"" + os.Getenv("AZURE_SUBSCRIPTION_ID") + "\"\n" +
		"  tenant_id = \"" + os.Getenv("AZURE_TENANT_ID") + "\"\n" +
		"  client_id = \"" + os.Getenv("AZURE_CLIENT_ID") + "\"\n" +
		"  client_secret = \"" + os.Getenv("AZURE_CLIENT_SECRET") + "\"\n" +
		"  ignore_error_codes = [\"AccessDenied\", \"AccessDeniedException\", \"NotAuthorized\", \"UnauthorizedOperation\", \"AuthorizationError\"]\n}\n")); err != nil {
		f2.Close()
		log.Fatal().Msgf(err.Error())
	}
	if err = f2.Close(); err != nil {
		log.Fatal().Msgf(err.Error())
	}
}

func processAwsCredentials(c *ComplianceScanService) {
	regionString := "regions = [\"*\"]\n"
	if len(c.config.MultipleAccountIds) > 0 {
		os.MkdirAll(HomeDirectory+"/.aws", os.ModePerm)
		aggr := "connection \"aws_all\" {\n  type = \"aggregator\" \n plugin      = \"aws\" \n  connections = [\"aws_*\"] \n} \n"
		spcFile, err := os.OpenFile(HomeDirectory+"/.steampipe/config/aws.spc",
			os.O_APPEND|os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
		defer spcFile.Close()
		if err != nil {
			log.Fatal().Msgf(err.Error())
		}
		if _, err = spcFile.Write([]byte(aggr)); err != nil {
			spcFile.Close()
			log.Fatal().Msgf(err.Error())
		}
		for _, accId := range c.config.MultipleAccountIds {
			f1, err := os.OpenFile(HomeDirectory+"/.aws/credentials", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				log.Fatal().Msgf(err.Error())
			}
			if _, err = f1.Write([]byte("\n[profile_" + accId + "]\nrole_arn = arn:aws:iam::" + accId + ":role/" + c.config.RolePrefix + "-mem-acc-read-only-access\ncredential_source = EcsContainer\n")); err != nil {
				f1.Close()
				log.Fatal().Msgf(err.Error())
			}
			if err = f1.Close(); err != nil {
				log.Fatal().Msgf(err.Error())
			}
			if _, err = spcFile.Write([]byte("\nconnection \"aws_" + accId + "\" {\n  plugin = \"aws\"\n  profile = \"profile_" + accId + "\"\n  " + regionString + "  max_error_retry_attempts = 10\n  ignore_error_codes = [\"AccessDenied\", \"AccessDeniedException\", \"NotAuthorized\", \"UnauthorizedOperation\", \"AuthorizationError\"]\n}\n")); err != nil {
				spcFile.Close()
				log.Fatal().Msgf(err.Error())
			}
		}
		if err = spcFile.Close(); err != nil {
			log.Fatal().Msgf(err.Error())
		}
	} else {
		err := os.Remove(HomeDirectory + "/.steampipe/config/aws.spc")
		if err != nil {
			log.Warn().Msgf(err.Error())
		}
		f2, err := os.OpenFile(HomeDirectory+"/.steampipe/config/aws.spc", os.O_WRONLY|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal().Msgf(err.Error())
		}
		if _, err = f2.Write([]byte("\nconnection \"aws\" {\n  plugin = \"aws\"\n  " + regionString + "  max_error_retry_attempts = 10\n  ignore_error_codes = [\"AccessDenied\", \"AccessDeniedException\", \"NotAuthorized\", \"UnauthorizedOperation\", \"AuthorizationError\"]\n}\n")); err != nil {
			f2.Close()
			log.Fatal().Msgf(err.Error())
		}
		if err = f2.Close(); err != nil {
			log.Fatal().Msgf(err.Error())
		}
	}
}

func processGcpCredentials(c *ComplianceScanService) error {
	if len(c.config.MultipleAccountIds) > 0 {
		gcpSpcFileName := HomeDirectory + "/.steampipe/config/gcp.spc"
		aggr := "connection \"gcp_all\" {\n  type = \"aggregator\" \n plugin      = \"gcp\" \n  connections = [\"gcp_*\"] \n} \n"
		spcFile, err := os.OpenFile(gcpSpcFileName,
			os.O_APPEND|os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
		if err != nil {
			log.Error().Msgf("Failed to open gcpSpcFileName:%s, error:%s", gcpSpcFileName, err.Error())
			return err
		}
		if _, err = spcFile.Write([]byte(aggr)); err != nil {
			spcFile.Close()
			return err
		}
		for _, accId := range c.config.MultipleAccountIds {
			accString := "connection \"gcp_" + strings.Replace(accId, "-", "", -1) + "\" {\n  plugin  = \"gcp\"\n  project = \"" + accId + "\"\n}\n"
			if _, err = spcFile.Write([]byte(accString)); err != nil {
				spcFile.Close()
				return err
			}
		}
		if err = spcFile.Close(); err != nil {
			return err
		}
	}
	return nil
}

func (c *ComplianceScanService) loopRegister() {
	err := c.dfClient.RegisterCloudAccount(c.config.NodeId, c.config.CloudProvider,
		c.config.CloudMetadata.ID, c.config.MultipleAccountIds,
		&c.config.OrgAccountId, c.config.Version)
	if err != nil {
		log.Error().Msgf("Error in inital registering cloud account: %s", err.Error())
	}

	ticker1 := time.NewTicker(1 * time.Minute)
	for {
		select {
		case <-ticker1.C:
			err := c.dfClient.RegisterCloudAccount(c.config.NodeId, c.config.CloudProvider,
				c.config.CloudMetadata.ID, c.config.MultipleAccountIds,
				&c.config.OrgAccountId, c.config.Version)
			if err != nil {
				log.Error().Msgf("Error in registering cloud account: %s", err.Error())
			}
		}
	}
}

func (c *ComplianceScanService) queryAndRegisterCloudResources() {
	log.Info().Msg("Querying Resources")
	c.cloudResources.Lock()
	defer c.cloudResources.Unlock()

	errorsCollected := query_resource.QueryAndRegisterResources(c.config, c.dfClient)
	if len(errorsCollected) > 0 {
		log.Error().Msgf("Error in sending resources, errors: %+v", errorsCollected)
	}
}

func (c *ComplianceScanService) refreshResourcesFromTrail() {
	cloudResourceTypesToRefresh, _ := c.CloudResourceChanges.GetResourceTypesToRefresh()
	if len(cloudResourceTypesToRefresh) == 0 {
		return
	}

	c.cloudResources.Lock()
	errorsCollected := query_resource.QueryAndUpdateResources(c.config, c.dfClient, cloudResourceTypesToRefresh)
	if len(errorsCollected) > 0 {
		log.Error().Msgf("Error in sending resources  %+v", errorsCollected)
	}
	c.cloudResources.Unlock()
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
		log.Info().Msgf("Error in os.Remove: %s", err.Error())
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: *c.SocketPath, Net: "unix"})
	if err != nil {
		log.Error().Msgf("Error listening for scans: %s", err.Error())
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
	log.Info().Msg("New client connected.")
	defer func() {
		log.Info().Msgf("Connection closed")
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
			jsonString, _ := json.Marshal(scanDetails.OtherScanDetails)
			var args ctl.StartCloudComplianceScanRequest
			json.Unmarshal(jsonString, &args)
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
			jobCount.Add(1)
			go func() {
				scanPool.Process(s)
				jobCount.Add(-1)
			}()
		case ctl.StopCloudComplianceScan:
			jsonString, _ := json.Marshal(scanDetails.OtherScanDetails)
			var args ctl.StopCloudComplianceScanRequest
			json.Unmarshal(jsonString, &args)
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
			go c.queryAndRegisterCloudResources()
		case ctl.CloudScannerJobCount:
			count := int(jobCount.Load())
			log.Debug().Msgf("Cloud scanner job count: %d", jobCount)
			data := []byte(string(strconv.Itoa(count)))
			_, err = conn.Write(data)
			if err != nil {
				log.Error().Msgf("Error writing job count to unix connection: %+v", err)
			}
		default:
			if _, ok := scanDetails.OtherScanDetails["GetCloudNodeID"]; !ok {
				log.Warn().Msgf("Default case, key GetCloudNodeID not found")
				continue
			}

			log.Info().Msgf("Received GetCloudNodeID request")
			nodeName := c.config.NodeId
			_, err = conn.Write([]byte(nodeName))
			if err != nil {
				log.Error().Msgf("Error writing CloudNodeID to unix connection: %+v", err)
			}
		}
	}
}
