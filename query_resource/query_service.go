package query_resource

import (
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/deepfence/ThreatMapper/deepfence_utils/log"
	"github.com/deepfence/ThreatMapper/deepfence_utils/utils"
	"github.com/deepfence/cloud-scanner/cloud_resource_changes"
	"github.com/deepfence/cloud-scanner/internal/deepfence"
	"github.com/deepfence/cloud-scanner/output"
	"github.com/deepfence/cloud-scanner/util"
)

type ResourceRefreshService struct {
	config                util.Config
	resourceRefreshCount  atomic.Int32
	resourceRefreshStatus sync.Map
	CloudResourceChanges  cloud_resource_changes.CloudResourceChanges
	dfClient              *deepfence.Client
	mutex                 sync.Mutex
}

func NewResourceRefreshService(config util.Config) (*ResourceRefreshService, error) {
	cloudResourceChanges, err := cloud_resource_changes.NewCloudResourceChanges(config)
	if err != nil {
		return nil, err
	}
	dfClient, err := deepfence.NewClient(config)
	if err != nil {
		log.Error().Msgf("deepfence.NewClient(config) error: %s", err.Error())
		return nil, err
	}

	return &ResourceRefreshService{
		config:                config,
		resourceRefreshCount:  atomic.Int32{},
		resourceRefreshStatus: sync.Map{},
		CloudResourceChanges:  cloudResourceChanges,
		dfClient:              dfClient,
	}, nil
}

func (r *ResourceRefreshService) Initialize() {
	log.Info().Msgf("CloudResourceChanges Initialization started")
	ok, err := r.CloudResourceChanges.Initialize()
	if err != nil {
		log.Warn().Msgf("%+v", err)
	}
	log.Info().Msgf("CloudResourceChanges Initialization completed")

	if ok {
		go r.refreshResourcesFromTrailPeriodically()
	}
}

func (r *ResourceRefreshService) Lock() {
	r.resourceRefreshCount.Add(1)
	log.Debug().Msgf("Resource refresh count: %d", r.resourceRefreshCount.Load())
	r.mutex.Lock()
}

func (r *ResourceRefreshService) Unlock() {
	r.resourceRefreshCount.Add(-1)
	log.Debug().Msgf("Resource refresh count: %d", r.resourceRefreshCount.Load())
	r.mutex.Unlock()
}

func (r *ResourceRefreshService) SetResourceRefreshStatus(account util.AccountsToRefresh, refreshStatus string, refreshMetadata util.RefreshMetadata) {
	r.resourceRefreshStatus.Store(account.AccountID, refreshStatus)

	var refreshMeta []byte
	var err error
	refreshMessage := ""
	if refreshStatus == utils.ScanStatusInProgress {
		refreshMessage = fmt.Sprintf("Refreshing %s. Progress: %d/%d resource types.",
			refreshMetadata.InProgressResourceType, refreshMetadata.CompletedResourceTypes, refreshMetadata.TotalResourceTypes)
		refreshMeta, err = json.Marshal(refreshMetadata)
		if err != nil {
			log.Error().Msg(err.Error())
		}
	}
	output.WriteCloudResourceRefreshStatus(account.NodeID, refreshStatus, refreshMessage, string(refreshMeta))
}

// SkipCloudAuditLogUpdate Weather to skip cloud audit log based resource updates
func (r *ResourceRefreshService) SkipCloudAuditLogUpdate(accountID string) bool {
	var refreshStatus any
	var ok bool
	if refreshStatus, ok = r.resourceRefreshStatus.Load(accountID); !ok {
		// Skip the resources update
		return true
	}
	refreshStatusString := refreshStatus.(string)
	if refreshStatusString == utils.ScanStatusSuccess || refreshStatusString == utils.ScanStatusFailed {
		// Proceed with the resources update
		return false
	}
	// Skip the resources update
	return true
}

func (r *ResourceRefreshService) refreshResourcesFromTrailPeriodically() {
	refreshTicker := time.NewTicker(30 * time.Minute)
	for {
		select {
		case <-refreshTicker.C:
			go func() {
				r.refreshResourcesFromTrail()
			}()
		}
	}
}

func (r *ResourceRefreshService) refreshResourcesFromTrail() {
	log.Info().Msg("Checking cloud audit logs for events")
	cloudResourceTypesToRefresh, _ := r.CloudResourceChanges.GetResourceTypesToRefresh()
	if len(cloudResourceTypesToRefresh) == 0 {
		return
	}
	var accountsToRefresh []util.AccountsToRefresh
	for accountID, resourceTypes := range cloudResourceTypesToRefresh {
		if r.SkipCloudAuditLogUpdate(accountID) {
			log.Debug().Msgf("Skipping resource refresh updation for account %s, account wide refresh already scheduled", accountID)
			continue
		}

		log.Debug().Msgf("Resource refresh updation for account %s, resource types: %v", accountID, resourceTypes)
		accountsToRefresh = append(accountsToRefresh, util.AccountsToRefresh{
			AccountID:     accountID,
			NodeID:        util.GetNodeID(r.config.CloudProvider, accountID),
			ResourceTypes: resourceTypes,
		})
	}

	r.FetchCloudAccountResources(accountsToRefresh, false)
	log.Info().Msg("Updating cloud resources from cloud audit logs complete")
}

func (r *ResourceRefreshService) GetRefreshCount() int32 {
	return r.resourceRefreshCount.Load()
}

// FetchCloudResources Fetch cloud resources from all accounts
func (r *ResourceRefreshService) FetchCloudResources(organizationAccounts []util.MonitoredAccount) {
	log.Info().Msg("Querying cloud resources")

	var accountsToRefresh []util.AccountsToRefresh
	if r.config.IsOrganizationDeployment {
		for _, monitoredAccount := range organizationAccounts {
			accountsToRefresh = append(accountsToRefresh, util.AccountsToRefresh{
				AccountID: monitoredAccount.AccountID,
				NodeID:    monitoredAccount.NodeID,
			})
		}
	} else {
		accountsToRefresh = []util.AccountsToRefresh{
			{
				AccountID: r.config.AccountID,
				NodeID:    r.config.NodeID,
			},
		}
	}
	r.FetchCloudAccountResources(accountsToRefresh, true)
	log.Info().Msg("Querying cloud resources complete")
}

// FetchCloudAccountResources Fetch cloud resources from selected accounts and resource types
func (r *ResourceRefreshService) FetchCloudAccountResources(accountsToRefresh []util.AccountsToRefresh, completeRefresh bool) {
	// Only one cloud account's resources are refreshed at a time
	r.Lock()
	defer r.Unlock()

	errorsCollected := r.QueryAndRegisterResources(accountsToRefresh, completeRefresh)
	if len(errorsCollected) > 0 {
		log.Error().Msgf("Error in sending resources, errors: %+v", errorsCollected)
	}
}
