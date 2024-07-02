package service

import (
	"sync"
	"sync/atomic"

	"github.com/deepfence/ThreatMapper/deepfence_utils/log"
	"github.com/deepfence/cloud-scanner/query_resource"
	"github.com/deepfence/cloud-scanner/util"
)

type ResourceRefreshLock struct {
	resourceRefreshCount atomic.Int32
	mutex                sync.Mutex
}

func NewResourceRefreshLock() *ResourceRefreshLock {
	return &ResourceRefreshLock{}
}

func (r *ResourceRefreshLock) Lock() {
	r.resourceRefreshCount.Add(1)
	log.Debug().Msgf("Resource refresh count: %d", r.resourceRefreshCount.Load())
	r.mutex.Lock()
}

func (r *ResourceRefreshLock) Unlock() {
	r.resourceRefreshCount.Add(-1)
	log.Debug().Msgf("Resource refresh count: %d", r.resourceRefreshCount.Load())
	r.mutex.Unlock()
}

func (r *ResourceRefreshLock) GetRefreshCount() int32 {
	return r.resourceRefreshCount.Load()
}

// FetchCloudResources Fetch cloud resources from all accounts
func (c *ComplianceScanService) FetchCloudResources() {
	log.Info().Msg("Querying cloud resources")

	var accountsToRefresh []util.AccountsToRefresh
	if c.config.IsOrganizationDeployment {
		for _, monitoredAccount := range c.GetOrganizationAccounts() {
			accountsToRefresh = append(accountsToRefresh, util.AccountsToRefresh{
				AccountID: monitoredAccount.AccountID,
				NodeID:    monitoredAccount.NodeID,
			})
		}
	} else {
		accountsToRefresh = []util.AccountsToRefresh{
			{
				AccountID: c.config.AccountID,
				NodeID:    c.config.NodeID,
			},
		}
	}
	c.FetchCloudAccountResources(accountsToRefresh, true)
	log.Info().Msg("Querying cloud resources complete")
}

// FetchCloudAccountResources Fetch cloud resources from selected accounts and resource types
func (c *ComplianceScanService) FetchCloudAccountResources(accountsToRefresh []util.AccountsToRefresh, completeRefresh bool) {
	errorsCollected := query_resource.QueryAndRegisterResources(c.config, accountsToRefresh, completeRefresh)
	if len(errorsCollected) > 0 {
		log.Error().Msgf("Error in sending resources, errors: %+v", errorsCollected)
	}
}
