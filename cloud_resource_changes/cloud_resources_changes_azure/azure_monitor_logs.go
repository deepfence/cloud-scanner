package cloud_resources_changes_azure

import (
	"github.com/deepfence/cloud-scanner/util"
)

type CloudResourceChangesAzure struct {
	config util.Config
}

func NewCloudResourcesChangesAzure(config util.Config) (*CloudResourceChangesAzure, error) {
	return &CloudResourceChangesAzure{
		config: config,
	}, nil
}

func (c *CloudResourceChangesAzure) Initialize() error {
	return nil
}

func (c *CloudResourceChangesAzure) GetResourceTypesToRefresh() (map[string][]string, error) {
	return nil, nil
}
