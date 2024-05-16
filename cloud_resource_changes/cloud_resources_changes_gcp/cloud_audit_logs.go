package cloud_resources_changes_gcp

import (
	"github.com/deepfence/cloud-scanner/util"
)

type CloudResourceChangesGCP struct {
	config util.Config
}

func NewCloudResourcesChangesGCP(config util.Config) (*CloudResourceChangesGCP, error) {
	return &CloudResourceChangesGCP{
		config: config,
	}, nil
}

func (c *CloudResourceChangesGCP) Initialize() error {
	return nil
}

func (c *CloudResourceChangesGCP) GetResourceTypesToRefresh() (map[string][]string, error) {
	return nil, nil
}
