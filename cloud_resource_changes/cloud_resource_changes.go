package cloud_resource_changes

import (
	"github.com/deepfence/cloud-scanner/cloud_resource_changes/cloud_resource_changes_aws"
	"github.com/deepfence/cloud-scanner/cloud_resource_changes/cloud_resources_changes_azure"
	"github.com/deepfence/cloud-scanner/cloud_resource_changes/cloud_resources_changes_gcp"
	"github.com/deepfence/cloud-scanner/util"
)

type CloudResourceChanges interface {
	Initialize() (bool, error)
	GetResourceTypesToRefresh() (map[string][]string, error)
}

func NewCloudResourceChanges(config util.Config) (CloudResourceChanges, error) {
	switch config.CloudProvider {
	case util.CloudProviderAWS:
		return cloud_resource_changes_aws.NewCloudResourcesChangesAWS(config)
	case util.CloudProviderGCP:
		return cloud_resources_changes_gcp.NewCloudResourcesChangesGCP(config)
	case util.CloudProviderAzure:
		return cloud_resources_changes_azure.NewCloudResourcesChangesAzure(config)
	}
	return nil, nil
}
