package cloud_resource_changes_aws

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/deepfence/ThreatMapper/deepfence_utils/log"
	"github.com/deepfence/cloud-scanner/util"
)

func GetSupportedAwsRegions() []string {
	return []string{"af-south-1", "ap-east-1", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3", "ap-south-1",
		"ap-southeast-1", "ap-southeast-2", "ap-southeast-3", "ca-central-1", "eu-central-1", "eu-north-1",
		"eu-south-1", "eu-west-1", "eu-west-2", "eu-west-3", "me-central-1", "me-south-1", "sa-east-1", "us-east-1",
		"us-east-2", "us-gov-east-1", "us-gov-west-1", "us-west-1", "us-west-2"}
}

type SteampipeQueryResponse struct {
	Rows []json.RawMessage `json:"rows"`
}

func ConvertRows[T any](rows []json.RawMessage) ([]T, error) {
	// Create an empty slice of the target type T
	var result []T

	// Iterate over each row
	for _, rawRow := range rows {
		// Create an instance of the target type T
		var elem T

		// Unmarshal the raw row into the target struct
		if err := json.Unmarshal(rawRow, &elem); err != nil {
			return nil, fmt.Errorf("failed to unmarshal row: %w", err)
		}

		// Append the unmarshaled element to the result slice
		result = append(result, elem)
	}

	return result, nil
}

func getCloudTrailTrails(config util.Config) []CloudTrailTrail {
	var query string
	var isOrganizationTrail string
	if config.IsOrganizationDeployment {
		isOrganizationTrail = "and is_organization_trail = true"
	}
	if len(config.CloudAuditLogsIDs) == 0 {
		query = "steampipe query --output json \"select * from aws_" + config.AccountID + ".aws_cloudtrail_trail where is_multi_region_trail = true " + isOrganizationTrail + "\""
	} else {
		query = "steampipe query --output json \"select * from aws_all.aws_cloudtrail_trail where is_multi_region_trail = true " + isOrganizationTrail + " and arn in ('" + strings.Join(config.CloudAuditLogsIDs, "', '") + "')\""
	}

	log.Debug().Msgf("(getCloudTrailTrails) Query: %s", query)

	cmd := exec.Command("bash", "-c", query)
	stdOut, stdErr := cmd.CombinedOutput()
	var trailList []CloudTrailTrail
	if stdErr != nil {
		log.Error().Msgf("Error while obtaining cloudtrail details: %v", stdErr)
		log.Error().Msgf(string(stdOut))
		return trailList
	}

	var steampipeQueryResponse SteampipeQueryResponse
	if err := json.Unmarshal(stdOut, &steampipeQueryResponse); err != nil {
		log.Error().Msgf("Error unmarshaling steampipe query details: %v \n Steampipe Output: %s",
			err, string(stdOut))
		return trailList
	}

	trailList, err := ConvertRows[CloudTrailTrail](steampipeQueryResponse.Rows)

	log.Debug().Msgf("trailList: %v", trailList)

	if err != nil {
		log.Error().Msgf("Error converting steampipe query details to CloudTrialTrail: %v \n Steampipe Output: %s",
			err, string(stdOut))
		return trailList
	}

	selectedARNs := make(map[string]bool)
	var selectedTrailList []CloudTrailTrail

	if len(config.CloudAuditLogsIDs) > 0 {
		for _, trail := range trailList {
			if selectedARNs[trail.Arn] {
				continue
			}
			selectedTrailList = append(selectedTrailList, trail)
			selectedARNs[trail.Arn] = true
		}
		if len(selectedTrailList) == 0 {
			log.Error().Msg("cloudtrail trail arn provided does not exist or is not a multi-region trail")
		}
		return selectedTrailList
	}

	for _, trail := range trailList {
		if strings.HasPrefix(trail.S3BucketName, "aws-controltower-logs") {
			continue
		}
		if len(trail.EventSelectors) > 0 {
			skip := true
			for _, eventSelector := range trail.EventSelectors {
				if eventSelector.IncludeManagementEvents && (eventSelector.ReadWriteType == "All" || eventSelector.ReadWriteType == "WriteOnly") {
					skip = false
					break
				}
			}
			if skip {
				continue
			}
			if selectedARNs[trail.Arn] {
				continue
			}
			selectedTrailList = append(selectedTrailList, trail)
			selectedARNs[trail.Arn] = true
		} else if len(trail.AdvancedEventSelectors) > 0 {
			skip := true
			for _, eventSelector := range trail.AdvancedEventSelectors {
				isManagementTrail := false
				isWrite := true
				for _, fieldSelector := range eventSelector.FieldSelectors {
					switch fieldSelector.Field {
					case "eventCategory":
						if util.InSlice("Management", fieldSelector.Equals) {
							isManagementTrail = true
						}
					case "readOnly":
						if util.InSlice("true", fieldSelector.Equals) {
							isWrite = false
						}
					}
				}
				if isManagementTrail && isWrite {
					skip = false
					break
				}
			}
			if skip {
				continue
			}
			if selectedARNs[trail.Arn] {
				continue
			}
			selectedTrailList = append(selectedTrailList, trail)
			selectedARNs[trail.Arn] = true
		} else {
			continue
		}
	}
	if len(selectedTrailList) == 0 {
		log.Warn().Msgf("Cloudtrail not configured")
		return trailList
	}
	return []CloudTrailTrail{selectedTrailList[0]}
}
