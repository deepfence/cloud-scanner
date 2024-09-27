package query_resource

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/deepfence/ThreatMapper/deepfence_utils/log"
	"github.com/deepfence/ThreatMapper/deepfence_utils/utils"
	"github.com/deepfence/cloud-scanner/util"
	_ "github.com/lib/pq"
)

var (
	CloudResourcesFile = util.InstallDirectory + "/var/log/fenced/cloud-resources/cloud_resources.log"
)

type CloudResourceInfo struct {
	Table    string   `json:"table,omitempty"`
	Columns  []string `json:"columns,omitempty"`
	IdColumn string   `json:"id_column,omitempty"`
}

var (
	cloudProviderToResourceMap = map[string][]CloudResourceInfo{}
)

func init() {
	var awsCloudTables []CloudResourceInfo
	err := json.Unmarshal([]byte(AWSCloudTablesJson), &awsCloudTables)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	cloudProviderToResourceMap[util.CloudProviderAWS] = awsCloudTables

	var gcpCloudTables []CloudResourceInfo
	err = json.Unmarshal([]byte(GCPCloudTablesJson), &gcpCloudTables)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	cloudProviderToResourceMap[util.CloudProviderGCP] = gcpCloudTables

	var azureCloudTables []CloudResourceInfo
	err = json.Unmarshal([]byte(AzureCloudTablesJson), &azureCloudTables)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	cloudProviderToResourceMap[util.CloudProviderAzure] = azureCloudTables
}

const (
	Ec2DnsSuffix1 = ".compute.amazonaws.com"
	Ec2DnsSuffix2 = ".ec2.internal"

	postgresqlCacheConnectionString = "dbname=postgresqlcache user=postgresqlcache host=127.0.0.1 port=9193 sslmode=disable"
)

func clearPostgresqlCache() error {
	db, err := sql.Open("postgres", postgresqlCacheConnectionString)
	if err != nil {
		return err
	}
	if _, err = db.Exec(`TRUNCATE TABLE postgresqlcache`); err != nil {
		return err
	}
	return nil
}

func (r *ResourceRefreshService) QueryAndRegisterResources(accountsToRefresh []util.AccountsToRefresh, completeRefresh bool) []error {
	if completeRefresh {
		err := clearPostgresqlCache()
		if err != nil {
			log.Warn().Msgf("failed to clear postgresql cache: " + err.Error())
		}
	}

	log.Debug().Msgf("Started querying resources for %v", accountsToRefresh)

	cloudResourcesFile, err := os.OpenFile(CloudResourcesFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return []error{err}
	}
	defer cloudResourcesFile.Close()

	var refreshStatus map[string]util.RefreshMetadata
	if r.config.DatabasePersistenceSupported {
		refreshStatus, err = r.dfClient.GetCloudAccountsRefreshStatus()
		if err != nil {
			return []error{err}
		}
	}

	for _, account := range accountsToRefresh {
		if refreshMetadata, ok := refreshStatus[account.AccountID]; ok && refreshMetadata.InProgressResourceType != "" {
			r.SetResourceRefreshStatus(account, utils.ScanStatusStarting, refreshMetadata)
		} else {
			r.SetResourceRefreshStatus(account, utils.ScanStatusStarting, util.RefreshMetadata{})
		}
	}

	count := 0
	var errs = make([]error, 0)
	for _, account := range accountsToRefresh {
		log.Debug().Msgf("Started querying resources for %v", account)

		skipThisResourceType := false
		var inProgressResourceType string
		if len(account.ResourceTypes) > 0 {
			// Partial refresh from cloudtrail
			r.SetResourceRefreshStatus(account, utils.ScanStatusInProgress, util.RefreshMetadata{})
		} else {
			if refreshMetadata, ok := refreshStatus[account.AccountID]; ok && refreshMetadata.InProgressResourceType != "" {
				inProgressResourceType = refreshMetadata.InProgressResourceType
				skipThisResourceType = true
			}
		}

		totalResourceTypes := len(cloudProviderToResourceMap[r.config.CloudProvider])
		for i, cloudResourceInfo := range cloudProviderToResourceMap[r.config.CloudProvider] {
			// If ResourceTypes is empty, refresh all resource types. Otherwise, only specified ones
			if len(account.ResourceTypes) > 0 {
				if !util.InSlice(cloudResourceInfo.Table, account.ResourceTypes) {
					continue
				}
				err = clearPostgresqlCacheRows(r.config.CloudProvider + "_" + account.AccountID + "." + cloudResourceInfo.Table)
				if err != nil {
					errs = append(errs, err)
					continue
				}
			} else {
				if skipThisResourceType {
					if inProgressResourceType == cloudResourceInfo.Table {
						skipThisResourceType = false
					} else {
						continue
					}
				}
				r.SetResourceRefreshStatus(account, utils.ScanStatusInProgress, util.RefreshMetadata{
					InProgressResourceType: cloudResourceInfo.Table,
					CompletedResourceTypes: i,
					TotalResourceTypes:     totalResourceTypes,
				})
			}

			ingestedCount, err := r.queryResources(account.AccountID, cloudResourceInfo, cloudResourcesFile)
			if err != nil {
				errs = append(errs, err)
			}

			log.Debug().Msgf("Cloud resources ingested in account %s, resource type %s: %d", account.AccountID, cloudResourceInfo.Table, ingestedCount)
			count += ingestedCount
		}

		log.Debug().Msgf("Querying resources complete for %v", account)
		r.SetResourceRefreshStatus(account, utils.ScanStatusSuccess, util.RefreshMetadata{})
	}
	log.Info().Msgf("Cloud resources ingested: %d", count)
	return errs
}

func clearPostgresqlCacheRows(keyPrefix string) error {
	db, err := sql.Open("postgres", postgresqlCacheConnectionString)
	if err != nil {
		return err
	}
	if _, err = db.Exec(`DELETE FROM TABLE postgresqlcache WHERE key LIKE '` + keyPrefix + `%'`); err != nil {
		return err
	}
	return nil
}

func (r *ResourceRefreshService) queryResources(accountId string, cloudResourceInfo CloudResourceInfo, cloudResourcesFile *os.File) (int, error) {
	log.Debug().Msgf("Querying resources for %s", cloudResourceInfo.Table)

	query := "steampipe query --output json \"select \\\"" + strings.Join(cloudResourceInfo.Columns[:], "\\\" , \\\"") + "\\\" from " + r.config.CloudProvider + "_" + strings.Replace(accountId, "-", "", -1) + "." + cloudResourceInfo.Table + " \""
	var stdOut []byte
	var stdErr error
	for i := 0; i <= 3; i++ {
		stdOut, stdErr = exec.Command("bash", "-c", query).CombinedOutput()
		if stdErr != nil {
			log.Error().Msgf("Error at querying res: %v for query: %s", stdErr, query)
			log.Error().Msgf(string(stdOut))
			if strings.Contains(string(stdOut), util.ErrSteampipeDB) || strings.Contains(string(stdOut), util.ErrSteampipeInvalidClientTokenID) {
				util.RestartSteampipeService()
			} else {
				time.Sleep(util.SleepTime)
			}
			continue
		} else {
			break
		}
	}
	if stdErr != nil {
		return 0, stdErr
	}

	log.Trace().Msgf("Got stdout for %s: %s", cloudResourceInfo.Table, string(stdOut))
	var steampipeQueryResponse SteampipeQueryResponse
	if err := json.Unmarshal(stdOut, &steampipeQueryResponse); err != nil {
		log.Error().Msgf("Error: %v \n Steampipe Output: %s", err, string(stdOut))
		return 0, errors.New(string(stdOut))
	}
	log.Debug().Msgf("Got length of %d for %s", len(steampipeQueryResponse.Rows), cloudResourceInfo.Table)

	var private_dns_name string
	for _, obj := range steampipeQueryResponse.Rows {
		obj["account_id"] = util.GetNodeID(r.config.CloudProvider, accountId)
		obj["cloud_provider"] = r.config.CloudProvider
		if _, ok := obj["title"]; ok {
			obj["name"] = fmt.Sprint(obj["title"])
			delete(obj, "title")
		}
		if _, ok := obj[cloudResourceInfo.IdColumn]; ok {
			obj["arn"] = fmt.Sprintf("%v", obj[cloudResourceInfo.IdColumn])
		} else {
			obj["arn"] = ""
		}
		if _, ok := obj["id"]; !ok {
			obj["id"] = cloudResourceInfo.Table
		}
		if obj["id"] == "aws_ec2_instance" {
			private_dns_name = fmt.Sprintf("%v", obj["private_dns_name"])
			if private_dns_name != "" {
				private_dns_name = strings.TrimSuffix(private_dns_name, Ec2DnsSuffix1)
				private_dns_name = strings.TrimSuffix(private_dns_name, Ec2DnsSuffix2)
				obj["name"] = strings.TrimSuffix(private_dns_name, "."+fmt.Sprintf("%v", obj["region"]))
			}
		}
		obj["resource_id"] = cloudResourceInfo.Table
		if _, ok := obj["location"]; ok {
			obj["region"] = obj["location"]
			delete(obj, "location")
		}
		if obj["region"] == nil || obj["region"] == "" {
			obj["region"] = "global"
		}

		jsonBytes, err := json.Marshal(obj)
		if err != nil {
			log.Error().Msgf(err.Error())
			continue
		}
		_, err = cloudResourcesFile.Write(append(jsonBytes, '\n'))
		if err != nil {
			log.Error().Msgf(err.Error())
			continue
		}
	}

	return len(steampipeQueryResponse.Rows), nil
}

type SteampipeQueryResponse struct {
	Rows []map[string]interface{} `json:"rows"`
}
